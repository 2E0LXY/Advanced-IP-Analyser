from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import re
import socket
import subprocess
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import replace

from .asset_profiles import infer_asset_profile
from .fingerprints import probe_service
from .models import Host
from .vendors import MacVendorLookup

DEFAULT_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "rpc", 139: "netbios", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 631: "ipp",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3000: "http", 3306: "mysql", 3389: "rdp",
    5000: "http", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http",
    8080: "http", 8081: "http", 8443: "https", 8888: "http", 9000: "http",
    9090: "http", 9100: "printer", 9200: "elasticsearch", 27017: "mongodb",
}
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class Scanner:
    def __init__(self, timeout: float = 0.35, workers: int = 64, ports: dict[int, str] | None = None,
                 vendors: MacVendorLookup | None = None, adaptive: bool = False):
        self.timeout = max(0.05, timeout)
        self.workers = min(512, max(1, workers))
        self.ports = ports or DEFAULT_PORTS
        self.vendors = vendors or MacVendorLookup()
        self.adaptive = adaptive
        self._throttle_lock = threading.Lock()
        self._probe_samples: deque[bool] = deque(maxlen=32)
        self._probe_delay = 0.0
        self._next_probe_at = 0.0
        self._route_lock = threading.Lock()
        self._local_routes: list[tuple[ipaddress.IPv4Network, str]] | None = None

    def scan(self, targets: Iterable[str], progress: Callable[[int, int, Host], None] | None = None,
             cancel: threading.Event | None = None, discover_services: bool = True,
             discovery_progress: Callable[[int, int, Host], None] | None = None) -> list[Host]:
        # A repeated target must never create repeated result rows. This also
        # protects callers that combine overlapping ranges.
        addresses = list(dict.fromkeys(targets))
        results: list[Host] = []
        # Keep the combined host/port fan-out bounded. A host now probes several
        # ports concurrently, so 64 hosts each with 64 sockets would overwhelm a LAN.
        host_workers = min(self.workers, 32) if len(self.ports) <= 1024 else min(4, self.workers)
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=host_workers)
        futures = {pool.submit(self.inspect, address): address for address in addresses}
        try:
            for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
                if cancel and cancel.is_set():
                    break
                host = future.result()
                results.append(host)
                if progress:
                    progress(done, len(addresses), host)
        finally:
            pool.shutdown(wait=not (cancel and cancel.is_set()), cancel_futures=True)
        results = sorted(results, key=lambda host: (ipaddress.ip_address(host.address).version,
                                                     int(ipaddress.ip_address(host.address))))
        return self.discover_all(results, discovery_progress, cancel) if discover_services else results

    def inspect(self, address: str) -> Host:
        port_items = list(self.ports.items())
        if len(self.ports) <= 1024:
            open_ports = []
            connection_times = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(port_items))) as pool:
                checks = {pool.submit(self._timed_port_open, address, port): (port, name)
                          for port, name in port_items}
                for future in concurrent.futures.as_completed(checks):
                    opened, elapsed_ms = future.result()
                    if opened:
                        open_ports.append(checks[future])
                        connection_times.append(elapsed_ms)
            open_ports.sort()
        else:
            open_ports = []
            connection_times = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(128, max(8, self.workers))) as pool:
                for start in range(0, len(port_items), 2048):
                    checks = {pool.submit(self._timed_port_open, address, port): (port, name)
                              for port, name in port_items[start:start + 2048]}
                    for future in concurrent.futures.as_completed(checks):
                        opened, elapsed_ms = future.result()
                        if opened:
                            open_ports.append(checks[future])
                            connection_times.append(elapsed_ms)
            open_ports.sort()
        services = [name for _port, name in open_ports]
        ping_started = time.monotonic()
        ping_latency = self._ping(address) if not open_ports else None
        pinged = bool(ping_latency)
        mac = self._neighbour_mac(address)
        # On a directly connected LAN, a valid neighbour-table entry is strong
        # reachability evidence even when the device blocks ICMP and every
        # selected TCP port. ARP-only discovery is how many appliances surface.
        reachable = bool(open_ports) or pinged or bool(mac)
        latency = (round(min(connection_times), 1) if connection_times else
                   round(float(ping_latency), 1) if pinged and not isinstance(ping_latency, bool) else
                   round((time.monotonic() - ping_started) * 1000, 1) if pinged else None)
        host = Host(address=address, reachable=reachable, latency_ms=latency, mac=mac,
                    services=services, ports=[port for port, _name in open_ports])
        profile = infer_asset_profile(host)
        return replace(host, device_type=profile.device_type)

    def _timed_port_open(self, address: str, port: int) -> tuple[bool, float]:
        started = time.monotonic()
        opened = self._port_open(address, port)
        return opened, max(0.1, round((time.monotonic() - started) * 1000, 1))

    def discover(self, host: Host) -> Host:
        """Enrich one completed host result without delaying its initial display."""
        mac = host.mac or (self._neighbour_mac(host.address) if host.reachable else "")
        hostname = host.hostname or (self._resolve_hostname(host.address) if host.reachable else "")
        manufacturer = self.vendors.lookup(mac) if mac else ""
        service_info: dict[str, dict[str, str]] = {}
        services = list(zip(host.ports, host.services))
        if services:
            fingerprint_timeout = min(2.0, max(0.5, self.timeout * 3))
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(services))) as pool:
                probes = {pool.submit(probe_service, host.address, port, name, fingerprint_timeout): port
                          for port, name in services}
                for future in concurrent.futures.as_completed(probes):
                    if details := future.result():
                        service_info[str(probes[future])] = details
        enriched = replace(host, hostname=hostname, mac=mac, manufacturer=manufacturer,
                           service_info=service_info)
        profile = infer_asset_profile(enriched)
        return replace(enriched, device_type=profile.device_type,
                       operating_system=profile.operating_system,
                       os_version=profile.os_version, model=profile.model,
                       profile_confidence=profile.confidence)

    def _resolve_hostname(self, address: str) -> str:
        gateway = self._local_gateway(address)
        if gateway:
            name = self._reverse_lookup(address, gateway)
            if name and self._hostname_is_unique(name, address, gateway):
                return name
        name = self._reverse_lookup(address)
        if name and self._hostname_is_unique(name, address):
            return name
        if os.name == "nt":
            try:
                output = subprocess.run(["nbtstat.exe", "-A", address], capture_output=True,
                                        text=True, errors="replace", timeout=2, check=False,
                                        creationflags=CREATE_NO_WINDOW).stdout
                match = re.search(r"^\s*([^\s<>]{1,15})\s+<00>\s+UNIQUE\b", output,
                                  flags=re.MULTILINE | re.IGNORECASE)
                if match:
                    return match.group(1)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        return ""

    @staticmethod
    def _hostname_is_unique(name: str, address: str, server: str = "") -> bool:
        """Accept a PTR name only when it maps uniquely back to this address.

        Some router/Tailscale DNS configurations publish the same descriptive
        PTR name for a group of devices. Displaying that as a host identity is
        misleading, so ambiguous or stale names are left unresolved.
        """
        try:
            target = ipaddress.ip_address(address.split("%", 1)[0])
            if target.version == 6:
                found = {str(ipaddress.ip_address(item[4][0].split("%", 1)[0]))
                         for item in socket.getaddrinfo(name, None, socket.AF_INET6)}
                return found == {str(target)}
            command = ["nslookup", "-timeout=1", "-retry=1", name]
            if server:
                command.append(server)
            output = subprocess.run(
                command, capture_output=True, text=True, errors="replace",
                timeout=2, check=False,
                creationflags=(CREATE_NO_WINDOW if os.name == "nt" else 0)).stdout
            sections = re.split(r"^Name:\s*", output, maxsplit=1,
                                flags=re.MULTILINE | re.IGNORECASE)
            if len(sections) != 2:
                return False
            found = set()
            for candidate in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", sections[1]):
                try:
                    found.add(str(ipaddress.ip_address(candidate)))
                except ValueError:
                    continue
            return found == {str(target)}
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired, ValueError):
            return False

    @staticmethod
    def _reverse_lookup(address: str, server: str = "") -> str:
        try:
            command = ["nslookup", "-timeout=1", "-retry=1", address]
            if server:
                command.append(server)
            output = subprocess.run(command,
                                    capture_output=True, text=True, errors="replace",
                                    timeout=2, check=False,
                                    creationflags=(CREATE_NO_WINDOW if os.name == "nt" else 0)).stdout
            match = re.search(r"(?:^Name:\s*|\bname\s*=\s*)([^\s]+)", output,
                              flags=re.MULTILINE | re.IGNORECASE)
            if match:
                return match.group(1).rstrip(".")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ""

    def _local_gateway(self, address: str) -> str:
        if os.name != "nt":
            return ""
        try:
            target = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            return ""
        if not isinstance(target, ipaddress.IPv4Address) or not target.is_private:
            return ""
        if self._local_routes is None:
            with self._route_lock:
                if self._local_routes is None:
                    self._local_routes = self._windows_local_routes()
        for network, gateway in self._local_routes:
            if target in network:
                return gateway
        return ""

    @staticmethod
    def _windows_local_routes() -> list[tuple[ipaddress.IPv4Network, str]]:
        """Match default gateways to on-link networks on the same interface."""
        try:
            output = subprocess.run(["route.exe", "print", "-4"], capture_output=True,
                                    text=True, errors="replace", timeout=3, check=False,
                                    creationflags=CREATE_NO_WINDOW).stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []
        rows = re.findall(r"^\s*(\d+(?:\.\d+){3})\s+(\d+(?:\.\d+){3})\s+(\S+)\s+"
                          r"(\d+(?:\.\d+){3})\s+\d+\s*$", output, re.MULTILINE)
        gateways = [(ipaddress.IPv4Address(gateway), interface)
                    for destination, mask, gateway, interface in rows
                    if destination == "0.0.0.0" and mask == "0.0.0.0"
                    and re.fullmatch(r"\d+(?:\.\d+){3}", gateway)]
        routes = []
        for destination, mask, gateway, interface in rows:
            if gateway.casefold() != "on-link":
                continue
            try:
                network = ipaddress.IPv4Network(f"{destination}/{mask}", strict=False)
                for default_gateway, gateway_interface in gateways:
                    if interface == gateway_interface and default_gateway in network:
                        routes.append((network, str(default_gateway)))
            except ValueError:
                continue
        return sorted(routes, key=lambda route: route[0].prefixlen, reverse=True)

    def discover_all(self, hosts: Iterable[Host],
                     progress: Callable[[int, int, Host], None] | None = None,
                     cancel: threading.Event | None = None) -> list[Host]:
        """Run the second discovery phase concurrently after host scanning."""
        hosts = list(hosts)
        candidates = [host for host in hosts if host.reachable]
        discovered = {host.identity: host for host in hosts}
        if not candidates:
            return hosts
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(16, self.workers, len(candidates)))
        futures = {pool.submit(self.discover, host): host for host in candidates}
        try:
            for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
                if cancel and cancel.is_set():
                    break
                host = future.result()
                discovered[host.identity] = host
                if progress:
                    progress(done, len(candidates), host)
        finally:
            pool.shutdown(wait=not (cancel and cancel.is_set()), cancel_futures=True)
        return [discovered[host.identity] for host in hosts]

    def _port_open(self, address: str, port: int) -> bool:
        if self.adaptive:
            self._wait_for_probe_slot()
        started = time.monotonic()
        try:
            with socket.create_connection((address, port), timeout=self.timeout):
                opened = True
        except (OSError, TimeoutError):
            opened = False
        if self.adaptive:
            elapsed = time.monotonic() - started
            self._record_probe_pressure(not opened and elapsed >= max(0.04, self.timeout * 0.75))
        return opened

    def _wait_for_probe_slot(self) -> None:
        with self._throttle_lock:
            now = time.monotonic()
            delay = max(0.0, self._next_probe_at - now)
            self._next_probe_at = max(now, self._next_probe_at) + self._probe_delay
        if delay:
            time.sleep(delay)

    def _record_probe_pressure(self, slow_failure: bool) -> None:
        with self._throttle_lock:
            self._probe_samples.append(slow_failure)
            if len(self._probe_samples) < self._probe_samples.maxlen:
                return
            pressure = sum(self._probe_samples) / len(self._probe_samples)
            if pressure >= 0.65:
                self._probe_delay = min(0.05, max(0.001, self._probe_delay * 2))
            elif pressure <= 0.20:
                self._probe_delay = max(0.0, self._probe_delay / 2 - 0.0005)
            self._probe_samples.clear()

    def _ping(self, address: str) -> float | None:
        """Return a round-trip time only for an echo reply from this target."""
        try:
            target = ipaddress.ip_address(address.split("%", 1)[0])
            family = ["-6"] if target.version == 6 else []
            command = (["ping", *family, "-n", "1", "-w", "1000", address] if os.name == "nt" else
                       ["ping", *family, "-n", "-c", "1", "-W", "1", address])
            result = subprocess.run(command,
                                    capture_output=True, timeout=2, check=False,
                                    creationflags=(CREATE_NO_WINDOW if os.name == "nt" else 0))
            if result.returncode != 0:
                return None
            output = result.stdout.decode(errors="replace") if isinstance(result.stdout, bytes) else str(result.stdout)
            for line in output.splitlines():
                if os.name == "nt":
                    reply = re.match(r"^\s*Reply from\s+(.+?):\s+.*\btime\s*([=<])\s*([\d.,]+)\s*ms\b",
                                     line, re.IGNORECASE)
                else:
                    reply = re.match(r"^\s*\d+\s+bytes from\s+(.+?):\s+.*\btime\s*([=<])\s*([\d.,]+)\s*ms\b",
                                     line, re.IGNORECASE)
                if not reply:
                    continue
                try:
                    reply_address = reply.group(1).split("%", 1)[0]
                    target_address = address.split("%", 1)[0]
                    if ipaddress.ip_address(reply_address) != ipaddress.ip_address(target_address):
                        continue
                except ValueError:
                    continue
                if reply.group(2) == "<":
                    return 0.5
                return max(0.1, float(reply.group(3).replace(",", ".")))
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _neighbour_mac(address: str) -> str:
        try:
            target = ipaddress.ip_address(address)
            unscoped = address.split("%", 1)[0]
            if os.name == "nt":
                if target.version == 6:
                    command = ("Get-NetNeighbor -AddressFamily IPv6 -IPAddress '" + unscoped +
                               "' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LinkLayerAddress")
                    output = subprocess.run(
                        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                        text=True, capture_output=True, timeout=2, check=False,
                        creationflags=CREATE_NO_WINDOW).stdout
                else:
                    output = subprocess.run(["arp.exe", "-a", address], text=True,
                                            capture_output=True, timeout=1, check=False,
                                            creationflags=CREATE_NO_WINDOW).stdout
                match = re.search(r"\b([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b", output,
                                  flags=re.IGNORECASE)
                return match.group(1).replace("-", ":").upper() if match else ""
            family = ["-6"] if target.version == 6 else []
            output = subprocess.run(["ip", *family, "neigh", "show", unscoped], text=True,
                                    capture_output=True, timeout=1, check=False).stdout
            words = output.split()
            return words[words.index("lladdr") + 1].upper() if "lladdr" in words else ""
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
            return ""
