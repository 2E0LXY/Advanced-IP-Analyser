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

    def scan(self, targets: Iterable[str], progress: Callable[[int, int, Host], None] | None = None,
             cancel: threading.Event | None = None, discover_services: bool = True,
             discovery_progress: Callable[[int, int, Host], None] | None = None) -> list[Host]:
        addresses = list(targets)
        results: list[Host] = []
        host_workers = self.workers if len(self.ports) <= 1024 else min(4, self.workers)
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
        connection_latencies: list[float] = []
        if len(self.ports) <= 1024:
            open_ports = []
            for port, name in self.ports.items():
                opened, elapsed = self._timed_port_open(address, port)
                if opened:
                    open_ports.append((port, name))
                    connection_latencies.append(elapsed)
        else:
            open_ports = []
            port_items = list(self.ports.items())
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(128, max(8, self.workers))) as pool:
                for start in range(0, len(port_items), 2048):
                    checks = {pool.submit(self._timed_port_open, address, port): (port, name)
                              for port, name in port_items[start:start + 2048]}
                    for future in concurrent.futures.as_completed(checks):
                        opened, elapsed = future.result()
                        if opened:
                            open_ports.append(checks[future])
                            connection_latencies.append(elapsed)
            open_ports.sort()
        services = [name for _port, name in open_ports]
        reachable = bool(services)
        latency = min(connection_latencies, default=None)
        if not reachable:
            ping_started = time.monotonic()
            reachable = self._ping(address)
            if reachable:
                latency = max(0.1, round((time.monotonic() - ping_started) * 1000, 1))
        hostname = ""
        if reachable:
            try:
                hostname = socket.gethostbyaddr(address)[0]
            except (socket.herror, socket.gaierror, TimeoutError):
                pass
        mac = self._neighbour_mac(address)
        host = Host(address=address, reachable=reachable, hostname=hostname, latency_ms=latency,
                    mac=mac, manufacturer=self.vendors.lookup(mac) if mac else "", services=services,
                    ports=[port for port, _name in open_ports])
        profile = infer_asset_profile(host)
        return replace(host, device_type=profile.device_type,
                       operating_system=profile.operating_system,
                       os_version=profile.os_version, model=profile.model,
                       profile_confidence=profile.confidence)

    def discover(self, host: Host) -> Host:
        """Enrich one completed host result without delaying its initial display."""
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
        enriched = replace(host, service_info=service_info)
        profile = infer_asset_profile(enriched)
        return replace(enriched, device_type=profile.device_type,
                       operating_system=profile.operating_system,
                       os_version=profile.os_version, model=profile.model,
                       profile_confidence=profile.confidence)

    def discover_all(self, hosts: Iterable[Host],
                     progress: Callable[[int, int, Host], None] | None = None,
                     cancel: threading.Event | None = None) -> list[Host]:
        """Run the second discovery phase concurrently after host scanning."""
        hosts = list(hosts)
        candidates = [host for host in hosts if host.reachable and host.ports]
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

    def _timed_port_open(self, address: str, port: int) -> tuple[bool, float]:
        started = time.monotonic()
        opened = self._port_open(address, port)
        elapsed = max(0.1, round((time.monotonic() - started) * 1000, 1))
        return opened, elapsed

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

    def _ping(self, address: str) -> bool:
        try:
            command = (["ping", "-n", "1", "-w", "1000", address] if os.name == "nt" else
                       ["ping", "-n", "-c", "1", "-W", "1", address])
            result = subprocess.run(command,
                                    capture_output=True, timeout=2, check=False,
                                    creationflags=(CREATE_NO_WINDOW if os.name == "nt" else 0))
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _neighbour_mac(address: str) -> str:
        try:
            if os.name == "nt":
                output = subprocess.run(["arp.exe", "-a", address], text=True,
                                        capture_output=True, timeout=1, check=False,
                                        creationflags=CREATE_NO_WINDOW).stdout
                match = re.search(r"\b([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b", output,
                                  flags=re.IGNORECASE)
                return match.group(1).replace("-", ":").upper() if match else ""
            output = subprocess.run(["ip", "neigh", "show", address], text=True,
                                    capture_output=True, timeout=1, check=False).stdout
            words = output.split()
            return words[words.index("lladdr") + 1].upper() if "lladdr" in words else ""
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
            return ""
