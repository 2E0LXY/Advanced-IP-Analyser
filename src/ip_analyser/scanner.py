from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import subprocess
import time
from collections.abc import Callable, Iterable

from .models import Host

DEFAULT_PORTS = {21: "ftp", 22: "ssh", 53: "dns", 80: "http", 139: "netbios", 443: "https", 445: "smb", 3389: "rdp"}


class Scanner:
    def __init__(self, timeout: float = 0.35, workers: int = 64, ports: dict[int, str] | None = None):
        self.timeout = max(0.05, timeout)
        self.workers = min(512, max(1, workers))
        self.ports = ports or DEFAULT_PORTS

    def scan(self, targets: Iterable[str], progress: Callable[[int, int, Host], None] | None = None) -> list[Host]:
        addresses = list(targets)
        results: list[Host] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.inspect, address): address for address in addresses}
            for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
                host = future.result()
                results.append(host)
                if progress:
                    progress(done, len(addresses), host)
        return sorted(results, key=lambda host: (ipaddress.ip_address(host.address).version,
                                                  int(ipaddress.ip_address(host.address))))

    def inspect(self, address: str) -> Host:
        started = time.monotonic()
        services = [name for port, name in self.ports.items() if self._port_open(address, port)]
        reachable = bool(services) or self._ping(address)
        latency = round((time.monotonic() - started) * 1000, 1) if reachable else None
        hostname = ""
        if reachable:
            try:
                hostname = socket.gethostbyaddr(address)[0]
            except (socket.herror, socket.gaierror, TimeoutError):
                pass
        return Host(address=address, reachable=reachable, hostname=hostname, latency_ms=latency,
                    mac=self._neighbour_mac(address), services=services)

    def _port_open(self, address: str, port: int) -> bool:
        try:
            with socket.create_connection((address, port), timeout=self.timeout):
                return True
        except (OSError, TimeoutError):
            return False

    def _ping(self, address: str) -> bool:
        try:
            result = subprocess.run(["ping", "-n", "-c", "1", "-W", "1", address], capture_output=True, timeout=2)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _neighbour_mac(address: str) -> str:
        try:
            output = subprocess.run(["ip", "neigh", "show", address], text=True, capture_output=True, timeout=1).stdout
            words = output.split()
            return words[words.index("lladdr") + 1].upper() if "lladdr" in words else ""
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
            return ""
