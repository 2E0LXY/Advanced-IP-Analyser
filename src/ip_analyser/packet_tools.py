from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from pathlib import Path


MAX_CAPTURE_HOSTS = 64
_INTERFACE = re.compile(r"[A-Za-z0-9_.:@-]{1,64}")


def _wireshark() -> str:
    executable = shutil.which("wireshark")
    if not executable:
        raise RuntimeError("Wireshark is not installed; run: sudo apt install wireshark")
    return executable


def _addresses(hosts: list[str]) -> list[str]:
    if not hosts:
        raise ValueError("select at least one host")
    if len(hosts) > MAX_CAPTURE_HOSTS:
        raise ValueError(f"packet filters are limited to {MAX_CAPTURE_HOSTS} selected hosts")
    addresses: list[str] = []
    for host in hosts:
        address = str(ipaddress.ip_address(host))
        if address not in addresses:
            addresses.append(address)
    return addresses


def _port(port: int | None) -> int | None:
    if port is not None and (isinstance(port, bool) or not 1 <= port <= 65_535):
        raise ValueError("packet filter port must be from 1 to 65535")
    return port


def capture_filter(hosts: list[str], port: int | None = None) -> str:
    """Build a bounded libpcap filter from validated IP addresses and a TCP port."""
    addresses = _addresses(hosts)
    port = _port(port)
    host_filter = " or ".join(f"host {address}" for address in addresses)
    if len(addresses) > 1:
        host_filter = f"({host_filter})"
    return f"{host_filter} and tcp port {port}" if port else host_filter


def display_filter(hosts: list[str], port: int | None = None) -> str:
    """Build a Wireshark display filter for selected IPv4 and IPv6 hosts."""
    addresses = _addresses(hosts)
    port = _port(port)
    terms = [f"{'ip' if ipaddress.ip_address(address).version == 4 else 'ipv6'}.addr == {address}"
             for address in addresses]
    host_filter = " || ".join(terms)
    if len(terms) > 1:
        host_filter = f"({host_filter})"
    return f"tcp.port == {port} && {host_filter}" if port else host_filter


def validate_interface(interface: str) -> str:
    interface = interface.strip()
    if not _INTERFACE.fullmatch(interface):
        raise ValueError("capture interface name is invalid")
    return interface


def list_capture_interfaces(timeout: float = 5.0) -> list[tuple[str, str]]:
    """Return interface names and Wireshark's human-readable descriptions."""
    try:
        result = subprocess.run([_wireshark(), "-D"], capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Wireshark interface discovery timed out") from error
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or
                           f"Wireshark interface discovery exited {result.returncode}")
    interfaces: list[tuple[str, str]] = []
    for line in result.stdout.splitlines()[:256]:
        match = re.match(r"^\s*\d+\.\s+(\S+)(?:\s+\((.*)\))?\s*$", line)
        if match and _INTERFACE.fullmatch(match.group(1)):
            name = match.group(1)
            interfaces.append((name, match.group(2) or name))
    if not interfaces:
        raise RuntimeError("Wireshark did not report any usable capture interfaces")
    return interfaces


def launch_live_capture(hosts: list[str], interface: str = "any",
                        port: int | None = None) -> subprocess.Popen:
    """Start Wireshark capture using generated arguments, never a shell command."""
    command = [_wireshark(), "-i", validate_interface(interface),
               "-f", capture_filter(hosts, port), "-k"]
    return subprocess.Popen(command)


def open_capture(path: Path, hosts: list[str] | None = None,
                 port: int | None = None) -> subprocess.Popen:
    """Open an existing capture, optionally with a generated display filter."""
    capture = path.expanduser().resolve()
    if not capture.is_file():
        raise ValueError("capture file does not exist or is not a regular file")
    command = [_wireshark(), "-r", str(capture)]
    if hosts:
        command.extend(["-Y", display_filter(hosts, port)])
    elif port is not None:
        raise ValueError("a port filter requires at least one host")
    return subprocess.Popen(command)


def launch_wireshark() -> subprocess.Popen:
    """Open Wireshark without starting a capture."""
    return subprocess.Popen([_wireshark()])
