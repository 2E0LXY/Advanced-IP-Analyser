from __future__ import annotations

import ipaddress
import re
import subprocess


def ipv4_24_target(value: str) -> str:
    """Return the containing /24 for an IPv4 address or interface value."""
    try:
        address = ipaddress.ip_interface(value.strip()).ip
    except ValueError as error:
        raise ValueError("enter one IPv4 address or CIDR before using /24") from error
    if address.version != 4:
        raise ValueError("the /24 shortcut is available for IPv4 targets only")
    return str(ipaddress.ip_network(f"{address}/24", strict=False))


def broadcasts_for_host(address: str, networks: list[tuple[str, str, str]]) -> list[str]:
    """Choose active-interface broadcasts that can reach a host, with safe fallbacks."""
    host = ipaddress.ip_address(address)
    if host.version != 4:
        return []
    matching = [broadcast for _interface, network, broadcast in networks
                if host in ipaddress.ip_network(network, strict=False)]
    candidates = matching or [broadcast for _interface, _network, broadcast in networks]
    return list(dict.fromkeys(candidates or ["255.255.255.255"]))


def current_ipv4_subnet() -> str:
    """Return the first global IPv4 subnet reported by iproute2."""
    try:
        output = subprocess.run(["ip", "-o", "-4", "addr", "show", "scope", "global"],
                                text=True, capture_output=True, timeout=2, check=True).stdout
    except (FileNotFoundError, subprocess.SubprocessError) as error:
        raise RuntimeError("could not read network interfaces; install iproute2") from error
    match = re.search(r"\binet\s+(\d+(?:\.\d+){3}/\d+)\b", output)
    if not match:
        raise RuntimeError("no active global IPv4 interface was found")
    return str(ipaddress.ip_network(match.group(1), strict=False))


def active_ipv4_networks() -> list[tuple[str, str, str]]:
    """Return (interface, network, broadcast) for active global IPv4 addresses."""
    try:
        output = subprocess.run(["ip", "-o", "-4", "addr", "show", "scope", "global"],
                                text=True, capture_output=True, timeout=2, check=True).stdout
    except (FileNotFoundError, subprocess.SubprocessError) as error:
        raise RuntimeError("could not read network interfaces; install iproute2") from error
    networks = []
    for line in output.splitlines():
        match = re.search(r"^\d+:\s+(\S+).*?\binet\s+(\d+(?:\.\d+){3}/\d+)\b", line)
        if match:
            network = ipaddress.ip_network(match.group(2), strict=False)
            networks.append((match.group(1), str(network), str(network.broadcast_address)))
    return networks
