from __future__ import annotations

import ipaddress
import re
import subprocess


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
