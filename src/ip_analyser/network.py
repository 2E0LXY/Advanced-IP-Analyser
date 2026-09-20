from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


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
    """Return the first active non-loopback IPv4 subnet."""
    networks = active_ipv4_networks()
    if networks:
        return networks[0][1]
    raise RuntimeError("no active global IPv4 interface was found")


def _windows_ipv4_networks() -> list[tuple[str, str, str]]:
    command = (
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object {$_.IPAddress -ne '127.0.0.1' -and $_.AddressState -eq 'Preferred'} | "
        "Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress"
    )
    try:
        output = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            text=True, capture_output=True, timeout=5, check=True,
            creationflags=CREATE_NO_WINDOW).stdout
    except (FileNotFoundError, subprocess.SubprocessError) as error:
        raise RuntimeError("could not read Windows network interfaces") from error
    try:
        records = json.loads(output or "[]")
    except json.JSONDecodeError as error:
        raise RuntimeError("Windows returned invalid network-interface data") from error
    if isinstance(records, dict):
        records = [records]
    networks: list[tuple[str, str, str]] = []
    for record in records if isinstance(records, list) else []:
        try:
            interface = str(record["InterfaceAlias"])
            value = f"{record['IPAddress']}/{int(record['PrefixLength'])}"
            network = ipaddress.ip_network(value, strict=False)
        except (KeyError, TypeError, ValueError):
            continue
        if network.version == 4:
            networks.append((interface, str(network), str(network.broadcast_address)))
    return networks


def active_ipv4_networks() -> list[tuple[str, str, str]]:
    """Return (interface, network, broadcast) for active global IPv4 addresses."""
    if os.name == "nt":
        return _windows_ipv4_networks()
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
