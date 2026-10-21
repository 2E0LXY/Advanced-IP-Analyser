from __future__ import annotations

import concurrent.futures
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


def _windows_ipv6_networks() -> list[tuple[str, str, str, int]]:
    command = (
        "Get-NetIPAddress -AddressFamily IPv6 | "
        "Where-Object {$_.IPAddress -ne '::1' -and $_.AddressState -eq 'Preferred'} | "
        "Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength | ConvertTo-Json -Compress"
    )
    try:
        output = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            text=True, capture_output=True, timeout=5, check=True,
            creationflags=CREATE_NO_WINDOW).stdout
    except (FileNotFoundError, subprocess.SubprocessError) as error:
        raise RuntimeError("could not read Windows IPv6 interfaces") from error
    try:
        records = json.loads(output or "[]")
    except json.JSONDecodeError as error:
        raise RuntimeError("Windows returned invalid IPv6 interface data") from error
    if isinstance(records, dict):
        records = [records]
    networks: list[tuple[str, str, str, int]] = []
    seen: set[tuple[str, str]] = set()
    for record in records if isinstance(records, list) else []:
        try:
            interface = str(record["InterfaceAlias"])
            index = int(record["InterfaceIndex"])
            address = ipaddress.IPv6Address(str(record["IPAddress"]).split("%", 1)[0])
            network = ipaddress.IPv6Network(
                f"{address}/{int(record['PrefixLength'])}", strict=False)
        except (KeyError, TypeError, ValueError):
            continue
        key = (interface, str(network))
        if key not in seen:
            networks.append((interface, str(network), str(address), index))
            seen.add(key)
    return networks


def active_ipv6_networks() -> list[tuple[str, str, str, int]]:
    """Return (interface, network, address, interface index) for active IPv6 interfaces."""
    if os.name == "nt":
        return _windows_ipv6_networks()
    try:
        output = subprocess.run(["ip", "-o", "-6", "addr", "show", "up"],
                                text=True, capture_output=True, timeout=2, check=True).stdout
    except (FileNotFoundError, subprocess.SubprocessError) as error:
        raise RuntimeError("could not read IPv6 interfaces; install iproute2") from error
    networks: list[tuple[str, str, str, int]] = []
    seen: set[tuple[str, str]] = set()
    for line in output.splitlines():
        match = re.search(r"^(\d+):\s+([^\s@]+)(?:@\S+)?\s+inet6\s+([0-9a-fA-F:]+)/(\d+)", line)
        if not match:
            continue
        try:
            index = int(match.group(1))
            interface = match.group(2)
            address = ipaddress.IPv6Address(match.group(3))
            if address.is_loopback:
                continue
            network = ipaddress.IPv6Network(f"{address}/{match.group(4)}", strict=False)
        except ValueError:
            continue
        key = (interface, str(network))
        if key not in seen:
            networks.append((interface, str(network), str(address), index))
            seen.add(key)
    return networks


def current_ipv6_networks() -> list[str]:
    """Return active local IPv6 prefixes without attempting to enumerate a /64."""
    networks = list(dict.fromkeys(item[1] for item in active_ipv6_networks()))
    if not networks:
        raise RuntimeError("no active IPv6 interface was found")
    return networks


def _stimulate_ipv6_neighbours(interface: str, index: int) -> None:
    target = f"ff02::1%{index if os.name == 'nt' else interface}"
    command = (["ping.exe", "-6", "-n", "1", "-w", "1000", target] if os.name == "nt" else
               ["ping", "-6", "-n", "-c", "1", "-W", "1", target])
    try:
        subprocess.run(command, capture_output=True, timeout=2, check=False,
                       creationflags=(CREATE_NO_WINDOW if os.name == "nt" else 0))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _windows_ipv6_neighbours(indices: set[int]) -> list[tuple[str, int]]:
    command = (
        "Get-NetNeighbor -AddressFamily IPv6 | "
        "Where-Object {$_.State -notin @('Unreachable','Incomplete') -and $_.IPAddress -ne '::1'} | "
        "Select-Object InterfaceIndex,IPAddress | ConvertTo-Json -Compress"
    )
    try:
        output = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            text=True, capture_output=True, timeout=5, check=True,
            creationflags=CREATE_NO_WINDOW).stdout
        records = json.loads(output or "[]")
    except (FileNotFoundError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise RuntimeError("could not read the Windows IPv6 neighbour table") from error
    if isinstance(records, dict):
        records = [records]
    neighbours: list[tuple[str, int]] = []
    for record in records if isinstance(records, list) else []:
        try:
            index = int(record["InterfaceIndex"])
            address = str(ipaddress.IPv6Address(str(record["IPAddress"]).split("%", 1)[0]))
        except (KeyError, TypeError, ValueError):
            continue
        if index in indices:
            neighbours.append((address, index))
    return neighbours


def discover_local_ipv6_hosts(interface: str | None = None) -> list[str]:
    """Discover local IPv6 nodes via multicast stimulation and the OS neighbour table.

    IPv6 /64 networks cannot be brute-force enumerated. This bounded discovery scans only
    local interface addresses and neighbours learned by NDP.
    """
    networks = active_ipv6_networks()
    if interface:
        networks = [item for item in networks if item[0] == interface or str(item[3]) == interface]
        if not networks:
            raise ValueError(f"IPv6 interface not found: {interface}")
    if not networks:
        raise RuntimeError("no active IPv6 interface was found")
    by_index = {item[3]: item for item in networks}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(by_index))) as pool:
        list(pool.map(lambda item: _stimulate_ipv6_neighbours(item[0], item[3]), by_index.values()))

    candidates: list[tuple[str, int]] = [(item[2], item[3]) for item in networks]
    if os.name == "nt":
        candidates.extend(_windows_ipv6_neighbours(set(by_index)))
    else:
        for index, item in by_index.items():
            try:
                output = subprocess.run(["ip", "-6", "neigh", "show", "dev", item[0]],
                                        text=True, capture_output=True, timeout=2, check=True).stdout
            except (FileNotFoundError, subprocess.SubprocessError) as error:
                raise RuntimeError("could not read the IPv6 neighbour table; install iproute2") from error
            for match in re.finditer(r"^([0-9a-fA-F:]+)\s+", output, re.MULTILINE):
                candidates.append((match.group(1), index))

    discovered: list[str] = []
    for value, index in candidates:
        try:
            address = ipaddress.IPv6Address(value.split("%", 1)[0])
        except ValueError:
            continue
        if address.is_loopback or address.is_multicast or address.is_unspecified:
            continue
        scoped = f"{address}%{index if os.name == 'nt' else by_index[index][0]}" if address.is_link_local else str(address)
        discovered.append(scoped)
    return list(dict.fromkeys(discovered))
