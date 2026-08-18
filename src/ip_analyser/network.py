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

