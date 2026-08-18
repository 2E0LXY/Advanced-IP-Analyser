from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
import webbrowser


def wake(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> None:
    raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(raw) != 6:
        raise ValueError("MAC address must contain six octets")
    packet = b"\xff" * 6 + raw * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        channel.sendto(packet, (broadcast, port))


def open_service(service: str, host: str) -> None:
    if service in {"http", "https", "ftp"}:
        url = service_url(service, host)
        if shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", url])
        elif not webbrowser.open(url):
            raise RuntimeError("no desktop URL opener is available; install xdg-utils")
    elif service == "smb":
        subprocess.Popen(["xdg-open", f"smb://{host}/"])
    elif service == "ssh":
        subprocess.Popen(["x-terminal-emulator", "-e", "ssh", host])
    elif service == "rdp":
        subprocess.Popen(["xfreerdp3", f"/v:{host}"])
    else:
        raise ValueError(f"unsupported service: {service}")


def service_url(service: str, host: str) -> str:
    """Build a browser URL, including brackets required for IPv6 literals."""
    try:
        address = ipaddress.ip_address(host)
        authority = f"[{host}]" if address.version == 6 else host
    except ValueError:
        authority = host
    return f"{service}://{authority}"


def preferred_web_service(services: list[str]) -> str | None:
    for service in ("https", "http"):
        if service in services:
            return service
    return None
