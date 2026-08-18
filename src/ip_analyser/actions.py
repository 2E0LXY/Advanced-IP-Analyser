from __future__ import annotations

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
        webbrowser.open(f"{service}://{host}")
    elif service == "smb":
        subprocess.Popen(["xdg-open", f"smb://{host}/"])
    elif service == "ssh":
        subprocess.Popen(["x-terminal-emulator", "-e", "ssh", host])
    elif service == "rdp":
        subprocess.Popen(["xfreerdp3", f"/v:{host}"])
    else:
        raise ValueError(f"unsupported service: {service}")
