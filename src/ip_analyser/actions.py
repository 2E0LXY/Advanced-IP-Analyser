from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import webbrowser
from dataclasses import dataclass


_SSH_USER = re.compile(r"[A-Za-z0-9._-]+")


def validate_ssh_username(username: str) -> str:
    """Reject values that OpenSSH could interpret as command-line options."""
    if username and (username.startswith("-") or not _SSH_USER.fullmatch(username)):
        raise ValueError("SSH username contains unsupported characters")
    return username


def wake(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> None:
    raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(raw) != 6:
        raise ValueError("MAC address must contain six octets")
    packet = b"\xff" * 6 + raw * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        channel.sendto(packet, (broadcast, port))


def open_service(service: str, host: str, port: int | None = None, username: str = "") -> None:
    if service in {"http", "https", "ftp"}:
        url = service_url(service, host, port)
        if shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", url])
        elif not webbrowser.open(url):
            raise RuntimeError("no desktop URL opener is available; install xdg-utils")
    elif service == "smb":
        subprocess.Popen(["xdg-open", f"smb://{host}/"])
    elif service == "ssh":
        validate_ssh_username(username)
        command = ["x-terminal-emulator", "-e", "ssh"]
        if port and port != 22:
            command.extend(["-p", str(port)])
        subprocess.Popen([*command, "--", f"{username}@{host}" if username else host])
    elif service == "rdp":
        subprocess.Popen(["xfreerdp3", f"/v:{host}:{port}" if port and port != 3389 else f"/v:{host}"])
    elif service == "telnet":
        terminal = shutil.which("x-terminal-emulator")
        client = shutil.which("telnet")
        if not terminal or not client:
            raise RuntimeError("install x-terminal-emulator and telnet to open Telnet services")
        subprocess.Popen([terminal, "-e", client, host, str(port or 23)])
    else:
        raise ValueError(f"unsupported service: {service}")


def open_network_tool(tool: str, host: str) -> None:
    """Launch a bounded diagnostic in a terminal without invoking a shell."""
    ipaddress.ip_address(host)
    terminal = shutil.which("x-terminal-emulator")
    commands = {
        "ping": [shutil.which("ping"), "-c", "4", host],
        "trace": [shutil.which("tracepath"), host],
    }
    command = commands.get(tool)
    if not terminal or not command or not command[0]:
        package = "iputils-ping" if tool == "ping" else "iputils-tracepath"
        raise RuntimeError(f"install x-terminal-emulator and {package} to use this tool")
    subprocess.Popen([terminal, "-e", *command])


@dataclass(frozen=True, slots=True)
class RemotePowerResult:
    host: str
    action: str
    succeeded: bool
    detail: str


def remote_power(host: str, action: str, user: str = "", timeout: int = 15) -> RemotePowerResult:
    """Run a non-interactive SSH power command; credentials are never stored."""
    ipaddress.ip_address(host)
    validate_ssh_username(user)
    commands = {
        "shutdown": ["sudo", "-n", "shutdown", "-h", "+1"],
        "reboot": ["sudo", "-n", "shutdown", "-r", "+1"],
        "cancel": ["sudo", "-n", "shutdown", "-c"],
    }
    if action not in commands:
        raise ValueError("remote action must be shutdown, reboot, or cancel")
    destination = f"{user}@{host}" if user else host
    executable = shutil.which("ssh")
    if not executable:
        return RemotePowerResult(host, action, False, "openssh-client is not installed")
    try:
        result = subprocess.run(
            [executable, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--",
             destination, *commands[action]],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return RemotePowerResult(host, action, False, "SSH command timed out")
    except OSError as error:
        return RemotePowerResult(host, action, False, str(error))
    detail = (result.stderr or result.stdout).strip()
    return RemotePowerResult(host, action, result.returncode == 0,
                             detail or ("command accepted" if result.returncode == 0 else f"SSH exited {result.returncode}"))


def service_url(service: str, host: str, port: int | None = None) -> str:
    """Build a browser URL, including brackets required for IPv6 literals."""
    try:
        address = ipaddress.ip_address(host)
        authority = f"[{host}]" if address.version == 6 else host
    except ValueError:
        authority = host
    defaults = {"http": 80, "https": 443, "ftp": 21}
    suffix = f":{port}" if port and port != defaults.get(service) else ""
    return f"{service}://{authority}{suffix}"


def preferred_web_service(services: list[str]) -> str | None:
    for service in ("https", "http"):
        if service in services:
            return service
    return None
