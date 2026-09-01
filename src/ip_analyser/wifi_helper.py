#!/usr/bin/python3
"""Narrow PolicyKit helper for passive Linux wireless monitor interfaces."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


_INTERFACE = re.compile(r"[A-Za-z0-9_.:@-]{1,15}")
_MONITOR = re.compile(r"aia[0-9]{1,6}mon")


def _tools() -> tuple[str, str]:
    iw = shutil.which("iw")
    ip = shutil.which("ip")
    if not iw or not ip:
        raise RuntimeError("the Debian iw and iproute2 packages are required")
    return iw, ip


def _run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or
                           f"wireless command exited {result.returncode}")
    return result.stdout


def _wireless(interface: str) -> None:
    if not _INTERFACE.fullmatch(interface):
        raise ValueError("invalid wireless interface")
    sysfs = Path("/sys/class/net") / interface / "wireless"
    if not sysfs.is_dir():
        raise ValueError("selected interface is not a Linux wireless interface")


def create(interface: str) -> str:
    _wireless(interface)
    iw, ip = _tools()
    monitor = f"aia{socket.if_nametoindex(interface)}mon"
    if not _MONITOR.fullmatch(monitor):
        raise ValueError("could not create a safe monitor-interface name")
    if (Path("/sys/class/net") / monitor).exists():
        info = _run([iw, "dev", monitor, "info"])
        if "type monitor" not in info:
            raise RuntimeError("the reserved monitor-interface name is already in use")
        return monitor
    _run([iw, "dev", interface, "interface", "add", monitor, "type", "monitor"])
    try:
        _run([ip, "link", "set", "dev", monitor, "up"])
    except Exception:
        _run([iw, "dev", monitor, "del"])
        raise
    return monitor


def remove(monitor: str) -> None:
    if not _MONITOR.fullmatch(monitor):
        raise ValueError("invalid managed monitor interface")
    path = Path("/sys/class/net") / monitor
    if not path.exists():
        return
    iw, _ip = _tools()
    info = _run([iw, "dev", monitor, "info"])
    if "type monitor" not in info:
        raise RuntimeError("refusing to remove an interface that is not in monitor mode")
    _run([iw, "dev", monitor, "del"])


def hop(monitor: str, channels: list[int], duration: int) -> None:
    if not _MONITOR.fullmatch(monitor) or not (Path("/sys/class/net") / monitor).exists():
        raise ValueError("invalid managed monitor interface")
    if (not channels or len(channels) > 128 or any(channel < 1 or channel > 233
                                                   for channel in channels) or
            not 1 <= duration <= 86_400):
        raise ValueError("invalid channel plan")
    iw, _ip = _tools()
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    deadline = time.monotonic() + duration
    index = 0
    while not stopping and time.monotonic() < deadline:
        _run([iw, "dev", monitor, "set", "channel", str(channels[index % len(channels)])])
        index += 1
        time.sleep(.75)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("action", choices=("create", "remove", "hop"))
    parser.add_argument("--interface", required=True)
    parser.add_argument("--channels", default="")
    parser.add_argument("--duration", type=int, default=300)
    try:
        args = parser.parse_args(argv)
        if os.geteuid() != 0:
            raise PermissionError("wireless monitor setup requires administrator authorization")
        if args.action == "create":
            print(create(args.interface))
        elif args.action == "remove":
            remove(args.interface)
        else:
            channels = [int(value) for value in args.channels.split(",") if value]
            hop(args.interface, channels, args.duration)
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
