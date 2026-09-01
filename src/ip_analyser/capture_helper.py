#!/usr/bin/python3
"""Narrow Linux AF_PACKET capture helper used directly or through PolicyKit."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import stat
import struct
import sys
import time
import signal
from pathlib import Path


_INTERFACE = re.compile(r"[A-Za-z0-9_.:@-]{1,64}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--host", action="append", default=[])
    parser.add_argument("--port", type=int)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--max-packets", type=int, required=True)
    parser.add_argument("--snaplen", type=int, default=65_535)
    parser.add_argument("--linktype", type=int, default=1)
    return parser


def _packet_scope(frame: bytes) -> tuple[str, str, int | None, int | None] | None:
    if len(frame) < 14:
        return None
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    for _ in range(2):
        if ether_type not in {0x8100, 0x88A8} or len(frame) < offset + 4:
            break
        ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    if ether_type == 0x0800 and len(frame) >= offset + 20:
        header_length = (frame[offset] & 0x0F) * 4
        if header_length < 20 or len(frame) < offset + header_length:
            return None
        source = str(ipaddress.ip_address(frame[offset + 12:offset + 16]))
        destination = str(ipaddress.ip_address(frame[offset + 16:offset + 20]))
        protocol = frame[offset + 9]
        fragment_offset = struct.unpack("!H", frame[offset + 6:offset + 8])[0] & 0x1FFF
        offset += header_length
        if fragment_offset:
            return source, destination, None, None
    elif ether_type == 0x86DD and len(frame) >= offset + 40:
        source = str(ipaddress.ip_address(frame[offset + 8:offset + 24]))
        destination = str(ipaddress.ip_address(frame[offset + 24:offset + 40]))
        protocol = frame[offset + 6]
        offset += 40
        fragment_offset = 0
        for _ in range(8):
            if protocol in {0, 43, 60} and len(frame) >= offset + 2:
                protocol, units = frame[offset], frame[offset + 1]
                offset += (units + 1) * 8
            elif protocol == 44 and len(frame) >= offset + 8:
                protocol = frame[offset]
                fragment_offset = struct.unpack("!H", frame[offset + 2:offset + 4])[0] >> 3
                offset += 8
            elif protocol == 51 and len(frame) >= offset + 2:
                protocol, units = frame[offset], frame[offset + 1]
                offset += (units + 2) * 4
            else:
                break
        if fragment_offset:
            return source, destination, None, None
    else:
        return None
    if protocol in {6, 17} and len(frame) >= offset + 4:
        source_port, destination_port = struct.unpack("!HH", frame[offset:offset + 4])
    else:
        source_port = destination_port = None
    return source, destination, source_port, destination_port


def _matches(frame: bytes, hosts: set[str], port: int | None) -> bool:
    if not hosts and port is None:
        return True
    scope = _packet_scope(frame)
    if scope is None:
        return False
    source, destination, source_port, destination_port = scope
    return ((not hosts or source in hosts or destination in hosts) and
            (port is None or source_port == port or destination_port == port))


def _open_output(path: Path) -> int:
    current_uid = os.getuid() if hasattr(os, "getuid") else os.stat(path).st_uid
    expected_uid = int(os.environ.get("PKEXEC_UID", current_uid))
    flags = os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    metadata = os.fstat(descriptor)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != expected_uid or
            metadata.st_nlink != 1):
        os.close(descriptor)
        raise PermissionError("capture output failed its ownership check")
    os.ftruncate(descriptor, 0)
    return descriptor


def capture(interface: str, hosts: set[str], port: int | None, duration: int,
            max_packets: int, output: Path, snaplen: int = 65_535,
            linktype: int = 1) -> int:
    try:
        channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    except PermissionError:
        return 13
    with channel:
        if interface != "any":
            channel.bind((interface, 0))
        channel.settimeout(0.25)
        descriptor = _open_output(output)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
            deadline = time.monotonic() + duration
            written = 0
            stopping = False

            def request_stop(_signum, _frame):
                nonlocal stopping
                stopping = True

            previous_term = signal.signal(signal.SIGTERM, request_stop)
            previous_int = signal.signal(signal.SIGINT, request_stop)
            while not stopping and written < max_packets and time.monotonic() < deadline:
                try:
                    frame = channel.recv(65_535)
                except socket.timeout:
                    continue
                if linktype == 1 and not _matches(frame, hosts, port):
                    continue
                timestamp = time.time()
                seconds = int(timestamp)
                microseconds = int((timestamp - seconds) * 1_000_000)
                captured = frame[:snaplen]
                stream.write(struct.pack("<IIII", seconds, microseconds,
                                         len(captured), len(frame)))
                stream.write(captured)
                stream.flush()
                written += 1
            signal.signal(signal.SIGTERM, previous_term)
            signal.signal(signal.SIGINT, previous_int)
            stream.flush()
            os.fsync(stream.fileno())
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if not _INTERFACE.fullmatch(args.interface):
            raise ValueError("invalid capture interface")
        if len(args.host) > 64:
            raise ValueError("too many capture hosts")
        hosts = {str(ipaddress.ip_address(host)) for host in args.host}
        if ((args.port is not None and not 1 <= args.port <= 65_535) or
                not 1 <= args.duration <= 86_400 or not 1 <= args.max_packets <= 100_000 or
                not 96 <= args.snaplen <= 65_535 or args.linktype not in {1, 127} or
                (args.linktype == 127 and (hosts or args.port is not None))):
            raise ValueError("invalid capture limits")
        if not args.output.is_absolute():
            raise ValueError("capture output path must be absolute")
        return capture(args.interface, hosts, args.port, args.duration, args.max_packets,
                       args.output, args.snaplen, args.linktype)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
