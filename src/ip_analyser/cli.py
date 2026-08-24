from __future__ import annotations

import argparse
from pathlib import Path

from .actions import wake
from .packet_tools import launch_live_capture, list_capture_interfaces, open_capture
from .scanner import Scanner
from .storage import export
from .targets import parse_targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Discover hosts on networks you are authorized to manage.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan an IP, range, or CIDR")
    scan.add_argument("target")
    scan.add_argument("--timeout", type=float, default=.35)
    scan.add_argument("--workers", type=int, default=64)
    scan.add_argument("--output", type=Path)
    wol = commands.add_parser("wake", help="send a Wake-on-LAN packet")
    wol.add_argument("mac")
    wol.add_argument("--broadcast", default="255.255.255.255")
    capture = commands.add_parser("capture", help="capture selected host traffic in Wireshark")
    capture.add_argument("target", help="IP, range, or CIDR (up to 64 addresses)")
    capture.add_argument("--interface", default="any")
    capture.add_argument("--port", type=int)
    open_packets = commands.add_parser("open-capture", help="open a packet capture in Wireshark")
    open_packets.add_argument("file", type=Path)
    open_packets.add_argument("--host", action="append", default=[])
    open_packets.add_argument("--port", type=int)
    commands.add_parser("capture-interfaces", help="list Wireshark capture interfaces")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "wake":
        wake(args.mac, args.broadcast)
        print("Wake-on-LAN packet sent")
        return 0
    if args.command == "capture":
        hosts = parse_targets(args.target, limit=64)
        launch_live_capture(hosts, args.interface, args.port)
        print(f"Opened Wireshark capture for {len(hosts)} host(s)")
        return 0
    if args.command == "capture-interfaces":
        for name, description in list_capture_interfaces():
            print(f"{name}\t{description}")
        return 0
    if args.command == "open-capture":
        open_capture(args.file, args.host or None, args.port)
        print(f"Opened {args.file} in Wireshark")
        return 0
    targets = parse_targets(args.target)
    scanner = Scanner(args.timeout, args.workers)
    hosts = scanner.scan(targets, lambda done, total, host: print(
        f"[{done}/{total}] {host.address:>39} {'up' if host.reachable else 'down':4} {','.join(host.services)}"))
    if args.output:
        reachable = [host for host in hosts if host.reachable]
        export(args.output, reachable)
        print(f"Exported {len(reachable)} reachable results to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
