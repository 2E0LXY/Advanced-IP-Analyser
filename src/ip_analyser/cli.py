from __future__ import annotations

import argparse
from pathlib import Path

from .actions import wake
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "wake":
        wake(args.mac, args.broadcast)
        print("Wake-on-LAN packet sent")
        return 0
    targets = parse_targets(args.target)
    scanner = Scanner(args.timeout, args.workers)
    hosts = scanner.scan(targets, lambda done, total, host: print(
        f"[{done}/{total}] {host.address:>39} {'up' if host.reachable else 'down':4} {','.join(host.services)}"))
    if args.output:
        export(args.output, hosts)
        print(f"Exported {len(hosts)} results to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
