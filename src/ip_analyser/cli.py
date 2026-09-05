from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from .actions import wake
from .monitoring import (
    MonitorAnalyzer,
    MonitorStore,
    enforce_capture_retention,
    export_analysis,
)
from .packet_filters import compile_filter
from .packet_tools import (
    capture_live,
    list_capture_interfaces,
    read_capture,
    start_monitor_capture,
)
from .scanner import Scanner
from .storage import export
from .targets import parse_targets
from .web_audit import audit_site, export_web_audit


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
    capture = commands.add_parser("capture", help="capture selected host traffic")
    capture.add_argument("target", help="IP, range, or CIDR (up to 64 addresses)")
    capture.add_argument("--interface", default="any")
    capture.add_argument("--port", type=int)
    capture.add_argument("--duration", type=int, default=10)
    capture.add_argument("--max-packets", type=int, default=5_000)
    capture.add_argument("--output", type=Path)
    open_packets = commands.add_parser("open-capture", help="inspect a packet capture")
    open_packets.add_argument("file", type=Path)
    open_packets.add_argument("--host", action="append", default=[])
    open_packets.add_argument("--port", type=int)
    open_packets.add_argument("--limit", type=int, default=1_000)
    open_packets.add_argument("--filter", default="", help="display-filter expression")
    commands.add_parser("capture-interfaces", help="list Linux capture interfaces")
    watch = commands.add_parser("watch", help="record and analyse network activity over time")
    watch.add_argument("--interface", default="any")
    watch.add_argument("--duration", type=int, default=300, help="seconds, up to 86400")
    watch.add_argument("--snaplen", type=int, default=128, help="bytes retained per packet")
    watch.add_argument("--report", type=Path)
    analyse = commands.add_parser("analyse-capture", help="create a deep-analysis report")
    analyse.add_argument("file", type=Path)
    analyse.add_argument("--report", type=Path, required=True)
    web = commands.add_parser("web-audit", help="run a bounded read-only web security audit")
    web.add_argument("url")
    web.add_argument("--max-pages", type=int, default=25)
    web.add_argument("--max-depth", type=int, default=2)
    web.add_argument("--timeout", type=float, default=5.0)
    web.add_argument("--exclude", action="append", default=[], help="excluded URL path prefix")
    web.add_argument("--allow-host", action="append", default=[], help="additional allowed hostname")
    web.add_argument("--report", type=Path, required=True, help=".json or .html output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "wake":
        wake(args.mac, args.broadcast)
        print("Wake-on-LAN packet sent")
        return 0
    if args.command == "capture":
        hosts = parse_targets(args.target, limit=64)
        capture = capture_live(hosts, args.interface, args.port, args.duration, args.max_packets)
        if args.output:
            destination = args.output.expanduser().resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(capture, destination)
            capture = destination
        print(f"Captured traffic for {len(hosts)} host(s) to {capture}")
        return 0
    if args.command == "capture-interfaces":
        for name, description in list_capture_interfaces():
            print(f"{name}\t{description}")
        return 0
    if args.command == "open-capture":
        records = read_capture(args.file, args.host or None, args.port, args.limit)
        predicate = compile_filter(args.filter)
        records = [record for record in records if predicate(record)]
        for record in records:
            source = f"{record.source}:{record.source_port}" if record.source_port else record.source
            destination = (f"{record.destination}:{record.destination_port}"
                           if record.destination_port else record.destination)
            print(f"{record.number:>6} {record.time_text} {source} -> {destination} "
                  f"{record.protocol} {record.length} {record.info}".rstrip())
        print(f"Read {len(records)} matching packet(s) from {args.file}")
        return 0
    if args.command == "watch":
        session = start_monitor_capture(args.interface, args.duration, snaplen=args.snaplen)
        print(f"Watching {args.interface}; recording to {session.path}")
        try:
            session.process.wait()
        except KeyboardInterrupt:
            session.stop()
        if session.error():
            raise RuntimeError(session.error())
        analysis = MonitorAnalyzer().analyze(read_capture(
            session.path, limit=100_000, allow_incomplete=True))
        store = MonitorStore(Path.home() / ".local" / "share" /
                             "advanced-ip-analyser" / "network-watch.sqlite3")
        try:
            store.save(analysis, session.path)
            store.prune(7)
            enforce_capture_retention(session.path.parent, days=7)
        finally:
            store.close()
        if args.report:
            export_analysis(args.report, analysis)
        print(f"Analysed {analysis.packet_count} packets, {len(analysis.flows)} conversations, "
              f"and {len(analysis.findings)} findings")
        return 0
    if args.command == "analyse-capture":
        analysis = MonitorAnalyzer().analyze(read_capture(args.file, limit=100_000))
        export_analysis(args.report, analysis)
        print(f"Saved analysis of {analysis.packet_count} packets to {args.report}")
        return 0
    if args.command == "web-audit":
        report = audit_site(args.url, max_pages=args.max_pages, max_depth=args.max_depth,
                            timeout=args.timeout, excluded_paths=tuple(args.exclude),
                            allowed_hosts=tuple(args.allow_host),
                            progress=lambda number, url: print(f"[{number}/{args.max_pages}] {url}"))
        export_web_audit(args.report, report)
        print(f"Audited {len(report.pages)} page(s), found {len(report.findings)} observation(s), "
              f"and saved {args.report}")
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
