"""Opt-in, local-only network inventory monitoring and report generation.

There is deliberately no HTTP listener, cloud client, AI API request, remote
command execution, or background startup registration in this module.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from contextlib import closing
from typing import Callable

from .scan_history import default_history_path, latest_evidence, record_scan
from .scanner import DEFAULT_PORTS, Scanner
from .targets import parse_targets

MAX_MONITOR_HOSTS = 1_024
MIN_INTERVAL_SECONDS = 60
MAX_REPORT_BYTES = 2_000_000
_ALLOWED_NETWORKS = tuple(ipaddress.ip_network(network) for network in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fc00::/7", "fe80::/10",
))


def validate_monitor_target(target: str) -> list[str]:
    """Restrict unattended scanning to bounded private/link-local LAN ranges."""
    addresses = parse_targets(target, limit=MAX_MONITOR_HOSTS)
    if not addresses:
        raise ValueError("monitor target contains no hosts")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not any(ip in network for network in _ALLOWED_NETWORKS):
            raise ValueError("automatic monitoring is restricted to local/private addresses")
    return addresses


def monitor_once(target: str, *, history_path: Path | None = None,
                 timeout: float = 0.35, workers: int = 16,
                 ports: dict[int, str] | None = None,
                 scanner_factory: Callable[..., Scanner] = Scanner) -> dict[str, object]:
    """Perform a bounded scan without service banner/HTTP discovery."""
    targets = validate_monitor_target(target)
    selected_ports = ports if ports is not None else {
        port: DEFAULT_PORTS.get(port, str(port))
        for port in (22, 80, 443, 445, 3389, 8080, 8081, 8880, 9999)
    }
    if not selected_ports or len(selected_ports) > 32 or any(
        not isinstance(port, int) or not 1 <= port <= 65535 for port in selected_ports
    ):
        raise ValueError("monitor supports between 1 and 32 TCP ports")
    scanner = scanner_factory(timeout=max(0.1, min(timeout, 2.0)),
                              workers=max(1, min(workers, 32)), ports=selected_ports)
    hosts = scanner.scan(targets, discover_services=False)
    reachable = [host for host in hosts if host.reachable]
    snapshot_id = record_scan(reachable, target, history_path)
    return {"snapshot_id": snapshot_id, "target": target,
            "scanned": len(targets), "reachable": len(reachable),
            "recorded_at": datetime.now(UTC).isoformat()}


def monitor_loop(target: str, *, interval: int = 300, count: int | None = None,
                 history_path: Path | None = None,
                 stop: threading.Event | None = None,
                 on_result: Callable[[dict[str, object]], None] | None = None,
                 scan_once: Callable[..., dict[str, object]] = monitor_once) -> int:
    """Run in the foreground only; stop promptly on Ctrl+C or supplied event."""
    if not MIN_INTERVAL_SECONDS <= interval <= 86_400:
        raise ValueError("monitor interval must be between 60 and 86400 seconds")
    if count is not None and not 1 <= count <= 10_000:
        raise ValueError("monitor count must be between 1 and 10000")
    validate_monitor_target(target)
    event = stop or threading.Event()
    completed = 0
    while not event.is_set() and (count is None or completed < count):
        result = scan_once(target, history_path=history_path)
        completed += 1
        if on_result:
            on_result(result)
        if count is not None and completed >= count:
            break
        event.wait(interval)
    return completed


def local_report(history_path: Path | None = None, *, include_identifiers: bool = False) -> dict:
    """Summarise local scan history without sending it anywhere.

    Identifiers are omitted by default; users explicitly opt in for LAN IP,
    MAC and hostname details in a report they intend to share.
    """
    path = (history_path or default_history_path()).expanduser().resolve()
    evidence = latest_evidence(path)
    changes = evidence.get("changes", {})
    report = {
        "schema": "advanced-ip-analyser/local-monitor/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "local_only": True,
        "identifiers_included": include_identifiers,
        "snapshots": [{"created_at": s.get("created_at"), "host_count": s.get("host_count")}
                      for s in evidence.get("snapshots", [])],
        "summary": {name: len(changes.get(name, [])) for name in ("new", "missing", "changed")},
    }
    if include_identifiers:
        # Already bounded and credential-filtered by scan_history._host_evidence.
        report["changes"] = changes
    else:
        report["changes"] = {
            "new": [{"ports": item.get("ports", []), "device_type": item.get("device_type", "")}
                    for item in changes.get("new", [])],
            "missing": [{"ports": item.get("ports", []), "device_type": item.get("device_type", "")}
                        for item in changes.get("missing", [])],
            "changed": [{"fields": item.get("fields", [])} for item in changes.get("changed", [])],
        }
    report["current_devices"] = []
    if path.is_file():
        uri = f"file:{path.as_posix()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
            rows = connection.execute(
                "SELECT evidence_json FROM scan_observation WHERE snapshot_id = "
                "(SELECT id FROM scan_snapshot ORDER BY id DESC LIMIT 1) LIMIT ?",
                (MAX_MONITOR_HOSTS,)
            ).fetchall()
        for (raw,) in rows:
            try:
                host = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if not isinstance(host, dict):
                continue
            if include_identifiers:
                report["current_devices"].append({key: host.get(key) for key in (
                    "address", "hostname", "mac", "manufacturer", "device_type",
                    "operating_system", "model", "ports", "services")})
            else:
                report["current_devices"].append({key: host.get(key) for key in (
                    "device_type", "ports", "services")})
    return report


def save_local_report(path: Path, report: dict) -> Path:
    """Atomically save a private report file; never transmit it."""
    destination = path.expanduser().resolve()
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("monitor report exceeds the size limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".ai-monitor-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        if os.name == "posix":
            destination.chmod(0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination
