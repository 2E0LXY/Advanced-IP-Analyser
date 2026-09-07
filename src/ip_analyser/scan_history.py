from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from .models import Host

MAX_SNAPSHOTS = 1_000
MAX_HOSTS_PER_SNAPSHOT = 65_536
MAX_NETWORK_WATCH_DATABASE_BYTES = 1024 * 1024 * 1024
_SENSITIVE_METADATA_NAME = re.compile(
    r"(?:^|[-_\s])(authorization|cookie|credential|password|private[-_\s]?key|"
    r"proxy[-_\s]?authorization|secret|token)(?:$|[-_\s])",
    re.IGNORECASE,
)


def default_history_path() -> Path:
    return Path.home() / ".local" / "share" / "advanced-ip-analyser" / "scan-history.sqlite3"


def default_network_watch_path() -> Path:
    return Path.home() / ".local" / "share" / "advanced-ip-analyser" / "network-watch.sqlite3"


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS scan_snapshot (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            target TEXT NOT NULL,
            host_count INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_observation (
            snapshot_id INTEGER NOT NULL REFERENCES scan_snapshot(id) ON DELETE CASCADE,
            identity TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            PRIMARY KEY (snapshot_id, identity)
        );
        CREATE INDEX IF NOT EXISTS scan_observation_identity
            ON scan_observation(identity, snapshot_id);
    """)
    if os.name == "posix":
        path.chmod(0o600)
    return connection


def _host_evidence(host: Host) -> dict[str, object]:
    metadata: dict[str, dict[str, str]] = {}
    for port, details in list(host.service_info.items())[:1_024]:
        safe_details: dict[str, str] = {}
        for name, value in list(details.items())[:64]:
            label = str(name)[:128]
            if _SENSITIVE_METADATA_NAME.search(label):
                continue
            safe_details[label] = str(value)[:2_048]
        metadata[str(port)] = safe_details
    return {
        "address": host.address,
        "hostname": host.hostname[:1_024],
        "mac": host.mac[:32],
        "manufacturer": host.manufacturer[:1_024],
        "device_type": host.device_type[:128],
        "operating_system": host.operating_system[:128],
        "os_version": host.os_version[:128],
        "model": host.model[:256],
        "profile_confidence": host.profile_confidence[:32],
        "ports": list(host.ports[:65_535]),
        "services": list(host.services[:65_535]),
        "service_info": metadata,
    }


def record_scan(hosts: Iterable[Host], target: str, path: Path | None = None) -> int:
    observations = list(hosts)
    if len(observations) > MAX_HOSTS_PER_SNAPSHOT:
        raise ValueError("scan history snapshot contains too many hosts")
    if not isinstance(target, str) or len(target) > 4_096:
        raise ValueError("scan target is invalid")
    # A host may be discovered by more than one probe. Keep the final, richest
    # observation for each stable identity so history writes remain atomic.
    unique_observations = {host.identity: host for host in observations}
    path = path or default_history_path()
    with closing(_connect(path)) as connection, connection:
        cursor = connection.execute(
            "INSERT INTO scan_snapshot(created_at, target, host_count) VALUES (?, ?, ?)",
            (datetime.now(UTC).isoformat(), target, len(unique_observations)))
        snapshot_id = int(cursor.lastrowid)
        rows = [(snapshot_id, host.identity, json.dumps(_host_evidence(host), separators=(",", ":"),
                                                        sort_keys=True))
                for host in unique_observations.values()]
        connection.executemany(
            "INSERT INTO scan_observation(snapshot_id, identity, evidence_json) VALUES (?, ?, ?)", rows)
        connection.execute("""
            DELETE FROM scan_snapshot WHERE id NOT IN (
                SELECT id FROM scan_snapshot ORDER BY id DESC LIMIT ?
            )
        """, (MAX_SNAPSHOTS,))
    return snapshot_id


def _snapshot(connection: sqlite3.Connection, snapshot_id: int) -> dict[str, dict[str, object]]:
    rows = connection.execute(
        "SELECT identity, evidence_json FROM scan_observation WHERE snapshot_id = ?",
        (snapshot_id,)).fetchall()
    result: dict[str, dict[str, object]] = {}
    for identity, raw in rows:
        try:
            evidence = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(identity, str) and isinstance(evidence, dict):
            result[identity] = evidence
    return result


def latest_evidence(path: Path | None = None, *, snapshot_limit: int = 30) -> dict[str, object]:
    if not 2 <= snapshot_limit <= 100:
        raise ValueError("snapshot limit must be between 2 and 100")
    path = path or default_history_path()
    if not path.exists():
        return {"snapshots": [], "changes": {"new": [], "missing": [], "changed": []}}
    with closing(_connect(path)) as connection:
        rows = connection.execute(
            "SELECT id, created_at, target, host_count FROM scan_snapshot ORDER BY id DESC LIMIT ?",
            (snapshot_limit,)).fetchall()
        snapshots = [{"id": row[0], "created_at": row[1], "target": row[2], "host_count": row[3]}
                     for row in rows]
        if len(rows) < 2:
            return {"snapshots": snapshots, "changes": {"new": [], "missing": [], "changed": []}}
        current, previous = _snapshot(connection, rows[0][0]), _snapshot(connection, rows[1][0])
    new = [current[key] for key in current.keys() - previous.keys()]
    missing = [previous[key] for key in previous.keys() - current.keys()]
    changed: list[dict[str, object]] = []
    for key in current.keys() & previous.keys():
        before, after = previous[key], current[key]
        fields = [name for name in ("address", "hostname", "mac", "manufacturer", "device_type",
                                    "operating_system", "os_version", "model", "ports", "services")
                  if before.get(name) != after.get(name)]
        if fields:
            changed.append({"identity": key, "fields": fields, "before": before, "after": after})
    return {"snapshots": snapshots,
            "changes": {"new": new[:1_000], "missing": missing[:1_000], "changed": changed[:1_000]},
            "capacity": _capacity_evidence(snapshots)}


def _bounded_json(value: object, default: object) -> object:
    if not isinstance(value, str) or len(value) > 1_000_000:
        return default
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return default
    return parsed


def latest_network_watch_evidence(path: Path | None = None) -> dict[str, object]:
    """Read a bounded summary of the most recent Network Watch session."""
    path = (path or default_network_watch_path()).expanduser().resolve()
    if not path.is_file():
        return {"available": False, "reason": "No Network Watch session database."}
    if path.stat().st_size > MAX_NETWORK_WATCH_DATABASE_BYTES:
        return {"available": False, "reason": "Network Watch database exceeds the read limit."}
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
            session = connection.execute(
                "SELECT id,started,ended,packets,bytes FROM sessions ORDER BY started DESC LIMIT 1"
            ).fetchone()
            if not session:
                return {"available": False, "reason": "No completed Network Watch session."}
            session_id = int(session[0])
            devices = connection.execute(
                "SELECT address,first_seen,last_seen,sent,received,peers,protocols "
                "FROM devices WHERE session_id=? LIMIT 2000", (session_id,)).fetchall()
            flows = connection.execute(
                "SELECT endpoint_a,port_a,endpoint_b,port_b,protocol,packets,bytes,diagnostics "
                "FROM flows WHERE session_id=? LIMIT 5000", (session_id,)).fetchall()
            dns = connection.execute(
                "SELECT timestamp,device,server,name,response,rcode FROM dns "
                "WHERE session_id=? LIMIT 5000", (session_id,)).fetchall()
            findings = connection.execute(
                "SELECT timestamp,severity,category,subject,explanation FROM findings "
                "WHERE session_id=? LIMIT 2000", (session_id,)).fetchall()
    except sqlite3.Error as error:
        return {"available": False, "reason": f"Network Watch history is unreadable: {type(error).__name__}."}
    return {
        "available": True,
        "session": {"started": session[1], "ended": session[2], "packets": session[3],
                    "bytes": session[4]},
        "devices": [{"address": row[0], "first_seen": row[1], "last_seen": row[2],
                     "sent": row[3], "received": row[4],
                     "peers": _bounded_json(row[5], []),
                     "protocols": _bounded_json(row[6], {})} for row in devices],
        "flows": [{"endpoint_a": row[0], "port_a": row[1], "endpoint_b": row[2],
                   "port_b": row[3], "protocol": row[4], "packets": row[5], "bytes": row[6],
                   "diagnostics": _bounded_json(row[7], {})} for row in flows],
        "dns": [{"timestamp": row[0], "device": row[1], "server": row[2], "name": row[3],
                 "response": bool(row[4]), "rcode": row[5]} for row in dns],
        "findings": [{"timestamp": row[0], "severity": row[1], "category": row[2],
                      "subject": row[3], "explanation": row[4]} for row in findings],
    }


def _capacity_evidence(snapshots: list[dict[str, object]]) -> dict[str, object]:
    if not snapshots:
        return {"available": False, "reason": "No completed scan snapshots."}
    target = snapshots[0].get("target")
    if not isinstance(target, str):
        return {"available": False, "reason": "The latest target is not a single subnet."}
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        return {"available": False, "reason": "The latest target is not a single subnet."}
    if network.version == 4 and network.prefixlen <= 30:
        usable = max(0, network.num_addresses - 2)
    else:
        usable = network.num_addresses
    counts = [int(item["host_count"]) for item in reversed(snapshots)
              if isinstance(item.get("host_count"), int)]
    return {"available": True, "subnet": str(network), "address_capacity": usable,
            "observed_reachable_counts_oldest_first": counts,
            "latest_observed_utilization_percent": round((counts[-1] / usable * 100), 2) if usable else 0,
            "limitation": "Reachable-address counts are not DHCP lease or pool data."}
