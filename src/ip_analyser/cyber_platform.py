"""Evidence-only cyber overview. LAN service exposure is not a verified CVE."""

from __future__ import annotations

from .models import Host
from .network_intelligence import analyse_hosts

MAX_DASHBOARD_DEVICES = 1024


def build_cyber_overview(report: dict) -> dict:
    """Summarise a saved local-monitor report without any network operations."""
    if not isinstance(report, dict):
        raise ValueError("cyber overview needs a local monitor report")
    raw = report.get("current_devices", [])
    if not isinstance(raw, list) or len(raw) > MAX_DASHBOARD_DEVICES:
        raise ValueError("invalid or oversized device inventory")
    hosts: list[Host] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        address = item.get("address")
        # Redacted reports cannot provide a per-device drilldown.
        if not isinstance(address, str) or not address.strip():
            continue
        ports = item.get("ports", [])
        services = item.get("services", [])
        if not isinstance(ports, list) or not isinstance(services, list):
            continue
        if len(ports) > 65535 or len(ports) != len(services):
            continue
        if not all(type(port) is int and 1 <= port <= 65535 for port in ports):
            continue
        if not all(isinstance(service, str) for service in services):
            continue
        try:
            host = Host.from_dict({
                "address": address, "reachable": True,
                "hostname": item.get("hostname") or "",
                "mac": item.get("mac") or "",
                "manufacturer": item.get("manufacturer") or "",
                "device_type": item.get("device_type") or "",
                "operating_system": item.get("operating_system") or "",
                "model": item.get("model") or "",
                "ports": ports, "services": services,
            })
        except (TypeError, ValueError):
            continue
        hosts.append(host)
    analysed = analyse_hosts(hosts)
    counts = {level: sum(item.risk_level == level for item in analysed)
              for level in ("Critical", "High", "Medium", "Low")}
    changes = report.get("summary", {})
    if not isinstance(changes, dict):
        changes = {}

    def change_count(kind: str) -> int:
        value = changes.get(kind, 0)
        return value if type(value) is int and 0 <= value <= 100000 else 0

    snapshots = report.get("snapshots", [])
    history = []
    if isinstance(snapshots, list):
        for snapshot in reversed(snapshots[:30]):
            if not isinstance(snapshot, dict):
                continue
            count = snapshot.get("host_count")
            if type(count) is int and 0 <= count <= 65536:
                history.append((str(snapshot.get("created_at") or ""), count))
    devices = [{
        "address": item.host.address,
        "name": item.host.hostname or item.host.device_type or "Unidentified device",
        "zone": item.zone,
        "score": item.risk_score,
        "level": item.risk_level,
        "ports": tuple(sorted(set(item.host.ports))),
        "factors": item.factors,
    } for item in analysed]
    return {
        "devices": devices, "total": len(analysed),
        "open_ports": sum(len(item["ports"]) for item in devices),
        "priority_review": counts["Critical"] + counts["High"],
        "risk_distribution": counts,
        "changes": {key: change_count(key) for key in ("new", "missing", "changed")},
        "history": history, "last_scan": history[-1][0] if history else None,
        "cve_status": "Not assessed",
        "internet_exposure_status": "Not verified from outside LAN",
    }
