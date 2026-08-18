from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from .models import Host


def save_favorites(path: Path, hosts: list[Host]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"format": 1, "devices": [host.to_dict() for host in hosts]}, indent=2) + "\n")


def load_favorites(path: Path) -> list[Host]:
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    if data.get("format") != 1 or not isinstance(data.get("devices"), list):
        raise ValueError("unsupported favorites file")
    return [Host.from_dict(item) for item in data["devices"]]


def export(path: Path, hosts: list[Host]) -> None:
    suffix = path.suffix.lower()
    if suffix == ".json":
        path.write_text(json.dumps([host.to_dict() for host in hosts], indent=2) + "\n")
    elif suffix == ".csv":
        with path.open("w", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["address", "reachable", "hostname", "latency_ms", "mac", "services", "seen_at", "note"])
            for host in hosts:
                writer.writerow([host.address, host.reachable, host.hostname, host.latency_ms, host.mac, ",".join(host.services), host.seen_at, host.note])
    elif suffix in {".html", ".htm"}:
        rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in
            [h.address, h.hostname, h.mac, ", ".join(h.services), h.seen_at]) + "</tr>" for h in hosts)
        path.write_text("<!doctype html><meta charset=utf-8><title>Network inventory</title>"
                        "<table><thead><tr><th>Address</th><th>Hostname</th><th>MAC</th><th>Services</th><th>Seen</th></tr></thead>"
                        f"<tbody>{rows}</tbody></table>\n")
    else:
        raise ValueError("export filename must end in .csv, .json, or .html")
