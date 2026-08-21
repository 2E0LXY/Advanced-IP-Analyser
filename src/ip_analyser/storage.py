from __future__ import annotations

import csv
import html
import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Host


MAX_INVENTORY_BYTES = 20 * 1024 * 1024


def _read_bounded(path: Path) -> str:
    if path.stat().st_size > MAX_INVENTORY_BYTES:
        raise ValueError("inventory file exceeds the 20 MiB limit")
    return path.read_text(encoding="utf-8")


def _csv_safe(value: object) -> object:
    """Prevent spreadsheet formula execution from network- or user-supplied text."""
    if not isinstance(value, str):
        return value
    return "'" + value if re.match(r"^[\s]*[=+@-]", value) else value


def save_favorites(path: Path, hosts: list[Host]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps({"format": 1, "devices": [host.to_dict() for host in hosts]}, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_favorites(path: Path) -> list[Host]:
    if not path.exists():
        return []
    data = json.loads(_read_bounded(path))
    if (not isinstance(data, dict) or data.get("format") != 1 or
            not isinstance(data.get("devices"), list)):
        raise ValueError("unsupported favorites file")
    return [Host.from_dict(item) for item in data["devices"]]


def export(path: Path, hosts: list[Host]) -> None:
    suffix = path.suffix.lower()
    if suffix == ".json":
        path.write_text(json.dumps([host.to_dict() for host in hosts], indent=2) + "\n", encoding="utf-8")
    elif suffix == ".csv":
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["address", "reachable", "hostname", "latency_ms", "mac", "manufacturer", "services", "ports", "service_info", "seen_at", "note"])
            for host in hosts:
                writer.writerow([_csv_safe(value) for value in
                                 [host.address, host.reachable, host.hostname, host.latency_ms, host.mac, host.manufacturer,
                                  ",".join(host.services), ",".join(str(port) for port in host.ports),
                                  json.dumps(host.service_info, sort_keys=True), host.seen_at, host.note]])
    elif suffix in {".html", ".htm"}:
        rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in
            [h.address, h.reachable, h.hostname, h.latency_ms if h.latency_ms is not None else "",
             h.mac, h.manufacturer, ", ".join(h.services), ", ".join(str(port) for port in h.ports),
             json.dumps(h.service_info, sort_keys=True), h.seen_at, h.note]) + "</tr>" for h in hosts)
        path.write_text("<!doctype html><meta charset=utf-8><title>Network inventory</title>"
                        "<table><thead><tr><th>Address</th><th>Reachable</th><th>Hostname</th><th>Latency ms</th>"
                        "<th>MAC</th><th>Manufacturer</th><th>Services</th><th>Ports</th><th>Service details</th>"
                        "<th>Seen</th><th>Note</th></tr></thead>"
                        f"<tbody>{rows}</tbody></table>\n", encoding="utf-8")
    elif suffix == ".xml":
        root = ET.Element("advanced-ip-analyser", {"format": "1"})
        for host in hosts:
            device = ET.SubElement(root, "device")
            for key, value in host.to_dict().items():
                child = ET.SubElement(device, key)
                if isinstance(value, list):
                    child.text = ",".join(str(item) for item in value)
                elif isinstance(value, dict):
                    child.text = json.dumps(value, sort_keys=True)
                else:
                    child.text = str(value if value is not None else "")
        ET.indent(root)
        ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
    else:
        raise ValueError("export filename must end in .csv, .json, .xml, or .html")


def import_inventory(path: Path, limit: int = 65_536) -> list[Host]:
    """Load this application's JSON or XML inventory formats safely."""
    content = _read_bounded(path)
    if path.suffix.lower() == ".json":
        data = json.loads(content)
        values = data.get("devices") if isinstance(data, dict) else data
        if not isinstance(values, list):
            raise ValueError("inventory JSON must contain a device list")
        hosts = [Host.from_dict(value) for value in values]
    elif path.suffix.lower() == ".xml":
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.IGNORECASE):
            raise ValueError("inventory XML declarations and entities are not allowed")
        try:
            root = ET.fromstring(content)
        except ET.ParseError as error:
            raise ValueError("inventory XML is malformed") from error
        if root.tag != "advanced-ip-analyser" or root.get("format") != "1":
            raise ValueError("unsupported inventory XML format")
        hosts = []
        for device in root.findall("device"):
            value = {child.tag: child.text or "" for child in device}
            value["services"] = [item for item in value.get("services", "").split(",") if item]
            value["ports"] = [int(item) for item in value.get("ports", "").split(",") if item]
            try:
                value["service_info"] = json.loads(value.get("service_info", "") or "{}")
            except json.JSONDecodeError as error:
                raise ValueError("invalid service metadata in inventory XML") from error
            value["reachable"] = value.get("reachable", "").casefold() == "true"
            latency = value.get("latency_ms", "")
            value["latency_ms"] = float(latency) if latency else None
            hosts.append(Host.from_dict(value))
    else:
        raise ValueError("inventory filename must end in .json or .xml")
    if len(hosts) > limit:
        raise ValueError(f"inventory contains more than {limit:,} devices")
    return hosts


def merge_devices(saved: list[Host], observed: list[Host]) -> list[Host]:
    """Merge scan observations by MAC first, retaining saved notes and offline devices."""
    merged = {host.identity: host for host in saved}
    address_keys = {host.address.casefold(): key for key, host in merged.items()}
    for host in observed:
        key = host.identity
        old_key = key if key in merged else address_keys.get(host.address.casefold())
        if old_key is not None:
            previous = merged.pop(old_key)
            address_keys = {address: identity for address, identity in address_keys.items()
                            if identity != old_key}
            updated = previous.merge_observation(host)
            merged[updated.identity] = updated
            address_keys[updated.address.casefold()] = updated.identity
        else:
            merged[key] = host
            address_keys[host.address.casefold()] = key
    return sorted(merged.values(), key=lambda host: (host.hostname.casefold(), host.address))
