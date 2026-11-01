"""Cross-platform live connection inventory and destination geolocation."""

from __future__ import annotations

import csv
import ipaddress
import json
import socket
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

MAX_GEO_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class ConnectionRecord:
    observed_at: str
    direction: str
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: int | None
    application: str
    executable: str

    @property
    def identity(self) -> tuple[Any, ...]:
        return (self.protocol, self.local_address, self.local_port,
                self.remote_address, self.remote_port, self.pid)


@dataclass(frozen=True, slots=True)
class GeoLocation:
    address: str
    city: str = ""
    region: str = ""
    country: str = ""
    organisation: str = ""
    latitude: float | None = None
    longitude: float | None = None

    @property
    def label(self) -> str:
        return ", ".join(part for part in
                         (self.city, self.region, self.country, self.organisation) if part) \
            or "Location unavailable"


def _endpoint(value: Any) -> tuple[str, int]:
    if not value:
        return "", 0
    address = getattr(value, "ip", value[0])
    port = getattr(value, "port", value[1])
    return str(address), int(port)


def _process_details(pid: int | None, cache: dict[int, tuple[str, str]]) -> tuple[str, str]:
    if pid is None:
        return "System / unavailable", ""
    if pid in cache:
        return cache[pid]
    try:
        process = psutil.Process(pid)
        details = (process.name() or f"PID {pid}", process.exe() or "")
    except (psutil.Error, OSError):
        details = (f"PID {pid}", "")
    cache[pid] = details
    return details


def snapshot_connections(process_cache: dict[int, tuple[str, str]] | None = None) -> list[ConnectionRecord]:
    """Return current TCP/UDP endpoints with best-effort owning-process details."""
    cache = process_cache if process_cache is not None else {}
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as error:
        raise RuntimeError("Connection ownership requires administrator/root permission on this system.") from error
    listeners: set[tuple[str, int]] = set()
    for connection in connections:
        local_address, local_port = _endpoint(connection.laddr)
        protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
        if local_address and not connection.raddr and connection.status in {psutil.CONN_LISTEN, "NONE"}:
            listeners.add((protocol, local_port))

    observed = datetime.now().astimezone().strftime("%H:%M:%S")
    records: list[ConnectionRecord] = []
    for connection in connections:
        local_address, local_port = _endpoint(connection.laddr)
        remote_address, remote_port = _endpoint(connection.raddr)
        if not local_address:
            continue
        protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
        if not remote_address:
            direction = "Listening"
        elif (protocol, local_port) in listeners:
            direction = "Inbound"
        else:
            direction = "Outbound"
        application, executable = _process_details(connection.pid, cache)
        records.append(ConnectionRecord(
            observed, direction, protocol, local_address, local_port,
            remote_address, remote_port, connection.status or "NONE",
            connection.pid, application, executable,
        ))
    order = {"Outbound": 0, "Inbound": 1, "Listening": 2}
    return sorted(records, key=lambda item: (order.get(item.direction, 9), item.application.casefold(),
                                              item.remote_address, item.remote_port))


def is_public_address(address: str) -> bool:
    try:
        value = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return not (value.is_private or value.is_loopback or value.is_link_local or
                value.is_multicast or value.is_unspecified or value.is_reserved)


def locate_address(address: str, timeout: float = 4.0) -> GeoLocation:
    """Resolve a public endpoint through ipwho.is; private endpoints stay local."""
    clean = address.split("%", 1)[0]
    try:
        ipaddress.ip_address(clean)
    except ValueError as error:
        raise ValueError("destination must be an IP address") from error
    if not is_public_address(clean):
        return GeoLocation(clean, country="Private / local network")
    url = ("https://ipwho.is/" + urllib.parse.quote(clean, safe=".:" ) +
           "?fields=success,ip,country,region,city,latitude,longitude,connection")
    request = urllib.request.Request(url, headers={"User-Agent": "Advanced-IP-Analyser connection-map"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - fixed HTTPS host
        encoded = response.read(MAX_GEO_RESPONSE_BYTES + 1)
    if len(encoded) > MAX_GEO_RESPONSE_BYTES:
        raise ValueError("geolocation response is too large")
    try:
        payload = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("geolocation service returned invalid data") from error
    if not isinstance(payload, dict) or not payload.get("success"):
        return GeoLocation(clean)
    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    return GeoLocation(
        clean,
        str(payload.get("city", "")), str(payload.get("region", "")),
        str(payload.get("country", "")),
        str(connection.get("isp") or connection.get("org") or ""),
        float(payload["latitude"]) if isinstance(payload.get("latitude"), (int, float)) else None,
        float(payload["longitude"]) if isinstance(payload.get("longitude"), (int, float)) else None,
    )


def export_connections(path: Path, records: list[ConnectionRecord],
                       locations: dict[str, GeoLocation]) -> None:
    rows = []
    for record in records:
        row = asdict(record)
        location = locations.get(record.remote_address)
        row.update({
            "destination_location": location.label if location else "",
            "latitude": location.latitude if location else None,
            "longitude": location.longitude if location else None,
        })
        rows.append(row)
    if path.suffix.casefold() == ".json":
        path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]) if rows else [
            "observed_at", "direction", "protocol", "local_address", "local_port",
            "remote_address", "remote_port", "state", "pid", "application", "executable",
            "destination_location", "latitude", "longitude",
        ])
        writer.writeheader()
        writer.writerows(rows)
