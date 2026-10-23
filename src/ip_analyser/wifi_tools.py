from __future__ import annotations

import json
import csv
import html
import os
import re
import shutil
import stat
import struct
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .vendors import MacVendorLookup


MAX_WIFI_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_WIFI_PACKETS = 100_000
MAX_WIFI_HISTORY_BYTES = 5 * 1024 * 1024
MAX_WIFI_HISTORY_ENTRIES = 365
MAX_WIFI_HISTORY_APS = 4_096
_INTERFACE = re.compile(r"[A-Za-z0-9_.:@-]{1,15}")
_MONITOR = re.compile(r"aia[0-9]{1,6}mon")


@dataclass(slots=True)
class WifiClient:
    mac: str
    bssid: str
    packets: int = 0
    signal_dbm: int | None = None
    first_seen: float = 0
    last_seen: float = 0
    probes: set[str] = field(default_factory=set)


@dataclass(slots=True)
class AccessPoint:
    bssid: str
    name: str = ""
    channel: int | None = None
    signal_dbm: int | None = None
    security: str = "Open or unknown"
    beacons: int = 0
    data_packets: int = 0
    first_seen: float = 0
    last_seen: float = 0
    handshake_seen: bool = False
    wps_advertised: bool = False
    manufacturer: str = ""
    risk_level: str = "No obvious issue"
    risk_reasons: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    clients: dict[str, WifiClient] = field(default_factory=dict)


def list_wireless_interfaces() -> list[str]:
    root = Path("/sys/class/net")
    if not root.is_dir():
        return []
    return sorted(path.name for path in root.iterdir()
                  if _INTERFACE.fullmatch(path.name) and (path / "wireless").is_dir())


def _helper_path() -> Path:
    return Path(__file__).with_name("wifi_helper.py").resolve()


def _pkexec_command(action: str, interface: str, channels: list[int] | None = None,
                    duration: int = 300) -> list[str]:
    if action == "create":
        if not _INTERFACE.fullmatch(interface):
            raise ValueError("invalid wireless interface")
    elif not _MONITOR.fullmatch(interface):
        raise ValueError("invalid managed monitor interface")
    helper = _helper_path()
    metadata = helper.stat()
    if (os.name != "posix" or metadata.st_uid != 0 or
            metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError("passive Wi-Fi Watch requires the installed Debian package")
    pkexec = shutil.which("pkexec")
    if not pkexec:
        raise RuntimeError("PolicyKit is unavailable; install the pkexec package")
    command = [pkexec, "/usr/bin/python3", "-I", str(helper), action,
               "--interface", interface, "--duration", str(duration)]
    if channels is not None:
        if (not channels or len(channels) > 128 or
                any(isinstance(value, bool) or not 1 <= value <= 233 for value in channels)):
            raise ValueError("wireless channel plan is invalid")
        command.extend(["--channels", ",".join(str(value) for value in channels)])
    return command


def create_monitor_interface(interface: str) -> str:
    result = subprocess.run(_pkexec_command("create", interface), capture_output=True,
                            text=True, timeout=30)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or
                           "wireless monitor authorization failed")
    monitor = result.stdout.strip()
    if not _MONITOR.fullmatch(monitor):
        raise RuntimeError("wireless helper returned an invalid monitor interface")
    return monitor


def remove_monitor_interface(interface: str) -> None:
    result = subprocess.run(_pkexec_command("remove", interface), capture_output=True,
                            text=True, timeout=30)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or
                           "wireless monitor cleanup failed")


def start_channel_hopper(interface: str, channels: list[int], duration: int) -> subprocess.Popen:
    return subprocess.Popen(_pkexec_command("hop", interface, channels, duration),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _mac(value: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in value)


def _radiotap(frame: bytes) -> tuple[int, int | None]:
    if len(frame) < 8 or frame[0] != 0:
        raise ValueError("invalid radiotap header")
    length = struct.unpack("<H", frame[2:4])[0]
    if length < 8 or length > len(frame):
        raise ValueError("truncated radiotap header")
    first_present = struct.unpack("<I", frame[4:8])[0]
    present = first_present
    offset = 8
    while present & 0x80000000:
        if offset + 4 > length:
            return length, None
        present = struct.unpack("<I", frame[offset:offset + 4])[0]
        offset += 4
    # Walk the standard fields that precede dBm antenna signal. Radiotap fields
    # are aligned relative to the beginning of the header, not packed.
    standard = ((0, 8, 8), (1, 1, 1), (2, 1, 1), (3, 2, 4), (4, 2, 2), (5, 1, 1))
    signal = None
    for bit, alignment, size in standard:
        if not first_present & (1 << bit):
            continue
        offset = (offset + alignment - 1) & ~(alignment - 1)
        if offset + size > length:
            return length, None
        if bit == 5:
            signal = struct.unpack("b", frame[offset:offset + 1])[0]
        offset += size
    return length, signal


def _tags(data: bytes) -> dict[int, list[bytes]]:
    result: dict[int, list[bytes]] = {}
    offset = 0
    while offset + 2 <= len(data):
        kind, length = data[offset], data[offset + 1]
        offset += 2
        if offset + length > len(data):
            break
        result.setdefault(kind, []).append(data[offset:offset + length])
        offset += length
    return result


def _security(capabilities: int, tags: dict[int, list[bytes]]) -> str:
    if 48 in tags:
        values = b"".join(tags[48])
        if b"\x00\x0f\xac\x08" in values or b"\x00\x0f\xac\x09" in values:
            return "WPA3"
        return "WPA2/RSN"
    if any(value.startswith(b"\x00\x50\xf2\x01") for value in tags.get(221, [])):
        return "WPA"
    return "WEP" if capabilities & 0x10 else "Open"


def wifi_security_assessment(security: str, wps_advertised: bool = False) -> tuple[str, list[str]]:
    """Return cautious configuration findings from advertised security only."""
    value = security.strip().upper()
    reasons = []
    level = "No obvious issue"
    if value.startswith("OPEN") or value == "OPEN OR UNKNOWN":
        level = "High"
        reasons.append("No wireless encryption was advertised; verify this is an intentional guest network.")
    elif value.startswith("WEP"):
        level = "High"
        reasons.append("WEP is obsolete and should be replaced with WPA2-AES or WPA3.")
    elif value == "WPA" or value.startswith("WPA ·") or value.startswith("WPA PERSONAL"):
        level = "Medium"
        reasons.append("Legacy WPA/TKIP was advertised; migrate to WPA2-AES or WPA3.")
    if wps_advertised:
        if level == "No obvious issue":
            level = "Medium"
        reasons.append("WPS was advertised; disable it unless it is specifically required and controlled.")
    return level, reasons


def _pcap_records(path: Path):
    if path.stat().st_size > MAX_WIFI_CAPTURE_BYTES:
        raise ValueError("wireless recording exceeds the 512 MiB limit")
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) < 24 or header[:4] != b"\xd4\xc3\xb2\xa1":
            raise ValueError("wireless recording must be little-endian PCAP")
        if struct.unpack("<I", header[20:24])[0] != 127:
            raise ValueError("wireless recording does not contain radiotap packets")
        for _count in range(MAX_WIFI_PACKETS):
            packet_header = stream.read(16)
            if not packet_header:
                return
            if len(packet_header) < 16:
                return  # An active capture may be between header writes.
            seconds, micros, captured, original = struct.unpack("<IIII", packet_header)
            if captured > 262_144:
                raise ValueError("wireless packet exceeds the safe capture limit")
            packet = stream.read(captured)
            if len(packet) < captured:
                return
            yield seconds + micros / 1_000_000, packet, original


def analyze_wifi_capture(path: Path) -> tuple[list[AccessPoint], list[WifiClient]]:
    aps: dict[str, AccessPoint] = {}
    unlinked: dict[str, WifiClient] = {}
    for timestamp, raw, _original in _pcap_records(path.expanduser().resolve()):
        try:
            offset, signal = _radiotap(raw)
        except ValueError:
            continue
        frame = raw[offset:]
        if len(frame) < 24:
            continue
        control = struct.unpack("<H", frame[:2])[0]
        frame_type, subtype = (control >> 2) & 3, (control >> 4) & 15
        to_ds, from_ds = bool(control & 0x100), bool(control & 0x200)
        address1, address2, address3 = _mac(frame[4:10]), _mac(frame[10:16]), _mac(frame[16:22])
        if frame_type == 0 and subtype in {8, 5} and len(frame) >= 36:
            bssid = address3
            tags = _tags(frame[36:])
            name = tags.get(0, [b""])[0].decode("utf-8", "replace")[:64]
            channel = tags.get(3, [b""])[0]
            capabilities = struct.unpack("<H", frame[34:36])[0]
            ap = aps.setdefault(bssid, AccessPoint(bssid, first_seen=timestamp,
                                                   last_seen=timestamp))
            ap.name = name or ap.name or "<hidden>"
            ap.channel = channel[0] if channel else ap.channel
            ap.signal_dbm = signal if signal is not None else ap.signal_dbm
            ap.security = _security(capabilities, tags)
            ap.wps_advertised = any(value.startswith(b"\x00\x50\xf2\x04")
                                    for value in tags.get(221, []))
            ap.risk_level, ap.risk_reasons = wifi_security_assessment(
                ap.security, ap.wps_advertised)
            ap.beacons += int(subtype == 8)
            ap.last_seen = timestamp
        elif frame_type == 0 and subtype == 4:
            tags = _tags(frame[24:])
            probes = {value.decode("utf-8", "replace")[:64] for value in tags.get(0, []) if value}
            client = unlinked.setdefault(address2, WifiClient(address2, "", first_seen=timestamp,
                                                               last_seen=timestamp))
            client.probes.update(probes)
            client.packets += 1
            client.signal_dbm = signal if signal is not None else client.signal_dbm
            client.last_seen = timestamp
        elif frame_type == 2:
            if to_ds and not from_ds:
                bssid, station = address1, address2
            elif from_ds and not to_ds:
                bssid, station = address2, address1
            else:
                continue
            ap = aps.setdefault(bssid, AccessPoint(bssid, first_seen=timestamp,
                                                   last_seen=timestamp))
            discovered = unlinked.pop(station, None)
            client = ap.clients.setdefault(station, WifiClient(
                station, bssid, first_seen=timestamp, last_seen=timestamp))
            if discovered:
                client.probes.update(discovered.probes)
                client.packets += discovered.packets
                client.signal_dbm = discovered.signal_dbm
                client.first_seen = min(client.first_seen, discovered.first_seen)
            client.packets += 1
            client.signal_dbm = signal if signal is not None else client.signal_dbm
            client.last_seen = timestamp
            ap.data_packets += 1
            ap.last_seen = timestamp
            header_length = 26 if control & 0x80 else 24
            payload = frame[header_length:]
            if b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in payload[:32]:
                ap.handshake_seen = True
    rogue_wifi_indicators(aps.values())
    return (sorted(aps.values(), key=lambda ap: (ap.signal_dbm or -999), reverse=True),
            sorted(unlinked.values(), key=lambda client: client.packets, reverse=True))


def rogue_wifi_indicators(access_points) -> int:
    """Mark conflicting same-SSID security as an indicator, never as proof of an evil twin."""
    access_points = list(access_points)
    by_name: dict[str, list[AccessPoint]] = {}
    for ap in access_points:
        if ap.name and ap.name != "<hidden>":
            by_name.setdefault(ap.name.casefold(), []).append(ap)
    count = 0
    for same_name in by_name.values():
        security = {ap.security for ap in same_name}
        if len(same_name) > 1 and len(security) > 1:
            detail = (f"SSID has conflicting security advertisements across {len(same_name)} BSSIDs; "
                      "verify against the authorized access-point inventory.")
            for ap in same_name:
                if detail not in ap.indicators:
                    ap.indicators.append(detail)
                    count += 1
    return count


_WIFI_VENDORS = MacVendorLookup()


def enrich_wifi_vendors(access_points: list[AccessPoint]) -> None:
    """Add locally cached IEEE manufacturer names; device BSSIDs are never sent."""
    for access_point in access_points:
        access_point.manufacturer = _WIFI_VENDORS.lookup(access_point.bssid)


def _client_value(client: WifiClient) -> dict:
    value = asdict(client)
    value["probes"] = sorted(client.probes)
    return value


def _ap_value(ap: AccessPoint, include_clients: bool = True) -> dict:
    value = {key: item for key, item in asdict(ap).items() if key != "clients"}
    if include_clients:
        value["clients"] = [_client_value(client) for client in ap.clients.values()]
    else:
        value["client_count"] = len(ap.clients)
    return value


def spreadsheet_safe_cell(value) -> str:
    text = str(value if value is not None else "")
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


def save_wifi_report(path: Path, aps: list[AccessPoint], unlinked: list[WifiClient]) -> None:
    suffix = path.suffix.casefold()
    if suffix == ".json":
        path.write_text(json.dumps({"format": 2,
                                    "access_points": [_ap_value(ap) for ap in aps],
                                    "unlinked_clients": [_client_value(item) for item in unlinked]},
                                   indent=2) + "\n", encoding="utf-8")
        return
    rows = [_ap_value(ap, include_clients=False) for ap in aps]
    columns = ("name", "bssid", "manufacturer", "channel", "signal_dbm", "security",
               "wps_advertised", "risk_level", "risk_reasons", "beacons", "data_packets",
               "client_count", "handshake_seen", "indicators")
    if suffix == ".csv":
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(columns)
            for row in rows:
                writer.writerow([spreadsheet_safe_cell(
                    "; ".join(row[column]) if isinstance(row.get(column), list) else row.get(column, ""))
                                 for column in columns])
        return
    if suffix in {".html", ".htm"}:
        headings = "".join(f"<th>{html.escape(column.replace('_', ' ').title())}</th>"
                           for column in columns)
        body = []
        for row in rows:
            cells = []
            for column in columns:
                value = row.get(column, "")
                if isinstance(value, list):
                    value = "; ".join(value)
                cells.append(f"<td>{html.escape(str(value))}</td>")
            body.append("<tr>" + "".join(cells) + "</tr>")
        document = ("<!doctype html><html><head><meta charset='utf-8'>"
                    "<title>Wi-Fi audit report</title><style>body{font-family:system-ui;margin:2rem;"
                    "color:#17324d}table{border-collapse:collapse;width:100%}th,td{border:1px solid #aac;"
                    "padding:.45rem;text-align:left}th{background:#102f49;color:white}tr:nth-child(even)"
                    "{background:#eef6fb}</style></head><body><h1>Wi-Fi audit report</h1><table><thead><tr>"
                    + headings + "</tr></thead><tbody>" + "".join(body) + "</tbody></table></body></html>")
        path.write_text(document, encoding="utf-8")
        return
    raise ValueError("Wi-Fi report must use .json, .csv, or .html")


def append_wifi_history(path: Path, aps: list[AccessPoint], timestamp: float | None = None) -> None:
    """Append one bounded summary snapshot for later configuration comparison."""
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: list[str] = []
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            if size > MAX_WIFI_HISTORY_BYTES:
                stream.seek(-MAX_WIFI_HISTORY_BYTES, os.SEEK_END)
                stream.readline()  # discard a possibly partial first record
            existing = stream.read(MAX_WIFI_HISTORY_BYTES).decode(
                "utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        pass
    record = {"format": 1, "timestamp": timestamp if timestamp is not None else time.time(),
              "access_points": [_ap_value(ap, include_clients=False)
                                for ap in aps[:MAX_WIFI_HISTORY_APS]]}
    lines = (existing + [json.dumps(record, separators=(",", ":"), ensure_ascii=False)])[-MAX_WIFI_HISTORY_ENTRIES:]
    while len(lines) > 1 and len(("\n".join(lines) + "\n").encode("utf-8")) > MAX_WIFI_HISTORY_BYTES:
        lines.pop(0)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(path)


def _security_strength(value: str) -> int | None:
    normalized = value.strip().upper()
    if normalized.startswith("OPEN"):
        return 0
    if normalized.startswith("WEP"):
        return 1
    if normalized == "WPA" or normalized.startswith("WPA ·"):
        return 2
    if normalized.startswith("WPA2"):
        return 3
    if normalized.startswith("WPA3"):
        return 4
    return None


def compare_wifi_history(path: Path) -> list[dict[str, str]]:
    """Compare the newest two valid snapshots without treating changes as proof of compromise."""
    try:
        if path.stat().st_size > MAX_WIFI_HISTORY_BYTES:
            raise ValueError("Wi-Fi history exceeds the 5 MiB safety limit")
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                value = json.loads(line)
                if isinstance(value, dict) and isinstance(value.get("access_points"), list):
                    records.append(value)
            except json.JSONDecodeError:
                continue
    except FileNotFoundError:
        return []
    if len(records) < 2:
        return []
    before = {str(ap.get("bssid", "")).upper(): ap for ap in records[-2]["access_points"]
              if isinstance(ap, dict) and ap.get("bssid")}
    after = {str(ap.get("bssid", "")).upper(): ap for ap in records[-1]["access_points"]
             if isinstance(ap, dict) and ap.get("bssid")}
    changes: list[dict[str, str]] = []
    for bssid in sorted(after.keys() - before.keys()):
        changes.append({"change": "New", "network": str(after[bssid].get("name", "<hidden>")),
                        "bssid": bssid, "detail": "Newly observed access point; verify against inventory."})
    for bssid in sorted(before.keys() - after.keys()):
        changes.append({"change": "Not observed", "network": str(before[bssid].get("name", "<hidden>")),
                        "bssid": bssid, "detail": "Not present in the latest observation; range and timing may differ."})
    for bssid in sorted(before.keys() & after.keys()):
        old_security = str(before[bssid].get("security", ""))
        new_security = str(after[bssid].get("security", ""))
        old_wps = bool(before[bssid].get("wps_advertised"))
        new_wps = bool(after[bssid].get("wps_advertised"))
        if old_security != new_security or old_wps != new_wps:
            detail = f"Security advertisement changed from {old_security or 'unknown'} to {new_security or 'unknown'}"
            old_strength, new_strength = _security_strength(old_security), _security_strength(new_security)
            if old_strength is not None and new_strength is not None and old_strength != new_strength:
                detail += " (weaker)" if new_strength < old_strength else " (stronger)"
            if old_wps != new_wps:
                detail += f"; WPS {'appeared' if new_wps else 'was no longer observed'}"
            changes.append({"change": "Security changed", "network": str(after[bssid].get("name", "<hidden>")),
                            "bssid": bssid, "detail": detail + "; confirm on the authorized access point."})
    return changes
