from __future__ import annotations

import json
import os
import re
import shutil
import stat
import struct
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path


MAX_WIFI_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_WIFI_PACKETS = 100_000
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


def save_wifi_report(path: Path, aps: list[AccessPoint], unlinked: list[WifiClient]) -> None:
    def client_value(client: WifiClient) -> dict:
        value = asdict(client)
        value["probes"] = sorted(client.probes)
        return value

    values = []
    for ap in aps:
        value = {key: item for key, item in asdict(ap).items() if key != "clients"}
        value["clients"] = [client_value(client) for client in ap.clients.values()]
        values.append(value)
    path.write_text(json.dumps({"format": 1, "access_points": values,
                                "unlinked_clients": [client_value(item) for item in unlinked]},
                               indent=2) + "\n", encoding="utf-8")
