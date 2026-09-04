from __future__ import annotations

import csv
import html
import ipaddress
import json
import math
import os
import sqlite3
import statistics
import struct
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from .packet_tools import PacketRecord


MAX_MONITOR_RECORDS = 100_000
MAX_RULES = 256
MAX_REPORT_ITEMS = 10_000


@dataclass(slots=True)
class TimeBucket:
    started: int
    packets: int = 0
    bytes: int = 0
    protocols: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class Flow:
    endpoint_a: str
    port_a: int | None
    endpoint_b: str
    port_b: int | None
    protocol: str
    first_seen: float
    last_seen: float
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    resets: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    zero_windows: int = 0
    syns: int = 0
    syn_acks: int = 0
    handshake_ms: float | None = None
    destinations: set[str] = field(default_factory=set, repr=False)
    packet_times: list[float] = field(default_factory=list, repr=False)
    _next_sequence: dict[str, int] = field(default_factory=dict, repr=False)
    _syn_time: float | None = field(default=None, repr=False)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def packets(self) -> int:
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def bytes(self) -> int:
        return self.bytes_a_to_b + self.bytes_b_to_a


@dataclass(slots=True)
class DeviceActivity:
    address: str
    first_seen: float
    last_seen: float
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    peers: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    protocols: Counter = field(default_factory=Counter)
    dns_names: set[str] = field(default_factory=set)
    external_peers: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class DnsEvent:
    timestamp: float
    device: str
    server: str
    name: str
    response: bool
    rcode: int


@dataclass(frozen=True, slots=True)
class Finding:
    timestamp: float
    severity: str
    category: str
    subject: str
    explanation: str


@dataclass(frozen=True, slots=True)
class AlertRule:
    name: str
    kind: str
    threshold: float | str = 0
    device: str = ""
    enabled: bool = True

    @classmethod
    def from_dict(cls, value: dict) -> "AlertRule":
        if not isinstance(value, dict):
            raise ValueError("alert rule must be an object")
        name = value.get("name", "")
        kind = value.get("kind", "")
        threshold = value.get("threshold", 0)
        device = value.get("device", "")
        enabled = value.get("enabled", True)
        if (not isinstance(name, str) or not name or len(name) > 128 or
                kind not in {"new_device", "traffic_bytes", "failed_connections",
                             "destination", "port", "dns_name"} or
                not isinstance(device, str) or len(device) > 64 or
                not isinstance(enabled, bool) or
                not isinstance(threshold, (str, int, float)) or isinstance(threshold, bool)):
            raise ValueError("alert rule is invalid")
        if device:
            device = str(ipaddress.ip_address(device))
        if kind in {"traffic_bytes", "failed_connections", "port"}:
            try:
                number = float(threshold)
            except (TypeError, ValueError) as error:
                raise ValueError("alert threshold must be numeric") from error
            if not math.isfinite(number) or number < 0 or (kind == "port" and not 1 <= number <= 65_535):
                raise ValueError("alert threshold is outside its allowed range")
            threshold = int(number) if number.is_integer() else number
        elif kind == "destination":
            threshold = str(ipaddress.ip_address(str(threshold)))
        elif kind == "dns_name":
            threshold = str(threshold).strip().casefold()
            if not threshold or len(threshold) > 253:
                raise ValueError("DNS alert text is invalid")
        return cls(name, kind, threshold, device, enabled)


@dataclass(slots=True)
class Analysis:
    started: float
    ended: float
    packet_count: int
    byte_count: int
    buckets: list[TimeBucket]
    flows: list[Flow]
    devices: list[DeviceActivity]
    dns: list[DnsEvent]
    findings: list[Finding]
    protocols: dict[str, int]
    services: dict[int, int]

    @property
    def duration(self) -> float:
        return max(0.0, self.ended - self.started)


def _endpoint_key(address: str, port: int | None) -> tuple[int, bytes, int]:
    try:
        ip = ipaddress.ip_address(address)
        return ip.version, ip.packed, port or 0
    except ValueError:
        return 99, address.encode("utf-8", "replace"), port or 0


def _packet_metadata(record: PacketRecord) -> dict:
    frame = record.preview
    result = {"flags": 0, "sequence": None, "ack": None, "window": None,
              "payload": b"", "fragment": False}
    if len(frame) < 14:
        return result
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    for _ in range(2):
        if ether_type not in {0x8100, 0x88A8} or len(frame) < offset + 4:
            break
        ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    protocol = -1
    if ether_type == 0x0800 and len(frame) >= offset + 20:
        ihl = (frame[offset] & 15) * 4
        if ihl < 20 or len(frame) < offset + ihl:
            return result
        fragment = struct.unpack("!H", frame[offset + 6:offset + 8])[0]
        result["fragment"] = bool(fragment & 0x1FFF)
        protocol = frame[offset + 9]
        offset += ihl
    elif ether_type == 0x86DD and len(frame) >= offset + 40:
        protocol = frame[offset + 6]
        offset += 40
        for _ in range(8):
            if protocol in {0, 43, 60} and len(frame) >= offset + 2:
                protocol, units = frame[offset], frame[offset + 1]
                offset += (units + 1) * 8
            elif protocol == 44 and len(frame) >= offset + 8:
                protocol = frame[offset]
                fragment_field = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
                result["fragment"] = bool(fragment_field >> 3)
                offset += 8
            elif protocol == 51 and len(frame) >= offset + 2:
                protocol, units = frame[offset], frame[offset + 1]
                offset += (units + 2) * 4
            else:
                break
    if result["fragment"] and protocol in {6, 17}:
        return result
    if protocol == 6 and len(frame) >= offset + 20:
        sequence, ack = struct.unpack("!II", frame[offset + 4:offset + 12])
        header_length = (frame[offset + 12] >> 4) * 4
        if header_length < 20 or len(frame) < offset + header_length:
            return result
        result.update(flags=frame[offset + 13], sequence=sequence, ack=ack,
                      window=struct.unpack("!H", frame[offset + 14:offset + 16])[0],
                      payload=frame[offset + header_length:])
    elif protocol == 17 and len(frame) >= offset + 8:
        result["payload"] = frame[offset + 8:]
    return result


def _dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 8:
        raise ValueError("DNS compression loop")
    labels: list[str] = []
    end = offset
    jumped = False
    while offset < len(data):
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, _ = _dns_name(data, pointer, depth + 1)
            labels.append(suffix)
            end = offset + 2 if not jumped else end
            jumped = True
            break
        offset += 1
        if length == 0:
            end = offset if not jumped else end
            break
        if length > 63 or offset + length > len(data):
            raise ValueError("invalid DNS label")
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(label for label in labels if label)[:253], end


def _parse_dns(record: PacketRecord, payload: bytes) -> DnsEvent | None:
    if len(payload) < 12:
        return None
    _identifier, flags, questions, _answers, _authority, _additional = struct.unpack(
        "!HHHHHH", payload[:12])
    if questions < 1:
        return None
    try:
        name, _ = _dns_name(payload, 12)
    except (UnicodeError, ValueError):
        return None
    if not name:
        return None
    response = bool(flags & 0x8000)
    return DnsEvent(record.timestamp,
                    record.destination if response else record.source,
                    record.source if response else record.destination,
                    name.casefold(), response, flags & 0xF)


def _tls_server_name(payload: bytes) -> str:
    try:
        if len(payload) < 9 or payload[0] != 22 or payload[5] != 1:
            return ""
        offset = 9 + 2 + 32
        session_length = payload[offset]
        offset += 1 + session_length
        cipher_length = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2 + cipher_length
        compression_length = payload[offset]
        offset += 1 + compression_length
        extensions_length = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        end = min(len(payload), offset + extensions_length)
        while offset + 4 <= end:
            kind, length = struct.unpack("!HH", payload[offset:offset + 4])
            value = payload[offset + 4:offset + 4 + length]
            if kind == 0 and len(value) >= 5:
                name_length = struct.unpack("!H", value[3:5])[0]
                return value[5:5 + name_length].decode("ascii", "replace")[:253]
            offset += 4 + length
    except (IndexError, struct.error, UnicodeError):
        pass
    return ""


def _application_hint(record: PacketRecord, payload: bytes) -> str:
    if not payload:
        return ""
    if record.protocol == "TCP" and ({record.source_port, record.destination_port} & {80, 8000, 8080}):
        line = payload.split(b"\r\n", 1)[0][:256]
        if line.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"HTTP/")):
            return "HTTP " + line.decode("ascii", "replace")
    if record.protocol == "TCP" and 443 in {record.source_port, record.destination_port}:
        name = _tls_server_name(payload)
        return f"TLS server name {name}" if name else "TLS"
    if record.protocol == "UDP" and 123 in {record.source_port, record.destination_port}:
        return "NTP"
    if record.protocol == "UDP" and 1900 in {record.source_port, record.destination_port}:
        return "SSDP"
    if record.protocol == "UDP" and {record.source_port, record.destination_port} & {67, 68}:
        return "DHCP"
    return ""


def _arp_owner(record: PacketRecord) -> tuple[str, str] | None:
    frame = record.preview
    if len(frame) < 42:
        return None
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    for _ in range(2):
        if ether_type not in {0x8100, 0x88A8} or len(frame) < offset + 4:
            break
        ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    if (ether_type != 0x0806 or len(frame) < offset + 28 or frame[offset + 4] != 6 or
            frame[offset + 5] != 4):
        return None
    mac = ":".join(f"{byte:02X}" for byte in frame[offset + 8:offset + 14])
    address = str(ipaddress.ip_address(frame[offset + 14:offset + 18]))
    return address, mac


class MonitorAnalyzer:
    def __init__(self, known_devices: Iterable[str] = (), rules: Iterable[AlertRule] = (),
                 baseline_bytes: dict[str, float] | None = None):
        self.known_devices = {str(ipaddress.ip_address(item)) for item in known_devices}
        self.rules = list(rules)[:MAX_RULES]
        self.baseline_bytes = baseline_bytes or {}

    def analyze(self, records: Iterable[PacketRecord]) -> Analysis:
        records = list(records)[:MAX_MONITOR_RECORDS]
        if not records:
            now = time.time()
            return Analysis(now, now, 0, 0, [], [], [], [], [], {}, {})
        buckets: dict[int, TimeBucket] = {}
        flows: dict[tuple, Flow] = {}
        devices: dict[str, DeviceActivity] = {}
        dns_events: list[DnsEvent] = []
        protocols: Counter = Counter()
        services: Counter = Counter()
        arp_owners: dict[str, set[str]] = defaultdict(set)
        for record in records:
            protocols[record.protocol] += 1
            owner = _arp_owner(record)
            if owner:
                arp_owners[owner[0]].add(owner[1])
            bucket_start = int(record.timestamp // 60 * 60)
            bucket = buckets.setdefault(bucket_start, TimeBucket(bucket_start))
            bucket.packets += 1
            bucket.bytes += max(0, record.length)
            bucket.protocols[record.protocol] = bucket.protocols.get(record.protocol, 0) + 1
            for port in (record.source_port, record.destination_port):
                if port:
                    services[port] += 1
            left = (record.source, record.source_port)
            right = (record.destination, record.destination_port)
            if _endpoint_key(*right) < _endpoint_key(*left):
                left, right = right, left
                forward = False
            else:
                forward = True
            key = (*left, *right, record.protocol)
            flow = flows.setdefault(key, Flow(*left, *right, record.protocol,
                                              record.timestamp, record.timestamp))
            flow.last_seen = max(flow.last_seen, record.timestamp)
            flow.first_seen = min(flow.first_seen, record.timestamp)
            flow.packet_times.append(record.timestamp)
            if forward:
                flow.packets_a_to_b += 1
                flow.bytes_a_to_b += record.length
                direction = "a"
            else:
                flow.packets_b_to_a += 1
                flow.bytes_b_to_a += record.length
                direction = "b"
            metadata = _packet_metadata(record)
            flags = metadata["flags"]
            if flags & 0x04:
                flow.resets += 1
            if flags & 0x02:
                flow.syn_acks += int(bool(flags & 0x10))
                flow.syns += int(not bool(flags & 0x10))
                if flags & 0x10 and flow._syn_time is not None and flow.handshake_ms is None:
                    flow.handshake_ms = max(0.0, (record.timestamp - flow._syn_time) * 1_000)
                elif not flags & 0x10 and flow._syn_time is None:
                    flow._syn_time = record.timestamp
            if metadata["window"] == 0 and flags & 0x10:
                flow.zero_windows += 1
            sequence = metadata["sequence"]
            if sequence is not None:
                expected = flow._next_sequence.get(direction)
                payload_length = len(metadata["payload"])
                advance = payload_length + int(bool(flags & 0x03))
                if expected is not None and sequence < expected and advance:
                    flow.retransmissions += 1
                elif expected is not None and sequence > expected:
                    flow.out_of_order += 1
                flow._next_sequence[direction] = max(expected or sequence,
                                                     sequence + advance)
            payload = metadata["payload"]
            dns_event = None
            if record.protocol in {"DNS", "mDNS"} or 53 in {record.source_port, record.destination_port}:
                dns_event = _parse_dns(record, payload)
                if dns_event:
                    dns_events.append(dns_event)
            hint = _application_hint(record, payload)
            if hint and hint not in record.info:
                protocols[hint.split(" ", 1)[0]] += 1
            for address, sent, peer in ((record.source, True, record.destination),
                                        (record.destination, False, record.source)):
                try:
                    ipaddress.ip_address(address)
                except ValueError:
                    continue
                device = devices.setdefault(address, DeviceActivity(
                    address, record.timestamp, record.timestamp))
                device.first_seen = min(device.first_seen, record.timestamp)
                device.last_seen = max(device.last_seen, record.timestamp)
                device.peers.add(peer)
                device.protocols[record.protocol] += 1
                if sent:
                    device.packets_sent += 1
                    device.bytes_sent += record.length
                    if record.destination_port:
                        device.ports.add(record.destination_port)
                else:
                    device.packets_received += 1
                    device.bytes_received += record.length
                try:
                    if ipaddress.ip_address(peer).is_global:
                        device.external_peers.add(peer)
                except ValueError:
                    pass
            if dns_event and dns_event.device in devices:
                devices[dns_event.device].dns_names.add(dns_event.name)
        findings = self._findings(list(flows.values()), list(devices.values()),
                                  dns_events, arp_owners)
        return Analysis(min(record.timestamp for record in records),
                        max(record.timestamp for record in records),
                        len(records), sum(max(0, record.length) for record in records),
                        sorted(buckets.values(), key=lambda item: item.started),
                        sorted(flows.values(), key=lambda item: item.bytes, reverse=True),
                        sorted(devices.values(), key=lambda item: item.bytes_sent + item.bytes_received,
                               reverse=True), dns_events, findings, dict(protocols), dict(services))

    def _findings(self, flows: list[Flow], devices: list[DeviceActivity],
                  dns: list[DnsEvent], arp_owners: dict[str, set[str]]) -> list[Finding]:
        findings: list[Finding] = []
        now = max((device.last_seen for device in devices), default=time.time())
        dns_failures = Counter(event.device for event in dns if event.response and event.rcode)
        for address, owners in arp_owners.items():
            if len(owners) > 1:
                findings.append(Finding(now, "alert", "ARP ownership changed", address,
                                        f"Observed {len(owners)} MAC addresses claiming this IPv4 address: "
                                        + ", ".join(sorted(owners))))
        for device in devices:
            total = device.bytes_sent + device.bytes_received
            if self.known_devices and device.address not in self.known_devices:
                findings.append(Finding(device.first_seen, "notice", "New device",
                                        device.address, "This address was not in the saved-device baseline."))
            if len(device.external_peers) >= 20:
                findings.append(Finding(now, "warning", "Connection fan-out", device.address,
                                        f"Contacted {len(device.external_peers)} external addresses during this session."))
            baseline = self.baseline_bytes.get(device.address, 0)
            if baseline and total > max(baseline * 3, baseline + 50_000_000):
                findings.append(Finding(now, "warning", "Traffic increase", device.address,
                                        f"Used {total:,} bytes versus a recent baseline of {baseline:,.0f}."))
            if dns_failures[device.address] >= 5:
                findings.append(Finding(now, "notice", "DNS failures", device.address,
                                        f"Received {dns_failures[device.address]} failed DNS responses."))
        for flow in flows:
            subject = f"{flow.endpoint_a} ↔ {flow.endpoint_b}"
            if flow.resets >= 5:
                findings.append(Finding(flow.last_seen, "warning", "TCP resets", subject,
                                        f"Observed {flow.resets} reset packets in this conversation."))
            if flow.retransmissions >= 10:
                findings.append(Finding(flow.last_seen, "warning", "Retransmissions", subject,
                                        f"Observed approximately {flow.retransmissions} repeated TCP sequences."))
            if flow.syns >= 5 and flow.syn_acks == 0:
                findings.append(Finding(flow.last_seen, "warning", "Failed connections", subject,
                                        f"Observed {flow.syns} connection attempts without a SYN/ACK."))
            if len(flow.packet_times) >= 6:
                intervals = [b - a for a, b in zip(flow.packet_times, flow.packet_times[1:]) if b > a]
                if len(intervals) >= 5 and statistics.mean(intervals) >= 5:
                    spread = statistics.pstdev(intervals) / statistics.mean(intervals)
                    if spread < .08:
                        findings.append(Finding(flow.last_seen, "notice", "Regular connection pattern",
                                                subject, "Packets arrived at unusually regular intervals; review if this is expected."))
        findings.extend(self._rule_findings(devices, flows, dns, now))
        return sorted(findings, key=lambda item: item.timestamp, reverse=True)[:1_000]

    def _rule_findings(self, devices: list[DeviceActivity], flows: list[Flow],
                       dns: list[DnsEvent], now: float) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            selected = [device for device in devices if not rule.device or device.address == rule.device]
            matches: list[str] = []
            if rule.kind == "new_device":
                matches = [d.address for d in selected if d.address not in self.known_devices]
            elif rule.kind == "traffic_bytes":
                matches = [d.address for d in selected if d.bytes_sent + d.bytes_received > float(rule.threshold)]
            elif rule.kind == "failed_connections":
                count = sum(f.syns for f in flows if f.syn_acks == 0)
                matches = [f"{count} failed attempts"] if count > float(rule.threshold) else []
            elif rule.kind == "destination":
                matches = [d.address for d in selected if str(rule.threshold) in d.peers]
            elif rule.kind == "port":
                matches = [d.address for d in selected if int(float(rule.threshold)) in d.ports]
            elif rule.kind == "dns_name":
                term = str(rule.threshold).casefold()
                matches = sorted({event.device for event in dns if term in event.name})
            if matches:
                findings.append(Finding(now, "alert", "Rule: " + rule.name,
                                        ", ".join(matches[:10]),
                                        f"The configured {rule.kind.replace('_', ' ')} condition matched."))
        return findings


class MonitorStore:
    def __init__(self, path: Path):
        self.path = path.expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY, started REAL NOT NULL, ended REAL NOT NULL,
                packets INTEGER NOT NULL, bytes INTEGER NOT NULL, capture TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS buckets (
                session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                started INTEGER NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL,
                protocols TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS devices (
                session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                address TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                sent INTEGER NOT NULL, received INTEGER NOT NULL, peers TEXT NOT NULL,
                protocols TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS flows (
                session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                endpoint_a TEXT NOT NULL, port_a INTEGER, endpoint_b TEXT NOT NULL, port_b INTEGER,
                protocol TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                packets INTEGER NOT NULL, bytes INTEGER NOT NULL, diagnostics TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS dns (
                session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                timestamp REAL NOT NULL, device TEXT NOT NULL, server TEXT NOT NULL,
                name TEXT NOT NULL, response INTEGER NOT NULL, rcode INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS findings (
                session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                timestamp REAL NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL,
                subject TEXT NOT NULL, explanation TEXT NOT NULL);
        """)

    def save(self, analysis: Analysis, capture: Path | None = None) -> int:
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO sessions(started,ended,packets,bytes,capture) VALUES(?,?,?,?,?)",
                (analysis.started, analysis.ended, analysis.packet_count, analysis.byte_count,
                 str(capture or "")))
            session_id = int(cursor.lastrowid)
            self.connection.executemany(
                "INSERT INTO buckets VALUES(?,?,?,?,?)",
                [(session_id, b.started, b.packets, b.bytes, json.dumps(b.protocols))
                 for b in analysis.buckets])
            self.connection.executemany(
                "INSERT INTO devices VALUES(?,?,?,?,?,?,?,?)",
                [(session_id, d.address, d.first_seen, d.last_seen, d.bytes_sent,
                  d.bytes_received, json.dumps(sorted(d.peers)), json.dumps(dict(d.protocols)))
                 for d in analysis.devices])
            self.connection.executemany(
                "INSERT INTO flows VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                [(session_id, f.endpoint_a, f.port_a, f.endpoint_b, f.port_b, f.protocol,
                  f.first_seen, f.last_seen, f.packets, f.bytes,
                  json.dumps({"resets": f.resets, "retransmissions": f.retransmissions,
                              "out_of_order": f.out_of_order, "zero_windows": f.zero_windows,
                              "syns": f.syns, "syn_acks": f.syn_acks,
                              "handshake_ms": f.handshake_ms})) for f in analysis.flows])
            self.connection.executemany(
                "INSERT INTO dns VALUES(?,?,?,?,?,?,?)",
                [(session_id, d.timestamp, d.device, d.server, d.name, int(d.response), d.rcode)
                 for d in analysis.dns[:MAX_REPORT_ITEMS]])
            self.connection.executemany(
                "INSERT INTO findings VALUES(?,?,?,?,?,?)",
                [(session_id, f.timestamp, f.severity, f.category, f.subject, f.explanation)
                 for f in analysis.findings])
        return session_id

    def recent_sessions(self, limit: int = 100) -> list[tuple]:
        return self.connection.execute(
            "SELECT id,started,ended,packets,bytes,capture FROM sessions ORDER BY started DESC LIMIT ?",
            (max(1, min(limit, 1_000)),)).fetchall()

    def baselines(self, days: int = 7) -> dict[str, float]:
        cutoff = time.time() - max(1, min(days, 90)) * 86_400
        rows = self.connection.execute(
            "SELECT address, sent + received FROM devices WHERE first_seen >= ?", (cutoff,)).fetchall()
        values: dict[str, list[int]] = defaultdict(list)
        for address, total in rows:
            values[address].append(total)
        return {address: statistics.median(totals) for address, totals in values.items()}

    def prune(self, days: int = 7) -> int:
        cutoff = time.time() - max(1, min(days, 365)) * 86_400
        with self.connection:
            cursor = self.connection.execute("DELETE FROM sessions WHERE ended < ?", (cutoff,))
        return cursor.rowcount

    def close(self) -> None:
        self.connection.close()


def save_rules(path: Path, rules: Iterable[AlertRule]) -> None:
    values = [asdict(rule) for rule in list(rules)[:MAX_RULES]]
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"format": 1, "rules": values}, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_rules(path: Path) -> list[AlertRule]:
    if not path.exists():
        return []
    if path.stat().st_size > 1_048_576:
        raise ValueError("alert rules file is too large")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("format") != 1 or not isinstance(value.get("rules"), list):
        raise ValueError("unsupported alert rules file")
    if len(value["rules"]) > MAX_RULES:
        raise ValueError("too many alert rules")
    return [AlertRule.from_dict(rule) for rule in value["rules"]]


def enforce_capture_retention(directory: Path, maximum_bytes: int = 250 * 1024 * 1024,
                              days: int = 7, protected: Iterable[Path] = ()) -> list[Path]:
    directory = directory.expanduser().resolve()
    if not directory.is_dir():
        return []
    maximum_bytes = max(10 * 1024 * 1024, min(maximum_bytes, 10 * 1024 * 1024 * 1024))
    cutoff = time.time() - max(1, min(days, 365)) * 86_400
    protected_paths = {path.expanduser().resolve() for path in protected}
    candidates = []
    for path in directory.glob("watch-*.pcap"):
        if path.is_symlink():
            continue
        resolved = path.resolve()
        if resolved.parent != directory or resolved in protected_paths or not resolved.is_file():
            continue
        metadata = resolved.stat()
        candidates.append((metadata.st_mtime, metadata.st_size, resolved))
    total = sum(size for _modified, size, _path in candidates)
    removed: list[Path] = []
    for modified, size, path in sorted(candidates):
        if modified >= cutoff and total <= maximum_bytes:
            continue
        path.unlink(missing_ok=True)
        total -= size
        removed.append(path)
    return removed


def export_analysis(path: Path, analysis: Analysis) -> None:
    suffix = path.suffix.lower()
    if suffix == ".json":
        value = {
            "format": 1,
            "summary": {"started": analysis.started, "ended": analysis.ended,
                        "packets": analysis.packet_count, "bytes": analysis.byte_count},
            "protocols": analysis.protocols,
            "flows": [{"endpoint_a": flow.endpoint_a, "port_a": flow.port_a,
                       "endpoint_b": flow.endpoint_b, "port_b": flow.port_b,
                       "protocol": flow.protocol, "first_seen": flow.first_seen,
                       "last_seen": flow.last_seen, "packets": flow.packets,
                       "bytes": flow.bytes, "resets": flow.resets,
                       "retransmissions": flow.retransmissions,
                       "out_of_order": flow.out_of_order,
                       "zero_windows": flow.zero_windows,
                       "handshake_ms": flow.handshake_ms}
                      for flow in analysis.flows[:MAX_REPORT_ITEMS]],
            "findings": [asdict(item) for item in analysis.findings],
            "dns": [asdict(item) for item in analysis.dns[:MAX_REPORT_ITEMS]],
        }
        path.write_text(json.dumps(value, indent=2, default=list) + "\n", encoding="utf-8")
    elif suffix == ".csv":
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["endpoint_a", "port_a", "endpoint_b", "port_b", "protocol",
                             "first_seen", "last_seen", "packets", "bytes", "resets",
                             "retransmissions", "out_of_order", "zero_windows"])
            for flow in analysis.flows[:MAX_REPORT_ITEMS]:
                writer.writerow([flow.endpoint_a, flow.port_a or "", flow.endpoint_b,
                                 flow.port_b or "", flow.protocol, flow.first_seen, flow.last_seen,
                                 flow.packets, flow.bytes, flow.resets, flow.retransmissions,
                                 flow.out_of_order, flow.zero_windows])
    elif suffix in {".html", ".htm"}:
        findings = "".join(f"<li><b>{html.escape(item.category)}</b> — "
                           f"{html.escape(item.subject)}: {html.escape(item.explanation)}</li>"
                           for item in analysis.findings)
        rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in
                       (flow.endpoint_a, flow.port_a or "", flow.endpoint_b, flow.port_b or "",
                        flow.protocol, flow.packets, flow.bytes, f"{flow.duration:.1f}s")) + "</tr>"
                       for flow in analysis.flows[:MAX_REPORT_ITEMS])
        path.write_text("<!doctype html><meta charset=utf-8><title>Network Watch report</title>"
                        "<h1>Network Watch report</h1>"
                        f"<p>{analysis.packet_count:,} packets · {analysis.byte_count:,} bytes · "
                        f"{analysis.duration:.1f} seconds</p><h2>Findings</h2><ul>{findings}</ul>"
                        "<h2>Conversations</h2><table><thead><tr><th>Endpoint A</th><th>Port A</th>"
                        "<th>Endpoint B</th><th>Port B</th><th>Protocol</th><th>Packets</th>"
                        f"<th>Bytes</th><th>Duration</th></tr></thead><tbody>{rows}</tbody></table>",
                        encoding="utf-8")
    else:
        raise ValueError("report filename must end in .json, .csv, or .html")
