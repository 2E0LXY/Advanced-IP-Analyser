"""Bounded infrastructure monitoring and diagnostic operations.

The functions in this module are deliberately independent from Tk so they can be
tested, used by the CLI, and reused by a future Android/desktop peer API.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import statistics
import subprocess
import time
from typing import Iterable
from urllib.request import Request, urlopen

from .scan_history import latest_evidence, latest_network_watch_evidence


MAX_POLICY_BYTES = 256 * 1024
MAX_REPORT_ROWS = 5_000
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
STANDARD_SNMP_OIDS = {
    "System description": "1.3.6.1.2.1.1.1.0",
    "System uptime": "1.3.6.1.2.1.1.3.0",
    "System name": "1.3.6.1.2.1.1.5.0",
    "Interface count": "1.3.6.1.2.1.2.1.0",
}
LLDP_REMOTE_NAME_OID = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REMOTE_PORT_OID = "1.0.8802.1.1.2.1.4.1.1.7"
CDP_DEVICE_ID_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_DEVICE_PORT_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"


@dataclass(frozen=True)
class NeighborEntry:
    address: str
    mac: str
    state: str = ""
    interface: str = ""


@dataclass(frozen=True)
class ConflictFinding:
    severity: str
    category: str
    subject: str
    explanation: str


@dataclass(frozen=True)
class ServiceObservation:
    source: str
    name: str
    address: str
    service: str = ""
    detail: str = ""


@dataclass(frozen=True)
class SnmpValue:
    oid: str
    value: str
    value_type: str


@dataclass(frozen=True)
class QualityResult:
    target: str
    port: int
    attempted: int
    successful: int
    loss_percent: float
    minimum_ms: float | None
    average_ms: float | None
    p95_ms: float | None
    jitter_ms: float | None
    samples_ms: tuple[float, ...] = ()


@dataclass
class MonitorPolicy:
    enabled: bool = False
    interval_minutes: int = 15
    quiet_start: str = "22:00"
    quiet_end: str = "07:00"
    notify_new_devices: bool = True
    notify_missing_devices: bool = True
    notify_port_changes: bool = True
    webhook_url: str = ""
    report_directory: str = ""

    def validate(self) -> None:
        if not 1 <= self.interval_minutes <= 10_080:
            raise ValueError("monitor interval must be from 1 minute to 7 days")
        for value in (self.quiet_start, self.quiet_end):
            if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
                raise ValueError("quiet hours must use 24-hour HH:MM")
        if self.webhook_url and not self.webhook_url.startswith("https://"):
            raise ValueError("webhook URL must use HTTPS")
        if len(self.webhook_url) > 2_048 or len(self.report_directory) > 4_096:
            raise ValueError("monitor policy value is too long")


def default_policy_path() -> Path:
    return Path.home() / ".config" / "advanced-ip-analyser" / "monitor-policy.json"


def load_monitor_policy(path: Path | None = None) -> MonitorPolicy:
    path = path or default_policy_path()
    if not path.exists():
        return MonitorPolicy()
    if path.stat().st_size > MAX_POLICY_BYTES:
        raise ValueError("monitor policy is too large")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("monitor policy must be an object")
    allowed = {field.name for field in MonitorPolicy.__dataclass_fields__.values()}
    policy = MonitorPolicy(**{key: item for key, item in value.items() if key in allowed})
    policy.validate()
    return policy


def save_monitor_policy(policy: MonitorPolicy, path: Path | None = None) -> Path:
    policy.validate()
    path = path or default_policy_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(asdict(policy), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.name == "posix":
        temporary.chmod(0o600)
    temporary.replace(path)
    return path


def policy_in_quiet_hours(policy: MonitorPolicy, now: datetime | None = None) -> bool:
    now = now or datetime.now().astimezone()
    current = now.hour * 60 + now.minute
    start_hour, start_minute = (int(part) for part in policy.quiet_start.split(":"))
    end_hour, end_minute = (int(part) for part in policy.quiet_end.split(":"))
    start, end = start_hour * 60 + start_minute, end_hour * 60 + end_minute
    if start == end:
        return False
    return start <= current < end if start < end else current >= start or current < end


def selected_policy_changes(policy: MonitorPolicy, summary: dict[str, object]) -> dict[str, object]:
    selected: dict[str, object] = {}
    if policy.notify_new_devices and summary.get("new"):
        selected["new"] = summary["new"]
    if policy.notify_missing_devices and summary.get("missing"):
        selected["missing"] = summary["missing"]
    if policy.notify_port_changes:
        changed = [item for item in summary.get("changed", [])
                   if isinstance(item, dict) and set(item.get("fields", [])) & {"ports", "services"}]
        if changed:
            selected["port_changes"] = changed
    return selected


def dispatch_policy_webhook(policy: MonitorPolicy, changes: dict[str, object], timeout: float = 8.0) -> None:
    """Send a user-configured change notification without exposing stored credentials."""
    policy.validate()
    if not policy.webhook_url:
        return
    body = json.dumps({"source": "Advanced IP Analyser", "schema": 1,
                       "generated_at": datetime.now(UTC).isoformat(), "changes": changes},
                      separators=(",", ":")).encode()
    if len(body) > 2 * 1024 * 1024:
        raise ValueError("change notification exceeds the webhook safety limit")
    request = Request(policy.webhook_url, data=body, method="POST",
                      headers={"Content-Type": "application/json", "User-Agent": "Advanced-IP-Analyser/3.0"})
    with urlopen(request, timeout=max(1.0, min(timeout, 30.0))) as response:
        if not 200 <= response.status < 300:
            raise OSError(f"webhook returned HTTP {response.status}")


def scan_change_summary(path: Path | None = None) -> dict[str, object]:
    evidence = latest_evidence(path)
    changes = evidence.get("changes", {}) if isinstance(evidence, dict) else {}
    return {
        "snapshots": evidence.get("snapshots", []) if isinstance(evidence, dict) else [],
        "new": list(changes.get("new", [])) if isinstance(changes, dict) else [],
        "missing": list(changes.get("missing", [])) if isinstance(changes, dict) else [],
        "changed": list(changes.get("changed", [])) if isinstance(changes, dict) else [],
        "capacity": evidence.get("capacity", {}) if isinstance(evidence, dict) else {},
    }


def _normalise_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(compact) != 12:
        return ""
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2)).upper()


def parse_neighbor_table(text: str) -> list[NeighborEntry]:
    """Parse Windows ``arp -a`` and Linux ``ip neigh`` output."""
    entries: list[NeighborEntry] = []
    interface = ""
    for raw in text.splitlines():
        line = raw.strip()
        match = re.match(r"Interface:\s+([^\s]+)", line, re.IGNORECASE)
        if match:
            interface = match.group(1)
            continue
        linux = re.match(r"([^\s]+)\s+dev\s+([^\s]+).*?lladdr\s+([^\s]+)(?:\s+(.+))?$", line)
        if linux:
            address, adapter, mac, state = linux.groups()
        else:
            windows = re.match(r"([^\s]+)\s+([0-9A-Fa-f:-]{11,20})\s+([^\s]+)", line)
            if not windows:
                continue
            address, mac, state = windows.groups()
            adapter = interface
        try:
            address = str(ipaddress.ip_address(address.split("%")[0]))
        except ValueError:
            continue
        normalised = _normalise_mac(mac)
        if normalised:
            entries.append(NeighborEntry(address, normalised, (state or "").strip(), adapter))
    return entries[:65_536]


def read_neighbor_table() -> list[NeighborEntry]:
    command = ["arp", "-a"] if os.name == "nt" else ["ip", "neigh", "show"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=12, check=False)
    return parse_neighbor_table(result.stdout)


def find_address_conflicts(entries: Iterable[NeighborEntry]) -> list[ConflictFinding]:
    by_address: dict[str, set[str]] = {}
    by_mac: dict[str, set[str]] = {}
    for entry in entries:
        by_address.setdefault(entry.address, set()).add(entry.mac)
        by_mac.setdefault(entry.mac, set()).add(entry.address)
    findings = [
        ConflictFinding("alert", "Duplicate IP", address,
                        "The neighbour cache associates this address with multiple MAC addresses: " +
                        ", ".join(sorted(macs)) + ". Verify DHCP reservations, static addresses and ARP stability.")
        for address, macs in by_address.items() if len(macs) > 1
    ]
    findings.extend(
        ConflictFinding("review", "Address movement", mac,
                        "One MAC appears at multiple addresses: " + ", ".join(sorted(addresses)) +
                        ". This can be normal DHCP churn, multi-addressing or stale cache data.")
        for mac, addresses in by_mac.items() if len(addresses) > 3
    )
    return findings[:2_000]


def _dns_query(name: str, query_type: int = 12) -> bytes:
    labels = [label.encode("idna") for label in name.rstrip(".").split(".") if label]
    question = b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"
    return b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question + query_type.to_bytes(2, "big") + b"\x00\x01"


def discover_local_services(address: str, timeout: float = 1.0) -> list[ServiceObservation]:
    """Collect bounded reverse-DNS, mDNS and SSDP naming evidence."""
    ip = ipaddress.ip_address(address.split("%")[0])
    observations: list[ServiceObservation] = []
    try:
        name, aliases, _addresses = socket.gethostbyaddr(str(ip))
        observations.append(ServiceObservation("Reverse DNS", name.rstrip("."), str(ip),
                                               detail="Aliases: " + ", ".join(aliases[:8]) if aliases else ""))
    except (OSError, socket.herror):
        pass
    if ip.version == 4 and ip.is_private:
        reversed_name = ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(max(0.1, min(timeout, 5.0)))
        try:
            sock.sendto(_dns_query(reversed_name), ("224.0.0.251", 5353))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and len(observations) < 64:
                try:
                    data, sender = sock.recvfrom(65_535)
                except socket.timeout:
                    break
                if sender[0] == str(ip):
                    printable = re.findall(rb"[ -~]{3,120}", data)
                    detail = " · ".join(item.decode(errors="replace") for item in printable[-4:])
                    observations.append(ServiceObservation("mDNS", detail or str(ip), str(ip), "5353/udp"))
        finally:
            sock.close()
    return observations


def discover_ssdp(timeout: float = 1.5) -> list[ServiceObservation]:
    request = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n").encode("ascii")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.2)
    observations: dict[tuple[str, str], ServiceObservation] = {}
    try:
        sock.sendto(request, ("239.255.255.250", 1900))
        deadline = time.monotonic() + max(0.2, min(timeout, 5.0))
        while time.monotonic() < deadline and len(observations) < 512:
            try:
                data, sender = sock.recvfrom(65_535)
            except socket.timeout:
                continue
            headers: dict[str, str] = {}
            for line in data.decode("iso-8859-1", errors="replace").splitlines()[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            label = headers.get("server") or headers.get("usn") or "SSDP device"
            service = headers.get("st", "ssdp:all")
            detail = headers.get("location", "")
            observations[(sender[0], service)] = ServiceObservation("SSDP", label, sender[0], service, detail)
    finally:
        sock.close()
    return list(observations.values())


def _ber_length(length: int) -> bytes:
    if length < 128:
        return bytes((length,))
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(raw),)) + raw


def _ber(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _ber_length(len(value)) + value


def _ber_integer(value: int) -> bytes:
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return _ber(0x02, raw)


def _encode_oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.strip(".").split(".")]
    if len(parts) < 2 or parts[0] > 2 or parts[1] > 39:
        raise ValueError("invalid SNMP OID")
    output = bytearray((parts[0] * 40 + parts[1],))
    for part in parts[2:]:
        if part < 0:
            raise ValueError("invalid SNMP OID")
        encoded = bytearray((part & 0x7F,))
        part >>= 7
        while part:
            encoded.insert(0, 0x80 | (part & 0x7F))
            part >>= 7
        output.extend(encoded)
    return bytes(output)


def build_snmp_request(community: str, oid: str, request_id: int, *, next_value: bool = False) -> bytes:
    if not community or len(community.encode()) > 128:
        raise ValueError("SNMP community must contain 1 to 128 bytes")
    varbind = _ber(0x30, _ber(0x06, _encode_oid(oid)) + _ber(0x05, b""))
    pdu = _ber(0xA1 if next_value else 0xA0,
               _ber_integer(request_id) + _ber_integer(0) + _ber_integer(0) + _ber(0x30, varbind))
    return _ber(0x30, _ber_integer(1) + _ber(0x04, community.encode()) + pdu)


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated BER value")
    tag, length = data[offset], data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if not count or count > 4 or offset + count > len(data):
            raise ValueError("invalid BER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("truncated BER value")
    return tag, data[offset:end], end


def _decode_oid(data: bytes) -> str:
    if not data:
        return ""
    first = min(2, data[0] // 40)
    parts = [first, data[0] - first * 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(part) for part in parts)


def parse_snmp_response(data: bytes) -> SnmpValue:
    _tag, message, _ = _read_tlv(data, 0)
    _version_tag, _version, cursor = _read_tlv(message, 0)
    _community_tag, _community, cursor = _read_tlv(message, cursor)
    _pdu_tag, pdu, _ = _read_tlv(message, cursor)
    _request_tag, _request, cursor = _read_tlv(pdu, 0)
    _error_tag, error, cursor = _read_tlv(pdu, cursor)
    _index_tag, _index, cursor = _read_tlv(pdu, cursor)
    if int.from_bytes(error, "big"):
        raise ValueError("SNMP agent returned an error")
    _list_tag, varbinds, _ = _read_tlv(pdu, cursor)
    _vb_tag, varbind, _ = _read_tlv(varbinds, 0)
    _oid_tag, oid_raw, cursor = _read_tlv(varbind, 0)
    value_tag, raw, _ = _read_tlv(varbind, cursor)
    if value_tag == 0x04:
        value = raw.decode("utf-8", errors="replace").strip("\x00")
        kind = "text"
    elif value_tag in {0x02, 0x41, 0x42, 0x43, 0x46}:
        value = str(int.from_bytes(raw, "big", signed=value_tag == 0x02))
        kind = {0x41: "counter", 0x42: "gauge", 0x43: "ticks", 0x46: "counter64"}.get(value_tag, "integer")
    elif value_tag == 0x40 and len(raw) == 4:
        value, kind = socket.inet_ntoa(raw), "address"
    elif value_tag in {0x80, 0x81, 0x82}:
        value, kind = "Unavailable", "exception"
    else:
        value, kind = raw.hex(), f"tag-{value_tag:02x}"
    return SnmpValue(_decode_oid(oid_raw), value, kind)


def snmp_get(host: str, community: str, oid: str, timeout: float = 1.5) -> SnmpValue:
    address = str(ipaddress.ip_address(host.split("%")[0]))
    request_id = int(time.time() * 1000) & 0x7FFFFFFF
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(max(0.1, min(timeout, 10.0)))
    try:
        sock.sendto(build_snmp_request(community, oid, request_id), (address, 161))
        response, _sender = sock.recvfrom(65_535)
    finally:
        sock.close()
    return parse_snmp_response(response)


def snmp_system_summary(host: str, community: str, timeout: float = 1.5) -> list[SnmpValue]:
    values: list[SnmpValue] = []
    for label, oid in STANDARD_SNMP_OIDS.items():
        try:
            value = snmp_get(host, community, oid, timeout)
            values.append(SnmpValue(value.oid, f"{label}: {value.value}", value.value_type))
        except (OSError, ValueError, TimeoutError) as error:
            values.append(SnmpValue(oid, f"{label}: unavailable ({type(error).__name__})", "error"))
    return values


def snmp_cli_walk(host: str, version: str, credentials: dict[str, str], oid: str,
                  timeout: float = 8.0) -> list[SnmpValue]:
    """Use an installed Net-SNMP client for v2c or authenticated SNMPv3 table walks."""
    executable = shutil.which("snmpwalk")
    if not executable:
        raise RuntimeError("snmpwalk is not installed; native scalar SNMPv2c queries remain available")
    address = str(ipaddress.ip_address(host.split("%")[0]))
    if version == "3":
        user = credentials.get("username", "")
        auth = credentials.get("auth_password", "")
        privacy = credentials.get("privacy_password", "")
        if not user or not auth:
            raise ValueError("SNMPv3 username and authentication password are required")
        command = [executable, "-v3", "-l", "authPriv" if privacy else "authNoPriv",
                   "-u", user, "-a", credentials.get("auth_protocol", "SHA"), "-A", auth]
        if privacy:
            command += ["-x", credentials.get("privacy_protocol", "AES"), "-X", privacy]
        command += [address, oid]
    else:
        community = credentials.get("community", "")
        if not community:
            raise ValueError("SNMP community is required")
        command = [executable, "-v2c", "-c", community, address, oid]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "SNMP walk failed").strip()[:1_000])
    values: list[SnmpValue] = []
    for line in result.stdout.splitlines()[:2_000]:
        match = re.match(r"([^=]+)=\s*([^:]+):\s*(.*)", line)
        if match:
            values.append(SnmpValue(match.group(1).strip(), match.group(3).strip(), match.group(2).strip()))
    return values


def topology_evidence(host: str, version: str, credentials: dict[str, str]) -> dict[str, list[SnmpValue]]:
    groups = {
        "LLDP remote names": LLDP_REMOTE_NAME_OID,
        "LLDP remote ports": LLDP_REMOTE_PORT_OID,
        "CDP device IDs": CDP_DEVICE_ID_OID,
        "CDP remote ports": CDP_DEVICE_PORT_OID,
    }
    result: dict[str, list[SnmpValue]] = {}
    for label, oid in groups.items():
        try:
            result[label] = snmp_cli_walk(host, version, credentials, oid)
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            result[label] = [SnmpValue(oid, f"Unavailable: {error}", "error")]
    return result


def tcp_quality(target: str, port: int, samples: int = 10, timeout: float = 1.0,
                interval: float = 0.1) -> QualityResult:
    address = str(ipaddress.ip_address(target.split("%")[0]))
    if not 1 <= port <= 65_535 or not 1 <= samples <= 200:
        raise ValueError("port or sample count is outside the allowed range")
    timings: list[float] = []
    for index in range(samples):
        started = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=max(0.05, min(timeout, 10.0))):
                timings.append((time.perf_counter() - started) * 1_000)
        except OSError:
            pass
        if interval and index + 1 < samples:
            time.sleep(max(0.0, min(interval, 5.0)))
    ordered = sorted(timings)
    average = statistics.fmean(timings) if timings else None
    p95 = ordered[min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1)] if ordered else None
    jitter = statistics.fmean(abs(b - a) for a, b in zip(timings, timings[1:])) if len(timings) > 1 else 0.0 if timings else None
    return QualityResult(address, port, samples, len(timings), round((samples - len(timings)) / samples * 100, 2),
                         round(min(timings), 2) if timings else None,
                         round(average, 2) if average is not None else None,
                         round(p95, 2) if p95 is not None else None,
                         round(jitter, 2) if jitter is not None else None,
                         tuple(round(value, 2) for value in timings))


def run_iperf3(server: str, seconds: int = 10, *, reverse: bool = False,
               udp: bool = False, bandwidth: str = "10M") -> dict[str, object]:
    executable = shutil.which("iperf3")
    if not executable:
        raise RuntimeError("iperf3 is not installed")
    address = str(ipaddress.ip_address(server.split("%")[0]))
    seconds = max(1, min(int(seconds), 120))
    command = [executable, "--client", address, "--time", str(seconds), "--json"]
    if reverse:
        command.append("--reverse")
    if udp:
        if not re.fullmatch(r"\d+(?:\.\d+)?[KMG]?", bandwidth, re.IGNORECASE):
            raise ValueError("iperf3 bandwidth must look like 10M or 500K")
        command += ["--udp", "--bitrate", bandwidth]
    result = subprocess.run(command, capture_output=True, text=True, timeout=seconds + 20, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "iperf3 failed").strip()[:1_000])
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("iperf3 returned an invalid report")
    return value


def capture_capabilities() -> list[dict[str, str]]:
    providers: list[dict[str, str]] = []
    for name, executable, note in (
        ("Npcap/Wireshark", "dumpcap", "Live capture with Wireshark-compatible interfaces"),
        ("TShark", "tshark", "Live capture and protocol decoding"),
        ("Windows Packet Monitor", "pktmon", "Built-in Windows ETL capture and PCAPNG conversion"),
        ("tcpdump", "tcpdump", "Native Unix packet capture"),
    ):
        path = shutil.which(executable)
        providers.append({"provider": name, "command": executable,
                          "available": "Yes" if path else "No", "path": path or "", "note": note})
    return providers


def top_talkers(limit: int = 50) -> list[dict[str, object]]:
    evidence = latest_network_watch_evidence()
    if not evidence.get("available"):
        return []
    devices = list(evidence.get("devices", []))
    devices.sort(key=lambda row: int(row.get("sent", 0)) + int(row.get("received", 0)), reverse=True)
    return devices[:max(1, min(limit, 500))]


def fetch_cisa_kev(timeout: float = 12.0) -> dict[str, object]:
    request = Request(CISA_KEV_URL, headers={"User-Agent": "Advanced-IP-Analyser/3.0"})
    with urlopen(request, timeout=max(1.0, min(timeout, 30.0))) as response:
        raw = response.read(20 * 1024 * 1024 + 1)
    if len(raw) > 20 * 1024 * 1024:
        raise ValueError("CISA KEV response exceeds the safety limit")
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get("vulnerabilities"), list):
        raise ValueError("CISA KEV response has an unexpected format")
    return value


def match_kev(catalogue: dict[str, object], terms: Iterable[str], limit: int = 200) -> list[dict[str, str]]:
    needles = [term.strip().casefold() for term in terms if len(term.strip()) >= 3][:32]
    if not needles:
        return []
    matches: list[dict[str, str]] = []
    for item in catalogue.get("vulnerabilities", []):
        if not isinstance(item, dict):
            continue
        haystack = " ".join(str(item.get(key, "")) for key in
                            ("vendorProject", "product", "vulnerabilityName", "shortDescription")).casefold()
        if all(needle in haystack for needle in needles):
            matches.append({key: str(item.get(key, ""))[:2_048] for key in
                            ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
                             "dueDate", "knownRansomwareCampaignUse", "requiredAction", "shortDescription")})
            if len(matches) >= limit:
                break
    return matches


def operations_report() -> dict[str, object]:
    changes = scan_change_summary()
    neighbors = read_neighbor_table()
    return {
        "schema": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_changes": changes,
        "neighbor_entries": [asdict(item) for item in neighbors[:MAX_REPORT_ROWS]],
        "conflicts": [asdict(item) for item in find_address_conflicts(neighbors)],
        "top_talkers": top_talkers(MAX_REPORT_ROWS),
        "capture_capabilities": capture_capabilities(),
        "limitations": [
            "Neighbour caches contain recently learned entries, not a complete DHCP lease database.",
            "Traffic attribution requires a capture point that can observe the relevant packets.",
            "CISA KEV matching is evidence for review, not proof that a detected device is vulnerable.",
        ],
    }


def export_operations_report(path: Path, report: dict[str, object] | None = None) -> Path:
    report = report or operations_report()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path
