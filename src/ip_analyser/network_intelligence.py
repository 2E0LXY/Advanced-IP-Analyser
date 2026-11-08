"""Explainable network-graph analytics built from local inventory metadata only."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import xml.etree.ElementTree as ET  # nosec B405 - writing trusted local output
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import Host

FORMAT_VERSION = 1
_RISKY_PORTS = {
    21: (14, "unencrypted FTP service"),
    23: (24, "unencrypted Telnet service"),
    25: (8, "mail service exposed"),
    111: (8, "RPC service exposed"),
    135: (8, "Windows RPC service exposed"),
    139: (10, "legacy NetBIOS service"),
    445: (14, "SMB file-sharing service"),
    1433: (12, "database service exposed"),
    3306: (12, "database service exposed"),
    3389: (14, "remote desktop service"),
    5432: (12, "database service exposed"),
    5900: (14, "remote display service"),
}


@dataclass(frozen=True, slots=True)
class EntityGroup:
    canonical: Host
    observations: tuple[Host, ...]
    match_reason: str

    @property
    def duplicate_count(self) -> int:
        return max(0, len(self.observations) - 1)


@dataclass(frozen=True, slots=True)
class DeviceInsight:
    host: Host
    risk_score: int
    risk_level: str
    zone: str
    factors: tuple[str, ...]
    duplicate_count: int = 0


def _normal(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def resolve_entities(hosts: Iterable[Host]) -> list[EntityGroup]:
    """Conservatively join repeated observations without fuzzy false positives."""
    groups: list[list[Host]] = []
    keys: list[set[str]] = []
    reasons: list[str] = []
    for host in hosts:
        host_keys = {f"ip:{host.address.casefold()}"}
        reason = "same IP address"
        if host.mac:
            host_keys.add(f"mac:{host.identity}")
            reason = "same hardware address"
        elif host.hostname and host.manufacturer:
            host_keys.add(f"named:{_normal(host.hostname)}:{_normal(host.manufacturer)}")
            reason = "same hostname and manufacturer"
        matched = next((
            index for index, current in enumerate(keys)
            if current & host_keys and not (
                host.mac and any(observed.mac and observed.identity != host.identity
                                 for observed in groups[index])
            )
        ), None)
        if matched is None:
            groups.append([host])
            keys.append(host_keys)
            reasons.append(reason)
        else:
            groups[matched].append(host)
            keys[matched].update(host_keys)
            if host.mac:
                reasons[matched] = "same hardware address"

    resolved: list[EntityGroup] = []
    for observations, reason in zip(groups, reasons):
        canonical = observations[0]
        for observation in observations[1:]:
            try:
                updated = canonical.merge_observation(observation)
                services_by_port = {port: service for service, port in
                                    zip(canonical.services, canonical.ports)}
                services_by_port.update({port: service for service, port in
                                         zip(observation.services, observation.ports)})
                canonical = Host(
                    address=updated.address, reachable=updated.reachable,
                    hostname=updated.hostname, latency_ms=updated.latency_ms,
                    mac=updated.mac, manufacturer=updated.manufacturer,
                    device_type=updated.device_type, operating_system=updated.operating_system,
                    os_version=updated.os_version, model=updated.model,
                    profile_confidence=updated.profile_confidence,
                    services=[services_by_port[port] for port in sorted(services_by_port)],
                    ports=sorted(services_by_port),
                    service_info={**canonical.service_info, **observation.service_info},
                    seen_at=updated.seen_at, note=updated.note,
                )
            except ValueError:
                # Conflicting hardware identities are never collapsed.
                resolved.append(EntityGroup(canonical, (canonical,), "unique identity"))
                canonical = observation
        resolved.append(EntityGroup(canonical, tuple(observations), reason))
    return sorted(resolved, key=lambda item: (item.canonical.address, item.canonical.hostname.casefold()))


def classify_zone(host: Host) -> str:
    text = " ".join((host.hostname, host.manufacturer, host.device_type,
                     host.operating_system, *host.services)).casefold()
    ports = set(host.ports)
    try:
        if not ipaddress.ip_address(host.address).is_private:
            return "Internet"
    except ValueError:
        return "Unknown"
    if any(word in text for word in ("router", "gateway", "switch", "access point")):
        return "Infrastructure"
    if ports & {53, 67, 68, 123, 161}:
        return "Infrastructure"
    if any(word in text for word in ("camera", "printer", "television", "iot", "smart", "esp")):
        return "IoT"
    if ports & {25, 53, 80, 443, 445, 1433, 3306, 5432, 8080, 8443}:
        return "Server"
    if ports & {22, 3389, 5900}:
        return "Admin"
    return "Workstation"


def score_host(host: Host) -> tuple[int, str, tuple[str, ...]]:
    """Return a bounded, explainable exposure score; it is not a threat verdict."""
    score = 0
    factors: list[str] = []
    for port in sorted(set(host.ports)):
        if port in _RISKY_PORTS:
            points, reason = _RISKY_PORTS[port]
            score += points
            factors.append(f"TCP {port}: {reason} (+{points})")
    if len(set(host.ports)) >= 12:
        score += 12
        factors.append("large exposed service surface (+12)")
    elif len(set(host.ports)) >= 6:
        score += 6
        factors.append("multiple exposed services (+6)")
    if host.reachable and not host.operating_system:
        score += 4
        factors.append("operating system not identified (+4)")
    if host.reachable and not host.mac:
        score += 2
        factors.append("hardware identity unavailable (+2)")
    score = min(score, 100)
    level = "Critical" if score >= 70 else "High" if score >= 45 else "Medium" if score >= 20 else "Low"
    if not factors:
        factors.append("no elevated exposure factors observed")
    return score, level, tuple(factors)


def analyse_hosts(hosts: Iterable[Host]) -> list[DeviceInsight]:
    insights: list[DeviceInsight] = []
    for entity in resolve_entities(hosts):
        score, level, factors = score_host(entity.canonical)
        insights.append(DeviceInsight(entity.canonical, score, level,
                                      classify_zone(entity.canonical), factors,
                                      entity.duplicate_count))
    return sorted(insights, key=lambda item: (-item.risk_score, item.host.address))


def _term_matches(item: DeviceInsight, term: str) -> bool:
    field, separator, raw = term.partition(":")
    if not separator:
        needle = term.casefold()
        values = (item.host.address, item.host.hostname, item.host.mac, item.host.manufacturer,
                  item.host.device_type, item.host.operating_system, item.zone,
                  item.risk_level, *item.host.services, *item.factors)
        return any(needle in str(value).casefold() for value in values)
    value = raw.strip()
    field = field.casefold()
    if field in {"ip", "address"}:
        try:
            return ipaddress.ip_address(item.host.address) in ipaddress.ip_network(value, strict=False)
        except ValueError:
            return value.casefold() in item.host.address.casefold()
    if field == "port":
        return value.isdigit() and int(value) in item.host.ports
    if field == "risk":
        match = re.fullmatch(r"(>=|<=|>|<|=)?(\d{1,3})", value)
        if match:
            operator, number = match.group(1) or "=", int(match.group(2))
            return {">=": item.risk_score >= number, "<=": item.risk_score <= number,
                    ">": item.risk_score > number, "<": item.risk_score < number,
                    "=": item.risk_score == number}[operator]
        return value.casefold() == item.risk_level.casefold()
    fields = {
        "name": item.host.hostname,
        "host": item.host.hostname,
        "mac": item.host.mac,
        "vendor": item.host.manufacturer,
        "type": item.host.device_type,
        "os": item.host.operating_system,
        "service": " ".join(item.host.services),
        "zone": item.zone,
        "factor": " ".join(item.factors),
    }
    return value.casefold() in fields.get(field, "").casefold()


def filter_insights(items: Iterable[DeviceInsight], query: str) -> list[DeviceInsight]:
    """Filter with field:value terms, NOT/-term and OR groups; whitespace means AND."""
    try:
        tokens = shlex.split(query)
    except ValueError as error:
        raise ValueError("query contains an unfinished quote") from error
    if not tokens:
        return list(items)
    groups: list[list[str]] = [[]]
    for token in tokens:
        if token.casefold() == "or":
            if groups[-1]:
                groups.append([])
            continue
        if token.casefold() == "and":
            continue
        groups[-1].append(token)

    def group_matches(item: DeviceInsight, group: list[str]) -> bool:
        for token in group:
            negative = token.startswith("-") or token.casefold().startswith("not:")
            term = token[1:] if token.startswith("-") else token[4:] if token.casefold().startswith("not:") else token
            matched = _term_matches(item, term)
            if matched == negative:
                return False
        return bool(group)

    return [item for item in items if any(group_matches(item, group) for group in groups)]


def intelligence_document(items: Iterable[DeviceInsight], query: str = "") -> dict:
    devices = []
    for item in items:
        devices.append({
            "identity": item.host.identity,
            "address": item.host.address,
            "hostname": item.host.hostname,
            "mac": item.host.mac,
            "manufacturer": item.host.manufacturer,
            "device_type": item.host.device_type,
            "operating_system": item.host.operating_system,
            "services": [{"name": name, "port": port}
                         for name, port in zip(item.host.services, item.host.ports)],
            "zone": item.zone,
            "risk": {"score": item.risk_score, "level": item.risk_level,
                     "factors": list(item.factors)},
            "merged_observations": item.duplicate_count + 1,
        })
    return {"format": "advanced-ip-analyser-intelligence", "version": FORMAT_VERSION,
            "generated_at": datetime.now(UTC).isoformat(), "query": query,
            "devices": devices}


def export_intelligence_json(path: Path, items: Iterable[DeviceInsight], query: str = "") -> None:
    path.write_text(json.dumps(intelligence_document(items, query), indent=2) + "\n", encoding="utf-8")


def export_graphml(path: Path, items: Iterable[DeviceInsight]) -> None:
    """Write portable GraphML with device-to-service dependency edges."""
    root = ET.Element("graphml", {"xmlns": "http://graphml.graphdrawing.org/xmlns"})
    for key_id, target, name, value_type in (
        ("label", "all", "label", "string"), ("kind", "all", "kind", "string"),
        ("risk", "node", "risk", "int"), ("zone", "node", "zone", "string"),
    ):
        ET.SubElement(root, "key", {"id": key_id, "for": target,
                                     "attr.name": name, "attr.type": value_type})
    graph = ET.SubElement(root, "graph", {"id": "network", "edgedefault": "directed"})
    service_nodes: set[int] = set()
    edge_index = 0
    for item in items:
        device_id = f"device-{item.host.identity}"
        node = ET.SubElement(graph, "node", {"id": device_id})
        for key, value in (("label", item.host.hostname or item.host.address),
                           ("kind", "device"), ("risk", str(item.risk_score)),
                           ("zone", item.zone)):
            ET.SubElement(node, "data", {"key": key}).text = value
        for service, port in zip(item.host.services, item.host.ports):
            if port not in service_nodes:
                service_node = ET.SubElement(graph, "node", {"id": f"service-{port}"})
                ET.SubElement(service_node, "data", {"key": "label"}).text = f"{service or 'tcp'}:{port}"
                ET.SubElement(service_node, "data", {"key": "kind"}).text = "service"
                ET.SubElement(service_node, "data", {"key": "risk"}).text = "0"
                ET.SubElement(service_node, "data", {"key": "zone"}).text = "Service"
                service_nodes.add(port)
            ET.SubElement(graph, "edge", {"id": f"e{edge_index}", "source": device_id,
                                           "target": f"service-{port}"})
            edge_index += 1
    ET.indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
