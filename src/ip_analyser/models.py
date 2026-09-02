from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import math
import re


_LEGACY_SERVICE_PORTS = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "dns": 53,
    "http": 80, "pop3": 110, "imap": 143, "https": 443, "smb": 445,
    "rdp": 3389,
}


@dataclass(slots=True)
class Host:
    address: str
    reachable: bool = False
    hostname: str = ""
    latency_ms: float | None = None
    mac: str = ""
    manufacturer: str = ""
    device_type: str = ""
    operating_system: str = ""
    os_version: str = ""
    model: str = ""
    profile_confidence: str = ""
    services: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    service_info: dict[str, dict[str, str]] = field(default_factory=dict)
    seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    note: str = ""

    @property
    def identity(self) -> str:
        """Stable device key: prefer a hardware address, then the current IP."""
        if self.mac:
            return re.sub(r"[^0-9A-Fa-f]", "", self.mac).casefold()
        return self.address.casefold()

    def merge_observation(self, observed: "Host") -> "Host":
        """Return an updated saved device without losing user-authored notes."""
        if self.mac and observed.mac and self.identity != observed.identity:
            raise ValueError("cannot merge devices with different MAC addresses")
        return Host(
            address=observed.address,
            reachable=observed.reachable,
            hostname=observed.hostname or self.hostname,
            latency_ms=observed.latency_ms,
            mac=observed.mac or self.mac,
            manufacturer=observed.manufacturer or self.manufacturer,
            device_type=observed.device_type or self.device_type,
            operating_system=observed.operating_system or self.operating_system,
            os_version=observed.os_version or self.os_version,
            model=observed.model or self.model,
            profile_confidence=observed.profile_confidence or self.profile_confidence,
            services=list(observed.services),
            ports=list(observed.ports),
            service_info={port: dict(details) for port, details in observed.service_info.items()},
            seen_at=observed.seen_at if observed.reachable else self.seen_at,
            note=self.note,
        )

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "Host":
        """Validate an untrusted inventory record before it reaches the UI or actions."""
        if not isinstance(value, dict):
            raise ValueError("inventory device must be an object")

        address_value = value.get("address", "")
        if not isinstance(address_value, str):
            raise ValueError("device address must be text")
        try:
            address = str(ipaddress.ip_address(address_value.strip()))
        except ValueError as error:
            raise ValueError(f"invalid device address: {address_value!r}") from error

        def text(name: str, limit: int) -> str:
            item = value.get(name, "")
            if not isinstance(item, str):
                raise ValueError(f"device {name} must be text")
            if len(item) > limit:
                raise ValueError(f"device {name} exceeds {limit:,} characters")
            return item

        reachable = value.get("reachable", False)
        if not isinstance(reachable, bool):
            raise ValueError("device reachable flag must be true or false")
        latency = value.get("latency_ms")
        if latency is not None:
            if isinstance(latency, bool) or not isinstance(latency, (int, float)):
                raise ValueError("device latency must be a number")
            latency = float(latency)
            if not math.isfinite(latency) or latency < 0:
                raise ValueError("device latency must be a finite non-negative number")

        mac = text("mac", 32).strip()
        if mac:
            compact = re.sub(r"[^0-9A-Fa-f]", "", mac)
            if len(compact) != 12 or re.search(r"[^0-9A-Fa-f:.-]", mac):
                raise ValueError("device MAC address must contain six hexadecimal octets")
            mac = ":".join(compact[index:index + 2] for index in range(0, 12, 2)).upper()

        services = value.get("services", [])
        ports = value.get("ports", [])
        if not isinstance(services, list) or not all(isinstance(item, str) for item in services):
            raise ValueError("device services must be a list of names")
        if len(services) > 65_535 or any(not item or len(item) > 128 or not item.isprintable()
                                        for item in services):
            raise ValueError("device service name is invalid")
        if not isinstance(ports, list) or any(isinstance(item, bool) or not isinstance(item, int)
                                              or item < 1 or item > 65_535 for item in ports):
            raise ValueError("device ports must be TCP port numbers")
        if services and not ports and all(item in _LEGACY_SERVICE_PORTS for item in services):
            ports = [_LEGACY_SERVICE_PORTS[item] for item in services]
        if len(services) != len(ports):
            raise ValueError("device services and ports must contain the same number of entries")

        raw_info = value.get("service_info", {})
        if not isinstance(raw_info, dict) or len(raw_info) > 65_535:
            raise ValueError("device service metadata must be an object")
        service_info: dict[str, dict[str, str]] = {}
        for port, details in raw_info.items():
            if not isinstance(port, str) or not port.isdigit() or not 1 <= int(port) <= 65_535:
                raise ValueError("service metadata contains an invalid port")
            if not isinstance(details, dict) or len(details) > 64:
                raise ValueError("service metadata details must be an object")
            clean_details: dict[str, str] = {}
            for label, detail in details.items():
                if (not isinstance(label, str) or not isinstance(detail, str) or
                        not label or len(label) > 128 or len(detail) > 2_048):
                    raise ValueError("service metadata contains an invalid value")
                clean_details[label] = detail
            service_info[port] = clean_details

        return cls(
            address=address,
            reachable=reachable,
            hostname=text("hostname", 1_024),
            latency_ms=latency,
            mac=mac,
            manufacturer=text("manufacturer", 1_024),
            device_type=text("device_type", 128),
            operating_system=text("operating_system", 128),
            os_version=text("os_version", 128),
            model=text("model", 256),
            profile_confidence=text("profile_confidence", 32),
            services=list(services),
            ports=list(ports),
            service_info=service_info,
            seen_at=text("seen_at", 128),
            note=text("note", 4_096),
        )
