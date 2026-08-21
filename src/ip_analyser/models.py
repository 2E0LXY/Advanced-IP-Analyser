from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class Host:
    address: str
    reachable: bool = False
    hostname: str = ""
    latency_ms: float | None = None
    mac: str = ""
    manufacturer: str = ""
    services: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    service_info: dict[str, dict[str, str]] = field(default_factory=dict)
    seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    note: str = ""

    @property
    def identity(self) -> str:
        """Stable device key: prefer a hardware address, then the current IP."""
        return (self.mac or self.address).casefold()

    def merge_observation(self, observed: "Host") -> "Host":
        """Return an updated saved device without losing user-authored notes."""
        if self.mac and observed.mac and self.mac.casefold() != observed.mac.casefold():
            raise ValueError("cannot merge devices with different MAC addresses")
        return Host(
            address=observed.address,
            reachable=observed.reachable,
            hostname=observed.hostname or self.hostname,
            latency_ms=observed.latency_ms,
            mac=observed.mac or self.mac,
            manufacturer=observed.manufacturer or self.manufacturer,
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
        allowed = {name for name in cls.__dataclass_fields__}
        return cls(**{key: item for key, item in value.items() if key in allowed})
