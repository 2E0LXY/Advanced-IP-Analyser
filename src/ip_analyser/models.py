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
    services: list[str] = field(default_factory=list)
    seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "Host":
        allowed = {name for name in cls.__dataclass_fields__}
        return cls(**{key: item for key, item in value.items() if key in allowed})
