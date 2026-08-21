from __future__ import annotations

from .scanner import DEFAULT_PORTS


def parse_ports(text: str, limit: int = 256) -> dict[int, str]:
    """Parse comma-separated ports and inclusive ranges."""
    ports: set[int] = set()
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            left, right = token.split("-", 1)
            start, end = int(left), int(right)
            if end < start:
                raise ValueError(f"invalid port range: {token}")
            if start < 1 or end > 65535:
                raise ValueError("ports must be between 1 and 65535")
            ports.update(range(start, end + 1))
        else:
            port = int(token)
            if port < 1 or port > 65535:
                raise ValueError("ports must be between 1 and 65535")
            ports.add(port)
        if len(ports) > limit:
            raise ValueError(f"port list exceeds the {limit}-port limit")
    if not ports:
        raise ValueError("enter at least one TCP port")
    return {port: DEFAULT_PORTS.get(port, f"tcp/{port}") for port in sorted(ports)}

