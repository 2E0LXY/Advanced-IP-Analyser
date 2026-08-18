from __future__ import annotations

import ipaddress


MAX_TARGETS = 65_536


def parse_targets(text: str, limit: int = MAX_TARGETS) -> list[str]:
    """Parse one IP, CIDR, or inclusive `start-end` range."""
    text = text.strip()
    if not text:
        raise ValueError("target is empty")
    if "-" in text:
        left, right = (part.strip() for part in text.split("-", 1))
        start, end = ipaddress.ip_address(left), ipaddress.ip_address(right)
        if start.version != end.version or int(end) < int(start):
            raise ValueError("range end must follow start and use the same IP version")
        count = int(end) - int(start) + 1
        _check_size(count, limit)
        return [str(ipaddress.ip_address(int(start) + offset)) for offset in range(count)]
    if "/" in text:
        network = ipaddress.ip_network(text, strict=False)
        count = network.num_addresses if network.version == 6 else max(0, network.num_addresses - 2)
        _check_size(count, limit)
        return [str(item) for item in network.hosts()]
    return [str(ipaddress.ip_address(text))]


def _check_size(count: int, limit: int) -> None:
    if count > limit:
        raise ValueError(f"target contains {count:,} addresses; limit is {limit:,}")
