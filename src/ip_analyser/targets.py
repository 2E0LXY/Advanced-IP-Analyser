from __future__ import annotations

import ipaddress
import re

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
        if network.prefixlen >= network.max_prefixlen - 1:
            count = network.num_addresses
        else:
            count = network.num_addresses - (2 if network.version == 4 else 1)
        _check_size(count, limit)
        return [str(item) for item in network.hosts()]
    return [str(ipaddress.ip_address(text))]


def parse_target_sets(text: str, limit: int = MAX_TARGETS) -> list[str]:
    """Parse comma, semicolon, or newline-separated address/range/CIDR targets.

    The total expanded, deduplicated result remains subject to one aggregate
    limit. This permits several connected subnets without weakening the bounded
    scan guarantee.
    """
    parts = [part.strip() for part in re.split(r"[,;\r\n]+", text) if part.strip()]
    if not parts:
        raise ValueError("target is empty")
    targets: list[str] = []
    seen: set[str] = set()
    for part in parts:
        for address in parse_targets(part, limit=limit):
            if address in seen:
                continue
            seen.add(address)
            targets.append(address)
            _check_size(len(targets), limit)
    return targets


def _check_size(count: int, limit: int) -> None:
    if count > limit:
        raise ValueError(f"target contains {count:,} addresses; limit is {limit:,}")
