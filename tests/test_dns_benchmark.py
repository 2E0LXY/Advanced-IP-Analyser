import struct

import pytest

from ip_analyser.dns_benchmark import (
    RESOLVERS,
    Resolver,
    ResolverResult,
    benchmark_resolvers,
    build_query,
    valid_response,
)


def test_build_query_contains_transaction_and_a_question() -> None:
    query = build_query("example.com", 0x1234)
    assert query[:2] == b"\x12\x34"
    assert query[4:6] == b"\x00\x01"
    assert b"\x07example\x03com\x00" in query
    assert query[-4:] == b"\x00\x01\x00\x01"


def test_valid_response_requires_matching_success_reply() -> None:
    response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    assert valid_response(response, 0x1234)
    assert not valid_response(response, 0x9999)
    assert not valid_response(struct.pack("!HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0), 0x1234)


def test_result_ignores_timeouts_for_average_and_jitter() -> None:
    result = ResolverResult(Resolver("Test", "192.0.2.1"), (10.0, None, 30.0))
    assert result.replies == 2
    assert result.average_ms == 20.0
    assert result.jitter_ms == 10.0


def test_benchmark_validates_bounds() -> None:
    with pytest.raises(ValueError):
        benchmark_resolvers(rounds=0)
    with pytest.raises(ValueError):
        benchmark_resolvers(timeout=float("nan"))
    assert len(RESOLVERS) == 36
