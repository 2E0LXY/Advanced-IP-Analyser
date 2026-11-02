import math
import socket
import struct
import unittest
from unittest.mock import patch

from ip_analyser.dns_benchmark import (
    RESOLVERS,
    DNSBenchmarkResult,
    DNSResolver,
    benchmark_resolvers,
    build_query,
    probe_resolver,
    valid_response,
)


class DNSBenchmarkTests(unittest.TestCase):
    def test_build_query_contains_transaction_and_a_question(self):
        query = build_query("example.com", 0x1234)
        self.assertEqual(query[:2], b"\x12\x34")
        self.assertEqual(query[4:6], b"\x00\x01")
        self.assertIn(b"\x07example\x03com\x00", query)
        self.assertEqual(query[-4:], b"\x00\x01\x00\x01")

    def test_valid_response_requires_matching_success_reply(self):
        response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        self.assertTrue(valid_response(response, 0x1234))
        self.assertFalse(valid_response(response, 0x9999))
        self.assertFalse(valid_response(
            struct.pack("!HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0), 0x1234))

    def test_result_ignores_timeouts_for_average_and_jitter(self):
        result = DNSBenchmarkResult(DNSResolver("Test", "192.0.2.1"), [10.0, None, 30.0])
        self.assertEqual(result.replies, 2)
        self.assertEqual(result.average_ms, 20.0)
        self.assertEqual(result.jitter_ms, 10.0)

    def test_benchmark_validates_bounds_and_catalog(self):
        with self.assertRaises(ValueError):
            benchmark_resolvers(rounds=0)
        with self.assertRaises(ValueError):
            benchmark_resolvers(timeout=float("nan"))
        self.assertEqual(len(RESOLVERS), 36)

    @patch("ip_analyser.dns_benchmark.secrets.randbelow", return_value=0x1234)
    @patch("ip_analyser.dns_benchmark.socket.socket")
    def test_probe_sends_udp_dns_and_validates_reply(self, socket_factory, _random):
        response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        client = socket_factory.return_value.__enter__.return_value
        client.recvfrom.return_value = (response, ("1.1.1.1", 53))
        latency, rcode = probe_resolver(DNSResolver("Test", "1.1.1.1"), "example.com", 1.5)
        socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout.assert_called_once_with(1.5)
        client.sendto.assert_called_once()
        self.assertIsNotNone(latency)
        self.assertTrue(math.isfinite(latency))
        self.assertEqual(rcode, 0)


if __name__ == "__main__":
    unittest.main()
