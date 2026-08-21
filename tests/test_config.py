import unittest

from ip_analyser.config import parse_ports


class PortConfigTests(unittest.TestCase):
    def test_ports_and_ranges(self):
        self.assertEqual(parse_ports("22, 80, 443-445"),
                         {22: "ssh", 80: "http", 443: "https", 444: "tcp/444", 445: "smb"})

    def test_rejects_invalid_ports(self):
        for value in ("", "0", "65536", "90-80"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ports(value)

    def test_all_tcp_ports_requires_explicit_large_limit(self):
        ports = parse_ports("1-65535", limit=65_535)
        self.assertEqual((len(ports), min(ports), max(ports)), (65_535, 1, 65_535))

    def test_out_of_range_endpoint_is_rejected_before_expansion(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 65535"):
            parse_ports("1-999999999")
