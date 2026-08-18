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
