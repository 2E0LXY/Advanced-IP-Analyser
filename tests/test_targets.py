import unittest

from ip_analyser.targets import parse_targets


class TargetTests(unittest.TestCase):
    def test_single_address(self):
        self.assertEqual(parse_targets("192.0.2.8"), ["192.0.2.8"])

    def test_range_is_inclusive(self):
        self.assertEqual(parse_targets("192.0.2.1-192.0.2.3"),
                         ["192.0.2.1", "192.0.2.2", "192.0.2.3"])

    def test_cidr_excludes_ipv4_network_and_broadcast(self):
        self.assertEqual(parse_targets("192.0.2.0/30"), ["192.0.2.1", "192.0.2.2"])

    def test_small_ipv6_cidr_is_supported(self):
        self.assertEqual(parse_targets("2001:db8::/126"),
                         ["2001:db8::1", "2001:db8::2", "2001:db8::3"])

    def test_ipv6_lan_is_not_brute_force_enumerated(self):
        with self.assertRaisesRegex(ValueError, "limit"):
            parse_targets("2001:db8:1::/64")

    def test_rejects_oversized_target(self):
        with self.assertRaisesRegex(ValueError, "limit"):
            parse_targets("10.0.0.0/8")

    def test_point_to_point_network_respects_target_limit(self):
        with self.assertRaisesRegex(ValueError, "limit"):
            parse_targets("192.0.2.0/31", limit=1)
