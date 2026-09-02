import unittest

from ip_analyser.asset_profiles import infer_asset_profile
from ip_analyser.models import Host


class AssetProfileTests(unittest.TestCase):
    def test_printer_and_model_are_inferred_from_bounded_discovery(self):
        host = Host(address="192.0.2.10", reachable=True, manufacturer="HP",
                    services=["ipp", "printer"], ports=[631, 9100],
                    service_info={"631": {"Page title": "HP LaserJet Pro M404 admin"}})
        profile = infer_asset_profile(host)
        self.assertEqual(profile.device_type, "Printer")
        self.assertIn("laserjet", profile.model.casefold())
        self.assertEqual(profile.confidence, "High")

    def test_os_uses_service_banner_without_overclaiming(self):
        host = Host(address="192.0.2.20", reachable=True, services=["ssh"], ports=[22],
                    service_info={"22": {"Banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5"}})
        profile = infer_asset_profile(host)
        self.assertEqual(profile.operating_system, "Debian Linux")
        self.assertEqual(profile.device_type, "Computer / server")

    def test_unknown_device_remains_conservative(self):
        profile = infer_asset_profile(Host(address="192.0.2.30", reachable=True))
        self.assertEqual(profile.device_type, "Unknown device")
        self.assertFalse(profile.operating_system)
        self.assertEqual(profile.confidence, "Low")


if __name__ == "__main__":
    unittest.main()
