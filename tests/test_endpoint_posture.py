from __future__ import annotations

import unittest
from unittest.mock import patch

from ip_analyser.endpoint_posture import (
    analyse_windows_snapshot,
    collect_endpoint_posture,
)


class EndpointPostureTests(unittest.TestCase):
    def test_good_snapshot_is_explainable(self) -> None:
        findings = analyse_windows_snapshot({
            "firewall": [
                {"Name": "Domain", "Enabled": True},
                {"Name": "Private", "Enabled": True},
                {"Name": "Public", "Enabled": True},
            ],
            "defender": {"AntivirusEnabled": True, "RealTimeProtectionEnabled": True},
            "antivirusProducts": [{"displayName": "Microsoft Defender Antivirus"}],
            "smb1State": "Disabled",
            "uacEnabled": 1,
            "networkProfiles": [{"NetworkCategory": "Private"}],
            "dnsServers": [{"ServerAddresses": ["1.1.1.1", "1.0.0.1"]}],
        })
        by_key = {item.key: item for item in findings}
        self.assertEqual(by_key["firewall"].status, "good")
        self.assertEqual(by_key["realtime"].status, "good")
        self.assertEqual(by_key["smb1"].status, "good")
        self.assertIn("1.1.1.1", by_key["dns"].summary)

    def test_disabled_controls_need_attention(self) -> None:
        findings = analyse_windows_snapshot({
            "firewall": [{"Name": "Public", "Enabled": False}],
            "defender": {"AntivirusEnabled": False, "RealTimeProtectionEnabled": False},
            "smb1State": "Enabled",
            "uacEnabled": 0,
        })
        by_key = {item.key: item for item in findings}
        self.assertEqual(by_key["firewall"].status, "attention")
        self.assertEqual(by_key["antivirus"].status, "attention")
        self.assertEqual(by_key["smb1"].status, "attention")
        self.assertEqual(by_key["uac"].status, "attention")

    def test_third_party_antivirus_avoids_false_alarm(self) -> None:
        findings = analyse_windows_snapshot({
            "defender": {"AntivirusEnabled": False, "RealTimeProtectionEnabled": False},
            "antivirusProducts": {"displayName": "Example Security"},
        })
        antivirus = next(item for item in findings if item.key == "antivirus")
        self.assertEqual(antivirus.status, "good")
        self.assertIn("Example Security", antivirus.summary)

    @patch("ip_analyser.endpoint_posture.platform.system", return_value="Linux")
    def test_non_windows_is_explicitly_unverified(self, _system) -> None:
        report = collect_endpoint_posture()
        self.assertEqual(report.platform, "Linux")
        self.assertEqual(report.findings[0].status, "unknown")


if __name__ == "__main__":
    unittest.main()
