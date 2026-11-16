"""Tests for the local Cyber Platform evidence model."""

from __future__ import annotations

import unittest

from ip_analyser.cyber_platform import build_cyber_overview


class CyberPlatformTests(unittest.TestCase):
    def test_empty_history_does_not_invent_results(self):
        result = build_cyber_overview({"current_devices": [], "snapshots": []})
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["open_ports"], 0)
        self.assertEqual(result["priority_review"], 0)
        self.assertEqual(result["cve_status"], "Not assessed")

    def test_device_counts_and_sorted_ports(self):
        report = {"current_devices": [
            {"address": "192.168.1.9", "hostname": "test-one",
             "ports": [443, 22], "services": ["https", "ssh"]},
            {"address": "192.168.1.10", "hostname": "test-two",
             "ports": [80], "services": ["http"]},
        ]}
        result = build_cyber_overview(report)
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["open_ports"], 3)
        self.assertEqual({host["address"] for host in result["devices"]},
                         {"192.168.1.9", "192.168.1.10"})

    def test_private_report_without_ids_is_not_misattributed(self):
        report = {"current_devices": [{"device_type": "Server", "ports": [22],
                                       "services": ["ssh"]}]}
        self.assertEqual(build_cyber_overview(report)["total"], 0)

    def test_no_claim_of_public_exposure_or_cve(self):
        result = build_cyber_overview({"current_devices": [
            {"address": "192.168.1.7", "ports": [23], "services": ["telnet"]},
        ]})
        self.assertEqual(result["cve_status"], "Not assessed")
        self.assertEqual(result["internet_exposure_status"], "Not verified from outside LAN")
        self.assertTrue(result["devices"][0]["factors"])

    def test_changes_and_chronological_history(self):
        result = build_cyber_overview({
            "current_devices": [],
            "summary": {"new": 1, "missing": 2, "changed": 3},
            "snapshots": [
                {"created_at": "2026-11-16", "host_count": 57},
                {"created_at": "2026-11-15", "host_count": 54},
            ],
        })
        self.assertEqual(result["changes"], {"new": 1, "missing": 2, "changed": 3})
        self.assertEqual(result["history"][0][1], 54)
        self.assertEqual(result["history"][-1][1], 57)

    def test_bad_inventory_is_rejected(self):
        with self.assertRaises(ValueError):
            build_cyber_overview({"current_devices": [{}] * 1025})

    def test_invalid_ports_and_addresses_ignored(self):
        result = build_cyber_overview({"current_devices": [
            {"address": "not-an-ip", "ports": [22], "services": ["ssh"]},
            {"address": "192.168.1.2", "ports": [True], "services": ["ssh"]},
        ]})
        self.assertEqual(result["total"], 0)


if __name__ == "__main__":
    unittest.main()
