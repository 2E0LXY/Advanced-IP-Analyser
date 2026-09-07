import tempfile
import unittest
from pathlib import Path

from ip_analyser.models import Host
from ip_analyser.monitoring import Analysis, DeviceActivity, Finding, Flow, MonitorStore
from ip_analyser.scan_history import (
    latest_evidence,
    latest_network_watch_evidence,
    record_scan,
)


class ScanHistoryTests(unittest.TestCase):
    def test_records_changes_and_capacity_without_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            first = Host("192.0.2.10", reachable=True, mac="AA:BB:CC:DD:EE:01",
                         services=["http"], ports=[80], note="never persist this note")
            record_scan([first], "192.0.2.0/24", path)
            changed = Host("192.0.2.20", reachable=True, mac="AA:BB:CC:DD:EE:01",
                           services=["https"], ports=[443])
            added = Host("192.0.2.30", reachable=True, mac="AA:BB:CC:DD:EE:02")
            record_scan([changed, added], "192.0.2.0/24", path)

            evidence = latest_evidence(path)

            self.assertEqual(len(evidence["changes"]["new"]), 1)
            self.assertEqual(len(evidence["changes"]["changed"]), 1)
            self.assertIn("address", evidence["changes"]["changed"][0]["fields"])
            self.assertEqual(evidence["capacity"]["address_capacity"], 254)
            self.assertIn("not DHCP lease", evidence["capacity"]["limitation"])
            self.assertNotIn("never persist", str(evidence))

    def test_empty_history_is_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.sqlite3"
            evidence = latest_evidence(path)
            self.assertEqual(evidence["snapshots"], [])

    def test_deduplicates_identity_and_drops_sensitive_service_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            first = Host("192.0.2.10", reachable=True, mac="AA:BB:CC:DD:EE:01")
            final = Host("192.0.2.11", reachable=True, mac="AA:BB:CC:DD:EE:01",
                         service_info={443: {"server": "example", "authorization": "secret",
                                             "api_token": "also-secret"}})

            record_scan([first, final], "192.0.2.0/24", path)
            evidence = latest_evidence(path)

            self.assertEqual(evidence["snapshots"][0]["host_count"], 1)
            raw = path.read_bytes()
            self.assertNotIn(b"also-secret", raw)
            self.assertNotIn(b"authorization", raw)

    def test_reads_bounded_latest_network_watch_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network-watch.sqlite3"
            analysis = Analysis(started=1.0, ended=2.0, packet_count=3, byte_count=300,
                                buckets=[], flows=[], devices=[], dns=[], findings=[],
                                protocols={}, services={})
            analysis.devices.append(DeviceActivity(
                "192.0.2.10", 1.0, 2.0, bytes_sent=10, bytes_received=20,
                peers={"192.0.2.1"}, ports={53}, protocols={"DNS": 1}))
            analysis.flows.append(Flow("192.0.2.10", 50000, "192.0.2.1", 53, "DNS", 1.0, 2.0))
            analysis.findings.append(Finding(2.0, "review", "DHCP", "Multiple DHCP servers", "two seen"))
            store = MonitorStore(path)
            try:
                store.save(analysis)
            finally:
                store.close()

            evidence = latest_network_watch_evidence(path)

            self.assertTrue(evidence["available"])
            self.assertEqual(evidence["session"]["packets"], 3)
            self.assertEqual(evidence["devices"][0]["address"], "192.0.2.10")
            self.assertEqual(evidence["findings"][0]["subject"], "Multiple DHCP servers")


if __name__ == "__main__":
    unittest.main()
