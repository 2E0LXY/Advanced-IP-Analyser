import json
from pathlib import Path
import socket
import struct
import tempfile
import time
import unittest

from ip_analyser.monitoring import (AlertRule, MonitorAnalyzer, MonitorStore,
                                    enforce_capture_retention, export_analysis,
                                    load_rules, save_rules)
from ip_analyser.packet_tools import PacketRecord


def tcp_record(number: int, timestamp: float, flags: int = 0x02,
               source: str = "192.168.1.10", destination: str = "198.51.100.4",
               sequence: int = 1, payload: bytes = b"") -> PacketRecord:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    tcp = struct.pack("!HHLLBBHHH", 50_000, 443, sequence, 0, 0x50,
                      flags, 8192, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), number, 0, 64, 6, 0,
                     socket.inet_aton(source), socket.inet_aton(destination))
    frame = ethernet + ip + tcp
    info = ",".join(name for bit, name in ((2, "SYN"), (16, "ACK"), (4, "RST")) if flags & bit)
    return PacketRecord(number, timestamp, source, destination, "TCP", 50_000, 443,
                        len(frame), info, frame)


def dns_record(timestamp: float, rcode: int = 0) -> PacketRecord:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    name = b"\x07example\x03com\x00"
    dns = struct.pack("!HHHHHH", 1, 0x8000 | rcode, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 53, 53000, 8 + len(dns), 0) + dns
    source, destination = "192.168.1.1", "192.168.1.10"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton(source), socket.inet_aton(destination))
    frame = ethernet + ip + udp
    return PacketRecord(1, timestamp, source, destination, "DNS", 53, 53000,
                        len(frame), "", frame)


class MonitoringTests(unittest.TestCase):
    def test_analysis_builds_timeline_flow_device_and_tcp_findings(self):
        started = 1_700_000_000.0
        records = [tcp_record(index + 1, started + index * 6, flags=0x02,
                              sequence=index + 1) for index in range(6)]
        analysis = MonitorAnalyzer(known_devices=["192.168.1.1"]).analyze(records)
        self.assertEqual(analysis.packet_count, 6)
        self.assertEqual(len(analysis.flows), 1)
        self.assertEqual(analysis.flows[0].syns, 6)
        self.assertTrue(any(item.category == "Failed connections" for item in analysis.findings))
        self.assertTrue(any(item.category == "New device" and item.subject == "192.168.1.10"
                            for item in analysis.findings))
        self.assertEqual(sum(bucket.packets for bucket in analysis.buckets), 6)

    def test_dns_is_parsed_and_failed_dns_is_explained(self):
        records = [dns_record(1_700_000_000 + index, 3) for index in range(5)]
        analysis = MonitorAnalyzer().analyze(records)
        self.assertEqual(analysis.dns[0].name, "example.com")
        self.assertEqual(analysis.dns[0].rcode, 3)
        self.assertTrue(any(item.category == "DNS failures" for item in analysis.findings))

    def test_configured_rules_are_validated_and_trigger(self):
        rule = AlertRule.from_dict({"name": "Large session", "kind": "traffic_bytes",
                                    "threshold": 1, "device": "192.168.1.10", "enabled": True})
        analysis = MonitorAnalyzer(rules=[rule]).analyze([tcp_record(1, 1_700_000_000)])
        self.assertTrue(any(item.category == "Rule: Large session" for item in analysis.findings))
        with self.assertRaises(ValueError):
            AlertRule.from_dict({"name": "Bad", "kind": "run_command"})

    def test_rules_round_trip_and_reject_unbounded_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            rules = [AlertRule("DNS", "dns_name", "example.com")]
            save_rules(path, rules)
            self.assertEqual(load_rules(path), rules)
            path.write_text(json.dumps({"format": 1, "rules": [{}] * 257}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "too many"):
                load_rules(path)

    def test_sqlite_history_baseline_pruning_and_reports(self):
        analysis = MonitorAnalyzer().analyze([tcp_record(1, time.time())])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = MonitorStore(root / "watch.sqlite3")
            session = store.save(analysis, root / "capture.pcap")
            self.assertEqual(store.recent_sessions()[0][0], session)
            self.assertGreater(store.baselines()["192.168.1.10"], 0)
            for suffix in (".json", ".csv", ".html"):
                report = root / f"report{suffix}"
                export_analysis(report, analysis)
                self.assertGreater(report.stat().st_size, 20)
            store.close()

    def test_capture_retention_preserves_bookmarks_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "watch-old.pcap"
            protected = root / "watch-protected.pcap"
            unrelated = root / "notes.txt"
            for path in (old, protected, unrelated):
                path.write_bytes(b"x")
            old_time = time.time() - 10 * 86_400
            import os
            os.utime(old, (old_time, old_time))
            os.utime(protected, (old_time, old_time))
            removed = enforce_capture_retention(root, days=7, protected=[protected])
            self.assertEqual(removed, [old.resolve()])
            self.assertTrue(protected.exists())
            self.assertTrue(unrelated.exists())


if __name__ == "__main__":
    unittest.main()
