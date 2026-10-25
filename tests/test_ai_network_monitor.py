from __future__ import annotations

import json
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from ip_analyser.ai_network_monitor import (
    local_report, monitor_loop, monitor_once, save_local_report, validate_monitor_target,
)
from ip_analyser.models import Host


class LocalAIMonitorTests(unittest.TestCase):
    def test_monitor_rejects_public_or_unbounded_targets(self):
        for target in ("8.8.8.8", "0.0.0.0/24", "127.0.0.1", "224.0.0.1",
                       "192.168.0.0/16", "2001:4860:4860::8888"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_monitor_target(target)


    def test_monitor_snapshot_and_redacted_report(self):
        with TemporaryDirectory() as directory:
            history = Path(directory) / "history.sqlite3"

            class FakeScanner:
                def __init__(self, **kwargs):
                    assert len(kwargs["ports"]) <= 32

                def scan(self, targets, discover_services):
                    assert not discover_services
                    return [Host(address="192.168.1.12", reachable=True, hostname="private-dvr",
                                 mac="AA:BB:CC:DD:EE:FF", ports=[80], services=["http"])]

            result = monitor_once("192.168.1.12", history_path=history, scanner_factory=FakeScanner)
            self.assertEqual(result["reachable"], 1)
            safe = local_report(history)
            self.assertNotIn("private-dvr", json.dumps(safe))
            self.assertNotIn("192.168.1.12", json.dumps(safe))
            report_path = save_local_report(Path(directory) / "report.json", safe)
            self.assertTrue(json.loads(report_path.read_text())["local_only"])

            detailed = local_report(history, include_identifiers=True)
            self.assertTrue(detailed["identifiers_included"])


    def test_monitor_repeat_is_bounded_and_stoppable(self):
        calls = []

        def fake_scan(target, *, history_path):
            calls.append(target)
            return {"reachable": 1}

        class NoWaitEvent:
            def is_set(self):
                return False

            def wait(self, seconds):
                assert seconds == 60

        self.assertEqual(monitor_loop("192.168.1.1", count=2, interval=60, scan_once=fake_scan,
                                      stop=NoWaitEvent()), 2)
        self.assertEqual(len(calls), 2)
        with self.assertRaises(ValueError):
            monitor_loop("192.168.1.1", interval=1, scan_once=fake_scan)
