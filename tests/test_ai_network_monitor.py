from __future__ import annotations

import json
import threading

import pytest

from ip_analyser.ai_network_monitor import (
    local_report, monitor_loop, monitor_once, save_local_report, validate_monitor_target,
)
from ip_analyser.models import Host


@pytest.mark.parametrize("target", ["8.8.8.8", "0.0.0.0/24", "127.0.0.1", "224.0.0.1",
                                            "192.168.0.0/16", "2001:4860:4860::8888"])
def test_monitor_rejects_public_or_unbounded_targets(target):
    with pytest.raises(ValueError):
        validate_monitor_target(target)


def test_monitor_snapshot_and_redacted_report(tmp_path):
    history = tmp_path / "history.sqlite3"

    class FakeScanner:
        def __init__(self, **kwargs):
            assert len(kwargs["ports"]) <= 32

        def scan(self, targets, discover_services):
            assert not discover_services
            return [Host(address="192.168.1.12", reachable=True, hostname="private-dvr",
                         mac="AA:BB:CC:DD:EE:FF", ports=[80], services=["http"])]

    result = monitor_once("192.168.1.12", history_path=history, scanner_factory=FakeScanner)
    assert result["reachable"] == 1
    safe = local_report(history)
    assert "private-dvr" not in json.dumps(safe)
    assert "192.168.1.12" not in json.dumps(safe)
    report_path = save_local_report(tmp_path / "report.json", safe)
    assert json.loads(report_path.read_text())["local_only"] is True

    detailed = local_report(history, include_identifiers=True)
    assert detailed["identifiers_included"] is True


def test_monitor_repeat_is_bounded_and_stoppable():
    calls = []

    def fake_scan(target, *, history_path):
        calls.append(target)
        return {"reachable": 1}

    class NoWaitEvent:
        def is_set(self):
            return False

        def wait(self, seconds):
            assert seconds == 60

    assert monitor_loop("192.168.1.1", count=2, interval=60, scan_once=fake_scan,
                        stop=NoWaitEvent()) == 2
    assert len(calls) == 2
    with pytest.raises(ValueError):
        monitor_loop("192.168.1.1", interval=1, scan_once=fake_scan)
