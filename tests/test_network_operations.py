from pathlib import Path
from datetime import datetime

import pytest

from ip_analyser.network_operations import (
    MonitorPolicy,
    NeighborEntry,
    build_snmp_request,
    find_address_conflicts,
    load_monitor_policy,
    match_kev,
    parse_neighbor_table,
    policy_in_quiet_hours,
    save_monitor_policy,
    selected_policy_changes,
)


def test_neighbor_parser_accepts_windows_and_linux_formats() -> None:
    windows = """Interface: 192.168.1.2 --- 0x8
      192.168.1.1          94-83-c4-c3-de-4b     dynamic
    """
    linux = "192.168.1.5 dev eth0 lladdr b0:b3:53:01:3d:93 REACHABLE"
    entries = parse_neighbor_table(windows + linux)
    assert entries == [
        NeighborEntry("192.168.1.1", "94:83:C4:C3:DE:4B", "dynamic", "192.168.1.2"),
        NeighborEntry("192.168.1.5", "B0:B3:53:01:3D:93", "REACHABLE", "eth0"),
    ]


def test_conflicts_distinguish_duplicate_ip_from_address_movement() -> None:
    entries = [
        NeighborEntry("192.168.1.10", "00:11:22:33:44:55"),
        NeighborEntry("192.168.1.10", "AA:BB:CC:DD:EE:FF"),
        NeighborEntry("192.168.1.11", "00:11:22:33:44:55"),
        NeighborEntry("192.168.1.12", "00:11:22:33:44:55"),
        NeighborEntry("192.168.1.13", "00:11:22:33:44:55"),
    ]
    findings = find_address_conflicts(entries)
    assert {finding.category for finding in findings} == {"Duplicate IP", "Address movement"}


def test_monitor_policy_round_trip_and_validation(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    policy = MonitorPolicy(enabled=True, interval_minutes=5, webhook_url="https://example.test/hook")
    save_monitor_policy(policy, path)
    assert load_monitor_policy(path) == policy
    with pytest.raises(ValueError, match="HTTPS"):
        save_monitor_policy(MonitorPolicy(webhook_url="http://example.test"), path)


def test_policy_quiet_hours_and_selected_changes() -> None:
    policy = MonitorPolicy(quiet_start="22:00", quiet_end="07:00", notify_missing_devices=False)
    assert policy_in_quiet_hours(policy, datetime(2026, 1, 1, 23, 0))
    assert policy_in_quiet_hours(policy, datetime(2026, 1, 1, 6, 30))
    assert not policy_in_quiet_hours(policy, datetime(2026, 1, 1, 12, 0))
    changes = selected_policy_changes(policy, {
        "new": [{"address": "192.0.2.1"}],
        "missing": [{"address": "192.0.2.2"}],
        "changed": [{"fields": ["hostname"]}, {"fields": ["ports"]}],
    })
    assert set(changes) == {"new", "port_changes"}


def test_snmp_request_is_bounded_ber_message() -> None:
    request = build_snmp_request("public", "1.3.6.1.2.1.1.5.0", 123)
    assert request.startswith(b"\x30")
    assert b"public" in request
    assert len(request) < 256
    with pytest.raises(ValueError):
        build_snmp_request("", "1.3.6.1.2.1.1.5.0", 123)


def test_kev_matching_requires_all_terms_and_returns_evidence() -> None:
    catalogue = {"vulnerabilities": [
        {"cveID": "CVE-2026-0001", "vendorProject": "Example", "product": "Router Pro",
         "vulnerabilityName": "Example Router issue", "requiredAction": "Apply updates"},
        {"cveID": "CVE-2026-0002", "vendorProject": "Another", "product": "Camera"},
    ]}
    matches = match_kev(catalogue, ["example", "router"])
    assert [item["cveID"] for item in matches] == ["CVE-2026-0001"]
    assert match_kev(catalogue, ["unknown"]) == []
