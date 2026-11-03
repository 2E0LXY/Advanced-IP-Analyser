import os

import pytest

from ip_analyser import windows_settings
from ip_analyser.windows_settings import (
    ETHERNET_SETTINGS_URI,
    WIFI_SETTINGS_URI,
    dns_settings_uri,
)


def test_dns_settings_uri_selects_wifi_for_wifi_aliases() -> None:
    assert dns_settings_uri(["Wi-Fi"]) == WIFI_SETTINGS_URI
    assert dns_settings_uri(["Wireless LAN adapter"]) == WIFI_SETTINGS_URI
    assert dns_settings_uri(["wlan0"]) == WIFI_SETTINGS_URI


def test_dns_settings_uri_defaults_to_ethernet() -> None:
    assert dns_settings_uri(["Ethernet", "vEthernet (Default Switch)"]) == ETHERNET_SETTINGS_URI
    assert dns_settings_uri([]) == ETHERNET_SETTINGS_URI


@pytest.mark.skipif(os.name != "nt", reason="Windows Settings URI launch is Windows-only")
def test_open_windows_dns_settings_uses_launcher_without_changing_settings(monkeypatch) -> None:
    launched: list[str] = []
    monkeypatch.setattr(
        windows_settings,
        "active_ipv4_networks",
        lambda: [("Wi-Fi", "192.0.2.0/24", "192.0.2.255")],
    )

    uri = windows_settings.open_windows_dns_settings(launched.append)

    assert uri == WIFI_SETTINGS_URI
    assert launched == [WIFI_SETTINGS_URI]
