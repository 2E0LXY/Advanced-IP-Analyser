import os
import unittest
from unittest.mock import patch

from ip_analyser import windows_settings
from ip_analyser.windows_settings import (
    ETHERNET_SETTINGS_URI,
    WIFI_SETTINGS_URI,
    dns_settings_uri,
)


class WindowsSettingsTests(unittest.TestCase):
    def test_dns_settings_uri_selects_wifi_for_wifi_aliases(self) -> None:
        self.assertEqual(dns_settings_uri(["Wi-Fi"]), WIFI_SETTINGS_URI)
        self.assertEqual(dns_settings_uri(["Wireless LAN adapter"]), WIFI_SETTINGS_URI)
        self.assertEqual(dns_settings_uri(["wlan0"]), WIFI_SETTINGS_URI)

    def test_dns_settings_uri_defaults_to_ethernet(self) -> None:
        self.assertEqual(
            dns_settings_uri(["Ethernet", "vEthernet (Default Switch)"]),
            ETHERNET_SETTINGS_URI,
        )
        self.assertEqual(dns_settings_uri([]), ETHERNET_SETTINGS_URI)

    @unittest.skipUnless(os.name == "nt", "Windows Settings URI launch is Windows-only")
    @patch.object(
        windows_settings,
        "active_ipv4_networks",
        return_value=[("Wi-Fi", "192.0.2.0/24", "192.0.2.255")],
    )
    def test_open_windows_dns_settings_uses_launcher_without_changing_settings(
            self, _networks) -> None:
        launched: list[str] = []
        uri = windows_settings.open_windows_dns_settings(launched.append)
        self.assertEqual(uri, WIFI_SETTINGS_URI)
        self.assertEqual(launched, [WIFI_SETTINGS_URI])


if __name__ == "__main__":
    unittest.main()
