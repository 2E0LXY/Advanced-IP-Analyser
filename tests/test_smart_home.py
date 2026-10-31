import unittest
from unittest.mock import AsyncMock, patch

from ip_analyser.smart_home import (
    SmartHomeDevice,
    SmartHomeError,
    discover_devices,
    inspect_network_services,
    inspect_device,
    set_brightness,
    set_power,
)
from ip_analyser.smart_home_gui import SmartHomeView, signal_display


class _Type:
    value = "bulb"


class _Feature:
    def __init__(self, value=None, writable=True):
        self.value = value
        self.attribute_setter = "set" if writable else None
        self.set_value = AsyncMock()


class _Device:
    host = "192.0.2.40"
    alias = "Desk lamp"
    model = "L530"
    device_type = _Type()
    is_on = True
    rssi = -51
    mac = "00:11:22:33:44:55"

    def __init__(self):
        self.features = {"state": _Feature(True), "brightness": _Feature(60)}
        self.update = AsyncMock()
        self.disconnect = AsyncMock()
        self.turn_on = AsyncMock()
        self.turn_off = AsyncMock()


class _Discover:
    discover = AsyncMock()
    discover_single = AsyncMock()


class _KasaError(Exception):
    pass


def _api():
    return object, _Discover, _KasaError


class SmartHomeTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovers_and_snapshots_supported_device(self):
        device = _Device()
        with (patch("ip_analyser.smart_home._kasa_api", side_effect=_api),
              patch.object(_Discover, "discover", AsyncMock(return_value={device.host: device}))):
            found = await discover_devices()

        self.assertEqual(found[0].alias, "Desk lamp")
        self.assertEqual(found[0].brightness, 60)
        self.assertTrue(found[0].can_power)
        device.disconnect.assert_awaited_once()

    async def test_direct_connection_rejects_missing_device(self):
        with (patch("ip_analyser.smart_home._kasa_api", side_effect=_api),
              patch.object(_Discover, "discover_single", AsyncMock(return_value=None)),
              self.assertRaisesRegex(SmartHomeError, "No supported")):
            await inspect_device("192.0.2.99")

    async def test_power_control_updates_and_disconnects(self):
        device = _Device()
        with (patch("ip_analyser.smart_home._kasa_api", side_effect=_api),
              patch.object(_Discover, "discover_single", AsyncMock(return_value=device))):
            result = await set_power(device.host, False)

        device.turn_off.assert_awaited_once()
        self.assertEqual(device.update.await_count, 2)
        device.disconnect.assert_awaited_once()
        self.assertEqual(result.address, device.host)

    async def test_brightness_control_uses_writable_feature(self):
        device = _Device()
        with (patch("ip_analyser.smart_home._kasa_api", side_effect=_api),
              patch.object(_Discover, "discover_single", AsyncMock(return_value=device))):
            await set_brightness(device.host, 35)

        device.features["brightness"].set_value.assert_awaited_once_with(35)
        device.disconnect.assert_awaited_once()

    async def test_credentials_must_be_complete(self):
        with self.assertRaisesRegex(ValueError, "both"):
            await discover_devices("user@example.com", "")

    def test_method_based_power_capability_is_available_without_feature_metadata(self):
        device = _Device()
        device.features = {}
        from ip_analyser.smart_home import _snapshot

        snapshot = _snapshot(device)

        self.assertTrue(snapshot.can_power)
        self.assertTrue(snapshot.can_deactivate)

    @patch("ip_analyser.scanner.Scanner")
    def test_service_inspection_resolves_unnamed_device_and_records_ports(self, scanner_type):
        host = type("Host", (), {
            "address": "192.0.2.40", "hostname": "desk-plug.lan",
            "ports": [80, 9999], "services": ["http", "kasa"],
            "service_info": {"80": {"Page title": "Desk plug"}},
        })()
        scanner_type.return_value.inspect.return_value = host
        scanner_type.return_value.discover.return_value = host
        device = SmartHomeDevice(
            address="192.0.2.40", alias="Unnamed TP-Link device", model="P100",
            kind="Plug", is_on=False, brightness=None, signal=None, mac="",
            can_power=True, can_brightness=False)

        result = inspect_network_services(device)

        self.assertEqual(result.alias, "desk-plug.lan")
        self.assertEqual(result.services, ((80, "http"), (9999, "kasa")))

    def test_service_menu_targets_use_correct_protocol_and_port(self):
        self.assertEqual(
            SmartHomeView._service_target("192.0.2.40", 8443, "https"),
            "https://192.0.2.40:8443")
        self.assertEqual(
            SmartHomeView._service_target("192.0.2.40", 445, "smb"),
            "file://192.0.2.40")
        self.assertIsNone(
            SmartHomeView._service_target("192.0.2.40", 9999, "kasa"))

    def test_signal_bars_cover_dbm_and_percentage_values(self):
        self.assertEqual(signal_display(None), "—")
        self.assertIn("🔴 ▂··· Too weak", signal_display(-85))
        self.assertIn("🟠 ▂▃·· Weak", signal_display(-75))
        self.assertIn("🟡 ▂▃▅· Strong", signal_display(-65))
        self.assertIn("🟢 ▂▃▅▇ Very strong", signal_display(-51))
        self.assertTrue(signal_display(82).endswith("82%"))

    def test_signal_falls_back_to_sys_info_when_direct_rssi_is_missing(self):
        device = _Device()
        device.rssi = None
        device.sys_info = {"rssi": -67}
        from ip_analyser.smart_home import _snapshot

        self.assertEqual(_snapshot(device).signal, -67)


if __name__ == "__main__":
    unittest.main()
