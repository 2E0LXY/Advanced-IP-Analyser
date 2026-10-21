import unittest
from unittest.mock import MagicMock, patch

from ip_analyser.local_smart_devices import (
    _hue_snapshot,
    _shelly_snapshot,
    _tasmota_snapshot,
    _tuya_config,
    _tuya_snapshot,
    _wled_snapshot,
    inspect_local_device,
    run_local_action,
    set_local_brightness,
    set_local_power,
)


class LocalSmartDeviceTests(unittest.TestCase):
    def test_tuya_configuration_parses_version_and_datapoints(self):
        self.assertEqual(_tuya_config("3.4,20,22"), (3.4, "20", "22"))
        with self.assertRaisesRegex(ValueError, "Tuya configuration"):
            _tuya_config("4.0,1,3")

    @patch("ip_analyser.local_smart_devices._tuya_status",
           return_value=({"1": True, "3": 650}, 3.3, "1", "3"))
    def test_smart_life_snapshot_maps_common_datapoints(self, _status):
        device = _tuya_snapshot("192.168.1.20", "device-123456", "local-key", "3.3,1,3")

        self.assertEqual(device.provider, "Smart Life / Tuya")
        self.assertTrue(device.is_on)
        self.assertEqual(device.brightness, 65)

    @patch("ip_analyser.local_smart_devices._http_json")
    def test_shelly_gen2_snapshot(self, request):
        request.side_effect = [
            {"id": "shellyplus1-aabb", "model": "SNSW-001X16EU", "mac": "AABB"},
            {"switch:0": {"output": True}, "wifi": {"rssi": -48}},
        ]

        device = _shelly_snapshot("192.168.1.21", "admin", "secret", "0")

        self.assertEqual(device.provider, "Shelly")
        self.assertTrue(device.is_on)
        self.assertEqual(device.signal, -48)

    @patch("ip_analyser.local_smart_devices._http_json")
    def test_tasmota_snapshot(self, request):
        request.return_value = {
            "Status": {"FriendlyName": ["Desk plug"], "Module": "Generic"},
            "StatusSTS": {"POWER": "ON", "Dimmer": 40, "Wifi": {"RSSI": 72}},
        }

        device = _tasmota_snapshot("192.168.1.22", "admin", "secret", "1")

        self.assertEqual(device.alias, "Desk plug")
        self.assertTrue(device.is_on)
        self.assertEqual(device.brightness, 40)

    @patch("ip_analyser.local_smart_devices._http_json")
    def test_wled_snapshot(self, request):
        request.return_value = {
            "state": {"on": True, "bri": 128},
            "info": {"name": "Kitchen strip", "ver": "0.15.0", "wifi": {"rssi": -52}},
        }

        device = _wled_snapshot("wled.local")

        self.assertEqual(device.alias, "Kitchen strip")
        self.assertEqual(device.brightness, 50)

    @patch("ip_analyser.local_smart_devices._http_json")
    def test_philips_hue_snapshot(self, request):
        request.return_value = {"1": {
            "name": "Hall lamp", "productname": "Hue color lamp", "type": "Extended color light",
            "uniqueid": "aa:bb-01", "state": {"on": True, "bri": 127}}}

        device = _hue_snapshot("192.168.1.25", "bridge-key", "1")

        self.assertEqual(device.provider, "Philips Hue")
        self.assertEqual(device.alias, "Hall lamp")
        self.assertEqual(device.brightness, 50)

    @patch("ip_analyser.local_smart_devices.inspect_local_device")
    @patch("ip_analyser.local_smart_devices._http_json")
    def test_wled_power_and_brightness_commands(self, request, inspect):
        inspect.return_value = MagicMock()

        set_local_power("WLED", "192.168.1.23", True)
        set_local_brightness("WLED", "192.168.1.23", 25)

        self.assertEqual(request.call_args_list[0].kwargs["data"], {"on": True})
        self.assertEqual(request.call_args_list[1].kwargs["data"], {"on": True, "bri": 64})

    @patch("ip_analyser.local_smart_devices.inspect_local_device")
    @patch("ip_analyser.local_smart_devices._http_json")
    def test_shelly_advanced_rpc(self, request, inspect):
        inspect.return_value = MagicMock()

        run_local_action(
            "Shelly", "192.168.1.24", "Switch.Toggle", {"id": 0}, "admin", "secret", "0")

        self.assertEqual(request.call_args.args[1], "/rpc/Switch.Toggle")
        self.assertEqual(request.call_args.kwargs["data"], {"id": 0})

    def test_unknown_provider_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            inspect_local_device("Unknown", "192.168.1.30")


if __name__ == "__main__":
    unittest.main()
