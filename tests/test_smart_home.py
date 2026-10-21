import unittest
from unittest.mock import AsyncMock, patch

from ip_analyser.smart_home import (
    SmartHomeError,
    discover_devices,
    inspect_device,
    set_brightness,
    set_power,
)


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


if __name__ == "__main__":
    unittest.main()
