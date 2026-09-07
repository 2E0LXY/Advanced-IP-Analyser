import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ip_analyser.wifi_tools import (AccessPoint, WifiClient, _pkexec_command,
                                    analyze_wifi_capture, rogue_wifi_indicators,
                                    save_wifi_report)


AP = bytes.fromhex("001122334455")
CLIENT = bytes.fromhex("66778899aabb")
BROADCAST = b"\xff" * 6


def radiotap(frame: bytes, signal: int = -42) -> bytes:
    return struct.pack("<BBHIb", 0, 0, 9, 1 << 5, signal) + frame


def wifi_header(control: int, address1: bytes, address2: bytes, address3: bytes) -> bytes:
    return struct.pack("<HH", control, 0) + address1 + address2 + address3 + b"\x00\x00"


def capture_bytes(frames: list[bytes]) -> bytes:
    result = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 1024, 127))
    for index, frame in enumerate(frames):
        result.extend(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)))
        result.extend(frame)
    return bytes(result)


class WifiToolTests(unittest.TestCase):
    def test_passive_beacon_probe_client_and_eapol_analysis(self):
        fixed = b"\x00" * 8 + struct.pack("<HH", 100, 0x10)
        rsn = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x08"
        tags = b"\x00\x07TestNet\x03\x01\x06" + bytes((48, len(rsn))) + rsn
        beacon = wifi_header(0x0080, BROADCAST, AP, AP) + fixed + tags
        probe = wifi_header(0x0040, BROADCAST, CLIENT, BROADCAST) + b"\x00\x04Cafe"
        eapol = (wifi_header(0x0108, AP, CLIENT, BROADCAST) +
                 b"\xaa\xaa\x03\x00\x00\x00\x88\x8e\x02\x03")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wifi.pcap"
            path.write_bytes(capture_bytes([radiotap(beacon), radiotap(probe, -51),
                                            radiotap(eapol, -49)]))
            aps, unlinked = analyze_wifi_capture(path)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].name, "TestNet")
        self.assertEqual(aps[0].channel, 6)
        self.assertEqual(aps[0].security, "WPA3")
        self.assertEqual(aps[0].signal_dbm, -42)
        self.assertTrue(aps[0].handshake_seen)
        self.assertEqual(unlinked, [])
        self.assertEqual(aps[0].clients["66:77:88:99:AA:BB"].probes, {"Cafe"})

    def test_rejects_wrong_link_type_and_oversized_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.pcap"
            path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 1024, 1))
            with self.assertRaisesRegex(ValueError, "radiotap"):
                analyze_wifi_capture(path)
            path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 1024, 127) +
                             struct.pack("<IIII", 1, 0, 300_000, 300_000))
            with self.assertRaisesRegex(ValueError, "safe capture"):
                analyze_wifi_capture(path)

    def test_json_report_serializes_sets_and_nested_clients(self):
        client = WifiClient("66:77:88:99:AA:BB", "00:11:22:33:44:55", probes={"Cafe"})
        ap = AccessPoint("00:11:22:33:44:55", name="Test", clients={client.mac: client})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            save_wifi_report(path, [ap], [])
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["access_points"][0]["clients"][0]["probes"], ["Cafe"])

    def test_conflicting_same_ssid_security_is_an_indicator_not_a_verdict(self):
        aps = [AccessPoint("00:11:22:33:44:55", name="Office", security="WPA3"),
               AccessPoint("00:11:22:33:44:66", name="Office", security="Open")]
        self.assertEqual(rogue_wifi_indicators(aps), 2)
        self.assertIn("verify", aps[0].indicators[0].casefold())

    @patch("ip_analyser.wifi_tools.shutil.which", return_value="/usr/bin/pkexec")
    @patch("ip_analyser.wifi_tools.os.name", "posix")
    @patch("ip_analyser.wifi_tools._helper_path")
    def test_helper_uses_fixed_validated_arguments(self, helper, _which):
        helper.return_value.stat.return_value = type(
            "Metadata", (), {"st_uid": 0, "st_mode": 0o100644})()
        command = _pkexec_command("hop", "aia2mon", [1, 6, 11], 300)
        self.assertEqual(command[-2:], ["--channels", "1,6,11"])
        self.assertNotIn(";", " ".join(command))
        with self.assertRaises(ValueError):
            _pkexec_command("hop", "wlan0;rm", [1], 300)


if __name__ == "__main__":
    unittest.main()
