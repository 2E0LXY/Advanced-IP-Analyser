from pathlib import Path
import tempfile
import unittest

from ip_analyser.models import Host
from ip_analyser.storage import export, import_inventory, load_favorites, merge_devices, save_favorites


class StorageTests(unittest.TestCase):
    def test_favorites_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "favorites.json"
            expected = [Host("192.0.2.1", reachable=True, services=["ssh"])]
            save_favorites(path, expected)
            actual = load_favorites(path)
            self.assertEqual(actual[0].to_dict(), expected[0].to_dict())

    def test_html_export_escapes_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            export(path, [Host("192.0.2.1", hostname="<script>")])
            self.assertNotIn("<script>", path.read_text())
            self.assertIn("&lt;script&gt;", path.read_text())
            self.assertIn("Manufacturer", path.read_text())

    def test_xml_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.xml"
            expected = Host("192.0.2.2", reachable=True, latency_ms=3.5,
                            mac="AA:BB:CC:DD:EE:FF", services=["ssh", "https"], ports=[22, 443],
                            service_info={"22": {"Banner": "SSH-2.0-OpenSSH_9.2"},
                                          "443": {"Server": "Apache/2.4", "Status": "200 OK"}},
                            note="server")
            export(path, [expected])
            actual = import_inventory(path)
            self.assertEqual(actual[0].to_dict(), expected.to_dict())

    def test_merge_tracks_device_by_mac_and_retains_note(self):
        saved = Host("192.0.2.2", mac="AA:BB:CC:DD:EE:FF", note="router")
        observed = Host("192.0.2.20", reachable=True, mac="AA:BB:CC:DD:EE:FF", services=["https"])
        merged = merge_devices([saved], [observed])
        self.assertEqual((merged[0].address, merged[0].note, merged[0].services),
                         ("192.0.2.20", "router", ["https"]))
