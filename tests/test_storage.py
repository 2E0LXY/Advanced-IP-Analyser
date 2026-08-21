from pathlib import Path
import tempfile
import unittest

from ip_analyser.models import Host
from ip_analyser.storage import export, import_inventory, load_favorites, merge_devices, save_favorites


class StorageTests(unittest.TestCase):
    def test_favorites_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "favorites.json"
            expected = [Host("192.0.2.1", reachable=True, services=["ssh"], ports=[22])]
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

    def test_csv_export_neutralizes_spreadsheet_formulas(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.csv"
            export(path, [Host("192.0.2.1", hostname="=HYPERLINK(\"https://bad\")", note="+cmd")])
            content = path.read_text(encoding="utf-8")
            self.assertIn("'=HYPERLINK", content)
            self.assertIn("'+cmd", content)

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

    def test_merge_collapses_duplicate_observations_by_address(self):
        observed = [Host("192.0.2.20", hostname="first"),
                    Host("192.0.2.20", hostname="second")]
        merged = merge_devices([], observed)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].hostname, "second")

    def test_import_rejects_invalid_device_types_and_xml_entities(self):
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "invalid.json"
            invalid.write_text('[{"address": "not-an-ip", "services": "ssh"}]', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "address"):
                import_inventory(invalid)

            xml = Path(directory) / "invalid.xml"
            xml.write_text('<!DOCTYPE x [<!ENTITY x "bad">]><advanced-ip-analyser format="1"/>', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "entities"):
                import_inventory(xml)

    def test_mac_identity_is_normalized_across_separator_styles(self):
        self.assertEqual(Host("192.0.2.1", mac="AA-BB-CC-DD-EE-FF").identity,
                         Host("192.0.2.2", mac="aa:bb:cc:dd:ee:ff").identity)

    def test_merge_accepts_equivalent_mac_separator_styles(self):
        saved = Host("192.0.2.1", mac="AA-BB-CC-DD-EE-FF", note="switch")
        observed = Host("192.0.2.2", mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(merge_devices([saved], [observed])[0].note, "switch")

    def test_import_rejects_non_object_device(self):
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "invalid.json"
            invalid.write_text('["not-a-device"]', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "object"):
                import_inventory(invalid)
