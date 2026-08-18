from pathlib import Path
import tempfile
import unittest

from ip_analyser.models import Host
from ip_analyser.storage import export, load_favorites, save_favorites


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
