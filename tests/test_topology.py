import tempfile
import unittest
from pathlib import Path

from PIL import Image

from ip_analyser.models import Host
from ip_analyser.topology import export_topology


class TopologyTests(unittest.TestCase):
    def test_export_is_valid_png_with_expected_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.png"
            export_topology(path, "192.0.2.0/24", [
                Host("192.0.2.7", hostname="A&B <server>", ports=[22, 443]),
            ])

            self.assertEqual(path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
            with Image.open(path) as image:
                self.assertEqual(image.format, "PNG")
                self.assertEqual(image.mode, "RGB")
                self.assertEqual(image.size, (1200, 282))
                self.assertNotEqual(image.getpixel((0, 0)), image.getpixel((50, 200)))


if __name__ == "__main__":
    unittest.main()
