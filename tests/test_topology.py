import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from ip_analyser.models import Host
from ip_analyser.topology import export_topology


class TopologyTests(unittest.TestCase):
    def test_export_is_valid_svg_with_escaped_host_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.svg"
            export_topology(path, "192.0.2.0/24", [Host("192.0.2.7", hostname="A&B <server>")])
            root = ET.parse(path).getroot()
            self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
            self.assertIn("A&B <server>", " ".join(node.text or "" for node in root.iter()))


if __name__ == "__main__":
    unittest.main()
