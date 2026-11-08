import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from ip_analyser.models import Host
from ip_analyser.network_intelligence import (
    analyse_hosts,
    export_graphml,
    export_intelligence_json,
    filter_insights,
    resolve_entities,
)


def sample_hosts():
    return [
        Host("192.168.1.10", True, "server", mac="AA:BB:CC:DD:EE:01",
             manufacturer="Example", services=["telnet", "https", "smb"], ports=[23, 443, 445]),
        Host("192.168.1.11", True, "camera", mac="AA:BB:CC:DD:EE:02",
             manufacturer="CamCo", device_type="Camera", services=["http"], ports=[80]),
        Host("192.168.1.12", True, "server", mac="AA:BB:CC:DD:EE:01",
             manufacturer="Example", services=["ssh"], ports=[22]),
    ]


class NetworkIntelligenceTests(unittest.TestCase):
    def test_entity_resolution_prefers_exact_hardware_identity(self):
        groups = resolve_entities(sample_hosts())
        duplicate = next(group for group in groups if group.canonical.mac.endswith("01"))
        self.assertEqual(len(groups), 2)
        self.assertEqual(duplicate.duplicate_count, 1)
        self.assertEqual(duplicate.match_reason, "same hardware address")
        self.assertEqual(duplicate.canonical.address, "192.168.1.12")
        self.assertEqual(duplicate.canonical.ports, [22, 23, 443, 445])

    def test_reused_ip_does_not_merge_conflicting_hardware(self):
        first = Host("192.168.1.20", mac="AA:BB:CC:DD:EE:10")
        second = Host("192.168.1.20", mac="AA:BB:CC:DD:EE:11")
        self.assertEqual(len(resolve_entities([first, second])), 2)

    def test_risk_is_explainable_and_zones_are_deterministic(self):
        insights = analyse_hosts(sample_hosts())
        server = next(item for item in insights if item.host.mac.endswith("01"))
        camera = next(item for item in insights if item.host.mac.endswith("02"))
        self.assertGreater(server.risk_score, 0)
        self.assertTrue(server.factors)
        self.assertEqual(camera.zone, "IoT")

    def test_query_supports_fields_cidr_risk_negation_and_or(self):
        insights = analyse_hosts(sample_hosts())
        self.assertEqual(len(filter_insights(insights, "zone:iot")), 1)
        self.assertEqual(len(filter_insights(insights, "ip:192.168.1.0/24 -zone:iot")), 1)
        self.assertEqual(len(filter_insights(insights, "port:22 OR type:camera")), 2)
        self.assertEqual(filter_insights(insights, "risk:>=0"), insights)
        with self.assertRaises(ValueError):
            filter_insights(insights, 'name:"unfinished')

    def test_exports_are_structured_and_parseable(self):
        insights = analyse_hosts(sample_hosts())
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "intelligence.json"
            graph_path = Path(directory) / "network.graphml"
            export_intelligence_json(json_path, insights, "risk:>=0")
            export_graphml(graph_path, insights)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["format"], "advanced-ip-analyser-intelligence")
            self.assertEqual(payload["query"], "risk:>=0")
            self.assertEqual(len(payload["devices"]), 2)
            ET.parse(graph_path)


if __name__ == "__main__":
    unittest.main()
