import json
import unittest

from ip_analyser.ai_analysis import ANALYSIS_MODES, build_analysis_preview
from ip_analyser.models import Host


class AIAnalysisPreviewTests(unittest.TestCase):
    def test_default_preview_removes_identifiers_and_sensitive_fields(self):
        host = Host(
            "192.0.2.10", reachable=True, hostname="private.example", mac="AA:BB:CC:DD:EE:FF",
            manufacturer="Example", services=["https"], ports=[443],
            service_info={"443": {"Server": "Example/1", "Authorization": "Bearer secret",
                                          "Set-Cookie": "session=secret"}})
        history = {"changes": {"new": [{"address": "192.0.2.10", "hostname": "private.example",
                                           "mac": "AA:BB:CC:DD:EE:FF"}]}}
        preview = build_analysis_preview(
            [host], history, mode="Full evidence assessment", provider="Gemini", model="gemini-a")
        self.assertNotIn("192.0.2.10", preview.payload)
        self.assertNotIn("AA:BB:CC:DD:EE:FF", preview.payload)
        self.assertNotIn("private.example", preview.payload)
        self.assertNotIn("Bearer secret", preview.payload)
        self.assertNotIn("session=secret", preview.payload)
        self.assertIn("[removed-sensitive-field]", preview.payload)
        self.assertFalse(json.loads(preview.payload)["privacy"]["raw_packet_payloads_included"])

    def test_identifiers_only_appear_after_explicit_option(self):
        host = Host("192.0.2.10", reachable=True, hostname="private.example",
                    mac="AA:BB:CC:DD:EE:FF")
        preview = build_analysis_preview(
            [host], {}, mode="Device fingerprinting and classification",
            provider="OpenAI", model="gpt-text", include_identifiers=True)
        self.assertIn("192.0.2.10", preview.payload)
        self.assertIn("private.example", preview.payload)

    def test_all_modes_build_bounded_previews(self):
        host = Host("192.0.2.10", reachable=True, services=["ssh"], ports=[22])
        for mode in ANALYSIS_MODES:
            with self.subTest(mode=mode):
                preview = build_analysis_preview(
                    [host], {}, mode=mode, provider="OpenRouter", model="vendor/model",
                    max_chars=4_000)
                self.assertLessEqual(len(preview.payload), 4_000)
                self.assertIn("NETWORK_EVIDENCE", preview.prompt)

    def test_rejects_oversized_question(self):
        with self.assertRaises(ValueError):
            build_analysis_preview(
                [], {}, mode="Natural-language asset search", provider="OpenAI", model="gpt-text",
                question="x" * 2_001)


if __name__ == "__main__":
    unittest.main()
