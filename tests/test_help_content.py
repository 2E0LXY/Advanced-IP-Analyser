import unittest

from ip_analyser.help_content import HELP_BY_KEY, HELP_SECTIONS, TAB_HELP


class HelpContentTests(unittest.TestCase):
    def test_every_main_tab_has_a_contextual_guide(self):
        expected_tabs = {
            "dashboard", "network_scan", "smart_home", "system", "disk_usage",
            "dns_benchmark", "connections", "intelligence", "security_posture",
            "diagnostics", "favorites", "wifi_analyzer", "packet_analysis",
            "web_security", "local_ai",
        }
        self.assertEqual(set(TAB_HELP), expected_tabs)
        self.assertTrue(all(help_key in HELP_BY_KEY for help_key in TAB_HELP.values()))

    def test_guides_are_unique_substantial_and_explain_interpretation_or_limits(self):
        self.assertEqual(len(HELP_BY_KEY), len(HELP_SECTIONS))
        for section in HELP_SECTIONS:
            with self.subTest(section=section.key):
                self.assertGreaterEqual(len(section.body), 900)
                self.assertTrue("HOW" in section.body or "SETTINGS" in section.body)
                self.assertTrue("LIMIT" in section.body or "SAFETY" in section.body or
                                "PRIVACY" in section.body)


if __name__ == "__main__":
    unittest.main()
