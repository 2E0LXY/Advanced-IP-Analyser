import unittest

from ip_analyser.actions import preferred_web_service, service_url


class WebActionTests(unittest.TestCase):
    def test_https_is_preferred(self):
        self.assertEqual(preferred_web_service(["http", "ssh", "https"]), "https")

    def test_http_fallback_and_missing_service(self):
        self.assertEqual(preferred_web_service(["ssh", "http"]), "http")
        self.assertIsNone(preferred_web_service(["ssh"]))

    def test_ipv4_and_ipv6_urls(self):
        self.assertEqual(service_url("https", "192.0.2.1"), "https://192.0.2.1")
        self.assertEqual(service_url("http", "2001:db8::1"), "http://[2001:db8::1]")
