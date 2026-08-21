import subprocess
import unittest
from unittest.mock import patch

from ip_analyser.actions import open_service, preferred_web_service, remote_power, service_url


class WebActionTests(unittest.TestCase):
    def test_https_is_preferred(self):
        self.assertEqual(preferred_web_service(["http", "ssh", "https"]), "https")

    def test_http_fallback_and_missing_service(self):
        self.assertEqual(preferred_web_service(["ssh", "http"]), "http")
        self.assertIsNone(preferred_web_service(["ssh"]))

    def test_ipv4_and_ipv6_urls(self):
        self.assertEqual(service_url("https", "192.0.2.1"), "https://192.0.2.1")
        self.assertEqual(service_url("http", "2001:db8::1"), "http://[2001:db8::1]")
        self.assertEqual(service_url("http", "192.0.2.1", 8080), "http://192.0.2.1:8080")
        self.assertEqual(service_url("https", "2001:db8::1", 8443), "https://[2001:db8::1]:8443")

    @patch("ip_analyser.actions.subprocess.Popen")
    def test_ssh_opener_uses_selected_username_and_port(self, popen):
        open_service("ssh", "192.0.2.20", 2222, username="network-admin")
        popen.assert_called_once_with(
            ["x-terminal-emulator", "-e", "ssh", "-p", "2222", "network-admin@192.0.2.20"])

    def test_ssh_username_rejects_command_options(self):
        with self.assertRaises(ValueError):
            open_service("ssh", "192.0.2.20", username="-oProxyCommand=bad")

    @patch("ip_analyser.actions.shutil.which", return_value="/usr/bin/ssh")
    @patch("ip_analyser.actions.subprocess.run")
    def test_remote_power_uses_noninteractive_argv(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = remote_power("192.0.2.5", "reboot", "admin")
        self.assertTrue(result.succeeded)
        command = run.call_args.args[0]
        self.assertEqual(command[-3:], ["admin@192.0.2.5", "systemctl", "reboot"])
        self.assertIn("BatchMode=yes", command)
