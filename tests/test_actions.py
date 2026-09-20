import subprocess
import unittest
from unittest.mock import patch

from ip_analyser.actions import (
    CREATE_NEW_CONSOLE,
    CREATE_NO_WINDOW,
    open_network_tool,
    open_service,
    preferred_web_service,
    remote_power,
    service_url,
)


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
    @patch("ip_analyser.actions.os.name", "posix")
    def test_ssh_opener_uses_selected_username_and_port(self, popen):
        open_service("ssh", "192.0.2.20", 2222, username="network-admin")
        popen.assert_called_once_with(
            ["x-terminal-emulator", "-e", "ssh", "-p", "2222", "--", "network-admin@192.0.2.20"])

    def test_ssh_username_rejects_command_options(self):
        with self.assertRaises(ValueError):
            open_service("ssh", "192.0.2.20", username="-oProxyCommand=bad")

    def test_service_opener_rejects_untrusted_host_and_port(self):
        with self.assertRaises(ValueError):
            open_service("ssh", "host & calc.exe")
        with self.assertRaises(ValueError):
            open_service("rdp", "192.0.2.20", 70_000)

    @patch("ip_analyser.actions.shutil.which", return_value="/usr/bin/ssh")
    @patch("ip_analyser.actions.subprocess.run")
    def test_remote_power_uses_noninteractive_argv(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = remote_power("192.0.2.5", "reboot", "admin")
        self.assertTrue(result.succeeded)
        command = run.call_args.args[0]
        self.assertEqual(command[-6:], ["admin@192.0.2.5", "sudo", "-n", "shutdown", "-r", "+1"])
        self.assertIn("BatchMode=yes", command)
        self.assertEqual(command[-7], "--")

    @patch("ip_analyser.actions.os.name", "nt")
    @patch("ip_analyser.actions.shutil.which", return_value=r"C:\Windows\System32\OpenSSH\ssh.exe")
    @patch("ip_analyser.actions.subprocess.run")
    def test_windows_remote_power_captures_ssh_without_console(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(remote_power("192.0.2.5", "reboot", "admin").succeeded)
        self.assertEqual(run.call_args.kwargs["creationflags"], CREATE_NO_WINDOW)

    @patch("ip_analyser.actions.shutil.which", return_value="/usr/bin/ssh")
    def test_remote_power_rejects_ssh_option_in_username(self, _which):
        with self.assertRaises(ValueError):
            remote_power("192.0.2.5", "reboot", "-oProxyCommand=touch_bad")

    @patch("ip_analyser.actions.shutil.which", return_value="/usr/bin/ssh")
    @patch("ip_analyser.actions.subprocess.run")
    def test_remote_power_cancel_uses_shutdown_cancel(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = remote_power("192.0.2.5", "cancel", "admin")
        self.assertTrue(result.succeeded)
        self.assertEqual(run.call_args.args[0][-5:],
                         ["admin@192.0.2.5", "sudo", "-n", "shutdown", "-c"])

    @patch("ip_analyser.actions.subprocess.Popen")
    @patch("ip_analyser.actions.shutil.which")
    @patch("ip_analyser.actions.os.name", "posix")
    def test_ping_tool_uses_fixed_argument_vector(self, which, popen):
        which.side_effect = lambda name: f"/usr/bin/{name}"
        open_network_tool("ping", "192.0.2.20")
        popen.assert_called_once_with(
            ["/usr/bin/x-terminal-emulator", "-e", "/usr/bin/ping", "-c", "4", "192.0.2.20"])

    @patch("ip_analyser.actions.subprocess.Popen")
    @patch("ip_analyser.actions.os.name", "nt")
    def test_windows_trace_uses_fixed_argument_vector(self, popen):
        open_network_tool("trace", "192.0.2.20")
        popen.assert_called_once_with(
            ["cmd.exe", "/k", "tracert.exe", "-d", "192.0.2.20"],
            creationflags=CREATE_NEW_CONSOLE)

    @patch("ip_analyser.actions.subprocess.Popen")
    @patch("ip_analyser.actions.shutil.which", return_value=r"C:\Windows\System32\telnet.exe")
    @patch("ip_analyser.actions.os.name", "nt")
    def test_windows_telnet_uses_validated_fixed_arguments(self, _which, popen):
        open_service("telnet", "192.0.2.20", 2323)
        popen.assert_called_once_with(
            ["cmd.exe", "/k", r"C:\Windows\System32\telnet.exe", "192.0.2.20", "2323"],
            creationflags=CREATE_NEW_CONSOLE)
