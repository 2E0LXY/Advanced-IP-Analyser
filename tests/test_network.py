import subprocess
import unittest
from unittest.mock import patch

from ip_analyser.network import current_ipv4_subnet


class NetworkTests(unittest.TestCase):
    @patch("ip_analyser.network.subprocess.run")
    def test_current_subnet(self, run):
        run.return_value.stdout = "2: enp1s0    inet 192.168.42.17/24 brd 192.168.42.255 scope global enp1s0\n"
        self.assertEqual(current_ipv4_subnet(), "192.168.42.0/24")

    @patch("ip_analyser.network.subprocess.run")
    def test_missing_interface(self, run):
        run.return_value.stdout = ""
        with self.assertRaisesRegex(RuntimeError, "no active"):
            current_ipv4_subnet()

    @patch("ip_analyser.network.subprocess.run", side_effect=subprocess.CalledProcessError(1, "ip"))
    def test_ip_command_failure(self, _run):
        with self.assertRaisesRegex(RuntimeError, "iproute2"):
            current_ipv4_subnet()
