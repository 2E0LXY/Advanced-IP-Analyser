import subprocess
import unittest
from unittest.mock import patch

from ip_analyser.network import active_ipv4_networks, broadcasts_for_host, current_ipv4_subnet, ipv4_24_target


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

    @patch("ip_analyser.network.subprocess.run")
    def test_active_networks_include_broadcast(self, run):
        run.return_value.stdout = "2: enp1s0    inet 192.168.42.17/24 brd 192.168.42.255 scope global enp1s0\n"
        self.assertEqual(active_ipv4_networks(), [("enp1s0", "192.168.42.0/24", "192.168.42.255")])

    @patch("ip_analyser.network.subprocess.run", side_effect=subprocess.CalledProcessError(1, "ip"))
    def test_ip_command_failure(self, _run):
        with self.assertRaisesRegex(RuntimeError, "iproute2"):
            current_ipv4_subnet()

    def test_ipv4_24_shortcut(self):
        self.assertEqual(ipv4_24_target("192.168.42.17"), "192.168.42.0/24")
        self.assertEqual(ipv4_24_target("192.168.42.17/20"), "192.168.42.0/24")

    def test_wake_broadcast_prefers_matching_interface(self):
        networks = [("lan0", "192.168.42.0/24", "192.168.42.255"),
                    ("vpn0", "10.0.0.0/24", "10.0.0.255")]
        self.assertEqual(broadcasts_for_host("192.168.42.20", networks), ["192.168.42.255"])
