import unittest
from unittest.mock import patch

from ip_analyser.cli import main


class CliPacketTests(unittest.TestCase):
    @patch("ip_analyser.cli.launch_live_capture")
    def test_capture_command_expands_target_and_launches_wireshark(self, launch):
        self.assertEqual(main(["capture", "192.0.2.1-192.0.2.2",
                               "--interface", "enp1s0", "--port", "443"]), 0)
        launch.assert_called_once_with(["192.0.2.1", "192.0.2.2"], "enp1s0", 443)

    @patch("ip_analyser.cli.list_capture_interfaces",
           return_value=[("enp1s0", "Ethernet")])
    def test_capture_interfaces_command(self, interfaces):
        self.assertEqual(main(["capture-interfaces"]), 0)
        interfaces.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
