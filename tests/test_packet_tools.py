from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ip_analyser.packet_tools import (capture_filter, display_filter, launch_live_capture,
                                      list_capture_interfaces, open_capture, validate_interface)


class PacketToolTests(unittest.TestCase):
    def test_capture_filter_supports_multiple_hosts_and_service_port(self):
        self.assertEqual(capture_filter(["192.0.2.1", "2001:db8::1"], 443),
                         "(host 192.0.2.1 or host 2001:db8::1) and tcp port 443")

    def test_display_filter_uses_correct_ipv4_and_ipv6_fields(self):
        self.assertEqual(display_filter(["192.0.2.1", "2001:db8::1"], 443),
                         "tcp.port == 443 && (ip.addr == 192.0.2.1 || ipv6.addr == 2001:db8::1)")

    def test_invalid_host_port_and_interface_are_rejected(self):
        with self.assertRaises(ValueError):
            capture_filter(["not-an-address"])
        with self.assertRaises(ValueError):
            capture_filter(["192.0.2.1"], 65_536)
        with self.assertRaises(ValueError):
            validate_interface("eth0\n-k")

    @patch("ip_analyser.packet_tools.subprocess.run")
    @patch("ip_analyser.packet_tools.shutil.which", return_value="/usr/bin/wireshark")
    def test_capture_interfaces_are_parsed_from_wireshark(self, _which, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "1. enp1s0 (Ethernet)\n2. any (Pseudo-device that captures on all interfaces)\n"
        self.assertEqual(list_capture_interfaces(),
                         [("enp1s0", "Ethernet"),
                          ("any", "Pseudo-device that captures on all interfaces")])

    @patch("ip_analyser.packet_tools.subprocess.Popen")
    @patch("ip_analyser.packet_tools.shutil.which", return_value="/usr/bin/wireshark")
    def test_live_capture_uses_fixed_argument_vector(self, _which, popen):
        launch_live_capture(["192.0.2.5"], "enp1s0", 22)
        popen.assert_called_once_with(
            ["/usr/bin/wireshark", "-i", "enp1s0", "-f",
             "host 192.0.2.5 and tcp port 22", "-k"])

    @patch("ip_analyser.packet_tools.subprocess.Popen")
    @patch("ip_analyser.packet_tools.shutil.which", return_value="/usr/bin/wireshark")
    def test_saved_capture_opens_with_generated_display_filter(self, _which, popen):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcapng"
            path.write_bytes(b"test capture")
            open_capture(path, ["192.0.2.5"])
            popen.assert_called_once_with(
                ["/usr/bin/wireshark", "-r", str(path.resolve()), "-Y", "ip.addr == 192.0.2.5"])


if __name__ == "__main__":
    unittest.main()
