from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ip_analyser.cli import main
from test_packet_filters import tcp_record


class CliPacketTests(unittest.TestCase):
    @patch("ip_analyser.cli.capture_live")
    def test_capture_command_expands_target_and_uses_native_capture(self, capture):
        capture.return_value = Path("capture.pcap")
        self.assertEqual(main(["capture", "192.0.2.1-192.0.2.2",
                               "--interface", "enp1s0", "--port", "443",
                               "--duration", "4", "--max-packets", "20"]), 0)
        capture.assert_called_once_with(["192.0.2.1", "192.0.2.2"],
                                        "enp1s0", 443, 4, 20)

    @patch("ip_analyser.cli.list_capture_interfaces",
           return_value=[("enp1s0", "Network interface")])
    def test_capture_interfaces_command(self, interfaces):
        self.assertEqual(main(["capture-interfaces"]), 0)
        interfaces.assert_called_once_with()

    @patch("ip_analyser.cli.read_capture", return_value=[])
    def test_open_capture_uses_filters_and_limit(self, reader):
        self.assertEqual(main(["open-capture", "sample.pcap", "--host", "192.0.2.1",
                               "--port", "53", "--limit", "12"]), 0)
        reader.assert_called_once_with(Path("sample.pcap"), ["192.0.2.1"], 53, 12)

    @patch("ip_analyser.cli.read_capture")
    def test_open_capture_applies_display_filter(self, reader):
        reader.return_value = [tcp_record(destination_port=80), tcp_record(destination_port=22)]
        with patch("builtins.print") as output:
            self.assertEqual(main(["open-capture", "sample.pcap", "--filter",
                                   "tcp.port == 80"]), 0)
        self.assertIn("Read 1 matching packet", output.call_args_list[-1].args[0])

    @patch("ip_analyser.cli.capture_live")
    def test_capture_can_be_copied_to_requested_output(self, capture):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.pcap"
            output = Path(directory) / "saved.pcap"
            source.write_bytes(b"capture")
            capture.return_value = source
            self.assertEqual(main(["capture", "192.0.2.1", "--output", str(output)]), 0)
            self.assertEqual(output.read_bytes(), b"capture")


if __name__ == "__main__":
    unittest.main()
