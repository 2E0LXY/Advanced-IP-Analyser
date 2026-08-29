import os
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from ip_analyser.capture_helper import _matches, _open_output, main


def udp_frame() -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    udp = struct.pack("!HHHH", 5353, 53, 8, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 17, 0,
                     socket.inet_aton("192.0.2.1"), socket.inet_aton("198.51.100.2"))
    return ethernet + ip + udp


class CaptureHelperTests(unittest.TestCase):
    def test_packet_matching_is_bounded_to_selected_host_and_port(self):
        frame = udp_frame()
        self.assertTrue(_matches(frame, {"192.0.2.1"}, 53))
        self.assertFalse(_matches(frame, {"203.0.113.1"}, 53))
        self.assertFalse(_matches(frame, {"192.0.2.1"}, 443))

    def test_secure_output_open_truncates_after_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture.pcap"
            output.write_bytes(b"old")
            descriptor = _open_output(output)
            try:
                self.assertEqual(os.fstat(descriptor).st_size, 0)
            finally:
                os.close(descriptor)

    def test_invalid_interface_is_rejected_before_capture(self):
        self.assertEqual(main(["--output", str(Path.cwd() / "capture.pcap"),
                               "--interface", "bad/interface",
                               "--host", "192.0.2.1", "--duration", "1",
                               "--max-packets", "1"]), 2)


if __name__ == "__main__":
    unittest.main()
