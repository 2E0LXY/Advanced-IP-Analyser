import gzip
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ip_analyser.packet_tools import (PacketRecord, capture_live, list_capture_interfaces,
                                      packet_hex_preview, read_capture,
                                      validate_interface)


def tcp_frame(source="192.0.2.5", destination="198.51.100.7",
              source_port=4242, destination_port=443) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    tcp = struct.pack("!HHLLBBHHH", source_port, destination_port, 1, 0,
                      0x50, 0x12, 8192, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0,
                     64, 6, 0, socket.inet_aton(source), socket.inet_aton(destination))
    return ethernet + ip + tcp


def pcap_bytes(frame: bytes) -> bytes:
    return (struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) +
            struct.pack("<IIII", 1_700_000_000, 125_000, len(frame), len(frame)) + frame)


def pcapng_bytes(frame: bytes) -> bytes:
    section_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    section = struct.pack("<II", 0x0A0D0D0A, 28) + section_body + struct.pack("<I", 28)
    interface_body = struct.pack("<HHI", 1, 0, 65535)
    interface = struct.pack("<II", 1, 20) + interface_body + struct.pack("<I", 20)
    padding = b"\x00" * ((4 - len(frame) % 4) % 4)
    packet_body = struct.pack("<IIIII", 0, 0, 1_700_000_000,
                              len(frame), len(frame)) + frame + padding
    packet_length = 12 + len(packet_body)
    packet = (struct.pack("<II", 6, packet_length) + packet_body +
              struct.pack("<I", packet_length))
    return section + interface + packet


class PacketToolTests(unittest.TestCase):
    def test_reads_and_filters_ethernet_ipv4_tcp_pcap(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcap"
            capture.write_bytes(pcap_bytes(tcp_frame()))
            records = read_capture(capture, ["192.0.2.5"], 443)
        self.assertEqual(len(records), 1)
        self.assertEqual((records[0].source, records[0].destination),
                         ("192.0.2.5", "198.51.100.7"))
        self.assertEqual((records[0].source_port, records[0].destination_port),
                         (4242, 443))
        self.assertEqual(records[0].protocol, "TCP")
        self.assertEqual(records[0].info, "SYN,ACK")

    def test_host_and_port_filter_can_exclude_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcap"
            capture.write_bytes(pcap_bytes(tcp_frame()))
            self.assertEqual(read_capture(capture, ["203.0.113.9"]), [])
            self.assertEqual(read_capture(capture, ["192.0.2.5"], 22), [])

    def test_reads_gzip_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcap.gz"
            with gzip.open(capture, "wb") as stream:
                stream.write(pcap_bytes(tcp_frame()))
            self.assertEqual(len(read_capture(capture)), 1)

    def test_reads_pcapng_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcapng"
            capture.write_bytes(pcapng_bytes(tcp_frame()))
            records = read_capture(capture, ["198.51.100.7"])
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].protocol, "TCP")

    def test_rejects_invalid_inputs_and_malformed_capture(self):
        with self.assertRaises(ValueError):
            validate_interface("eth0\n--option")
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "bad.pcap"
            capture.write_bytes(b"not a capture")
            with self.assertRaisesRegex(ValueError, "supported PCAP"):
                read_capture(capture)
            with self.assertRaisesRegex(ValueError, "requires at least one host"):
                read_capture(capture, port=443)

    @patch("ip_analyser.packet_tools.socket.if_nameindex",
           return_value=[(1, "lo"), (2, "enp1s0")])
    def test_lists_native_linux_interfaces(self, _interfaces):
        self.assertEqual(list_capture_interfaces(), [
            ("any", "All Linux interfaces"), ("lo", "Loopback"),
            ("enp1s0", "Network interface")])

    def test_hex_preview_is_bounded_and_readable(self):
        record = PacketRecord(1, 0, "a", "b", "Other", None, None, 3, "", b"A\x00B")
        self.assertIn("41 00 42", packet_hex_preview(record))
        self.assertIn("A.B", packet_hex_preview(record))
        invalid = PacketRecord(2, float("inf"), "a", "b", "Other",
                               None, None, 0, "", b"")
        self.assertEqual(invalid.time_text, "invalid time")

    @patch("ip_analyser.packet_tools.subprocess.run")
    def test_live_capture_uses_validated_fixed_arguments(self, run):
        def complete(command, **_kwargs):
            output = Path(command[command.index("--output") + 1])
            output.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4,
                                           0, 0, 65535, 1))
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        run.side_effect = complete
        with tempfile.TemporaryDirectory() as directory:
            output = capture_live(["192.0.2.5"], "enp1s0", 443, 2, 10,
                                  Path(directory))
            self.assertTrue(output.is_file())
        command = run.call_args.args[0]
        self.assertIn("--interface", command)
        self.assertIn("enp1s0", command)
        self.assertEqual(command[-4:], ["--host", "192.0.2.5", "--port", "443"])

    def test_live_capture_limits_are_validated_before_launch(self):
        with self.assertRaisesRegex(ValueError, "duration"):
            capture_live(["192.0.2.5"], duration=0)
        with self.assertRaisesRegex(ValueError, "packet limit"):
            capture_live(["192.0.2.5"], max_packets=100_001)


if __name__ == "__main__":
    unittest.main()
