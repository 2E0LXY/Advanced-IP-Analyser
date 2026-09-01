import socket
import struct
import tempfile
import unittest
from pathlib import Path

from ip_analyser.packet_filters import (FilterSyntaxError, compile_filter, load_saved_filters,
                                        packet_fields, save_saved_filters)
from ip_analyser.packet_tools import PacketRecord


def ipv4_frame(protocol: int, payload: bytes, source: str = "192.168.1.10",
               destination: str = "8.8.8.8") -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, protocol, 0,
                     socket.inet_aton(source), socket.inet_aton(destination))
    return ethernet + ip + payload


def tcp_record(payload: bytes = b"", source_port: int = 54132, destination_port: int = 80,
               flags: int = 0x02, number: int = 1) -> PacketRecord:
    tcp = struct.pack("!HHLLBBHHH", source_port, destination_port, 1, 0,
                      0x50, flags, 8192, 0, 0) + payload
    frame = ipv4_frame(6, tcp)
    return PacketRecord(number, 0, "192.168.1.10", "8.8.8.8", "TCP", source_port,
                        destination_port, len(frame), "", frame)


def udp_dns_record(response: bool = False) -> PacketRecord:
    name = b"\x06google\x03com\x00"
    dns = struct.pack("!HHHHHH", 0x1234, 0x8180 if response else 0x0100,
                      1, 1 if response else 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 53532, 53, 8 + len(dns), 0) + dns
    frame = ipv4_frame(17, udp)
    return PacketRecord(2, 0, "192.168.1.10", "8.8.8.8", "DNS", 53532, 53,
                        len(frame), "", frame)


class PacketFilterTests(unittest.TestCase):
    def test_ip_ports_flags_frame_and_boolean_combinations(self):
        record = tcp_record()
        expressions = (
            "ip.addr == 192.168.1.10", "ip.addr == 192.168.1.0/24",
            "tcp.port == 80", "tcp.flags.syn == 1", "tcp.flags.ack == 0",
            "tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "ip.addr == 192.168.1.10 && (tcp.port == 80 || tcp.port == 443)",
            "!(tcp.port == 22)", "frame.len >= 54", "tcp.len == 0", "tcp",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                self.assertTrue(compile_filter(expression)(record))
        self.assertFalse(compile_filter("tcp.flags.rst == 1 || tcp.port == 22")(record))

    def test_dns_fields_and_text_operators(self):
        query = udp_dns_record()
        response = udp_dns_record(True)
        self.assertTrue(compile_filter("dns && dns.flags.response == 0")(query))
        self.assertTrue(compile_filter('dns.qry.name contains "google.com"')(query))
        self.assertTrue(compile_filter('dns.qry.name matches "^google\\.com$"')(query))
        self.assertTrue(compile_filter("dns.flags.response == 1")(response))
        self.assertFalse(compile_filter("dns.flags.response != 0")(query))

    def test_http_request_response_and_tls(self):
        request = tcp_record(b"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertTrue(compile_filter("http && http.request")(request))
        self.assertTrue(compile_filter('http.request.method == "GET"')(request))
        self.assertTrue(compile_filter('http.host contains "example.com"')(request))
        self.assertTrue(compile_filter('http.request.uri contains "/login"')(request))
        response = tcp_record(b"HTTP/1.1 404 Not Found\r\n\r\n", source_port=80,
                              destination_port=54132)
        self.assertTrue(compile_filter("http.response.code == 404")(response))
        tls = tcp_record(bytes.fromhex("160303000401000000"), destination_port=443)
        self.assertTrue(compile_filter("https && tls.handshake.type == 1")(tls))
        self.assertTrue(compile_filter("ssl.handshake.type == 1")(tls))

    def test_rejects_unknown_unsafe_or_excessive_filters(self):
        invalid = ("unknown", "ip.addr = 1.2.3.4", "tcp.port ==", "(tcp",
                   'http.host matches "(?=bad)"', "tcp &&& udp")
        for expression in invalid:
            with self.subTest(expression=expression), self.assertRaises(FilterSyntaxError):
                compile_filter(expression)
        with self.assertRaises(FilterSyntaxError):
            compile_filter("tcp " * 1_000)

    def test_saved_filters_are_atomic_bounded_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "filters.json"
            save_saved_filters({"Web": "tcp.port == 80", "Queries": "dns.flags.response == 0"}, path)
            self.assertEqual(load_saved_filters(path)["Web"], "tcp.port == 80")
            with self.assertRaises(ValueError):
                save_saved_filters({"Bad": "made.up == 1"}, path)
            with self.assertRaises(ValueError):
                save_saved_filters({str(index): "tcp" for index in range(101)}, path)

    def test_decoded_fields_are_bounded_and_consistent(self):
        fields = packet_fields(tcp_record()).values
        self.assertEqual(fields["ip.src"], ("192.168.1.10",))
        self.assertEqual(fields["tcp.port"], (54132, 80))
        self.assertEqual(fields["tcp.flags.syn"], (1,))


if __name__ == "__main__":
    unittest.main()
