import unittest
from unittest.mock import patch

from ip_analyser.scanner import Scanner


class ScannerPortDetailTests(unittest.TestCase):
    @patch("ip_analyser.scanner.probe_service")
    @patch("ip_analyser.scanner.socket.gethostbyaddr", return_value=("printer.local", [], []))
    @patch.object(Scanner, "_neighbour_mac", return_value="")
    @patch.object(Scanner, "_ping", return_value=True)
    @patch.object(Scanner, "_port_open")
    def test_open_ports_stay_aligned_with_service_names(self, port_open, _ping, _mac, _hostname, fingerprint):
        port_open.side_effect = lambda _address, port: port in {22, 443}
        fingerprint.side_effect = lambda _address, port, _service, _timeout: ({"Server": "nginx"} if port == 443 else {})
        host = Scanner(ports={22: "ssh", 80: "http", 443: "https"}).inspect("192.0.2.20")
        self.assertEqual(host.ports, [22, 443])
        self.assertEqual(host.services, ["ssh", "https"])
        self.assertEqual(host.service_info, {"443": {"Server": "nginx"}})


if __name__ == "__main__":
    unittest.main()
