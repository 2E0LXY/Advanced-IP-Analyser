import unittest
from unittest.mock import patch

from ip_analyser.models import Host
from ip_analyser.scanner import Scanner


class ScannerPortDetailTests(unittest.TestCase):
    @patch.object(Scanner, "discover")
    @patch.object(Scanner, "inspect")
    def test_scan_completes_host_phase_before_discovery(self, inspect, discover):
        order = []
        inspect.side_effect = lambda address: (order.append(f"scan:{address}") or
                                               Host(address, reachable=True, services=["http"], ports=[80]))
        discover.side_effect = lambda host: (order.append(f"discover:{host.address}") or host)
        Scanner(workers=1).scan(["192.0.2.1", "192.0.2.2"])
        first_discovery = next(index for index, value in enumerate(order) if value.startswith("discover:"))
        self.assertTrue(all(value.startswith("scan:") for value in order[:first_discovery]))
        self.assertEqual(first_discovery, 2)

    @patch("ip_analyser.scanner.probe_service")
    @patch("ip_analyser.scanner.socket.gethostbyaddr", return_value=("printer.local", [], []))
    @patch.object(Scanner, "_neighbour_mac", return_value="")
    @patch.object(Scanner, "_ping", return_value=True)
    @patch.object(Scanner, "_port_open")
    def test_open_ports_stay_aligned_with_service_names(self, port_open, _ping, _mac, _hostname, fingerprint):
        port_open.side_effect = lambda _address, port: port in {22, 443}
        fingerprint.side_effect = lambda _address, port, _service, _timeout: ({"Server": "nginx"} if port == 443 else {})
        scanner = Scanner(ports={22: "ssh", 80: "http", 443: "https"})
        host = scanner.inspect("192.0.2.20")
        self.assertEqual(host.ports, [22, 443])
        self.assertEqual(host.services, ["ssh", "https"])
        self.assertEqual(host.service_info, {})
        discovered = scanner.discover(host)
        self.assertEqual(discovered.service_info, {"443": {"Server": "nginx"}})


if __name__ == "__main__":
    unittest.main()
