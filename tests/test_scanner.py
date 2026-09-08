import unittest
from unittest.mock import Mock, patch

from ip_analyser.models import Host
from ip_analyser.scanner import CREATE_NO_WINDOW, Scanner


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
        self.assertEqual(host.device_type, "Web device / server")
        self.assertEqual(host.service_info, {})
        discovered = scanner.discover(host)
        self.assertEqual(discovered.service_info, {"443": {"Server": "nginx"}})

    @patch("ip_analyser.scanner.os.name", "nt")
    @patch("ip_analyser.scanner.subprocess.run")
    def test_windows_background_ping_and_arp_never_open_consoles(self, run):
        run.side_effect = [Mock(returncode=0), Mock(stdout="  192.0.2.20  aa-bb-cc-dd-ee-ff dynamic")]
        scanner = Scanner(ports={80: "http"})
        self.assertTrue(scanner._ping("192.0.2.20"))
        self.assertEqual(scanner._neighbour_mac("192.0.2.20"), "AA:BB:CC:DD:EE:FF")
        self.assertTrue(all(call.kwargs["creationflags"] == CREATE_NO_WINDOW
                            for call in run.call_args_list))

    @patch("ip_analyser.scanner.time.monotonic", side_effect=[10.0, 10.012])
    @patch.object(Scanner, "_port_open", return_value=True)
    def test_latency_is_a_single_probe_time_not_whole_scan_duration(self, _open, _clock):
        opened, latency = Scanner()._timed_port_open("192.0.2.20", 443)
        self.assertTrue(opened)
        self.assertEqual(latency, 12.0)


if __name__ == "__main__":
    unittest.main()
