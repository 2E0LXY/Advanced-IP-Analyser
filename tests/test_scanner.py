import time
import unittest
from unittest.mock import Mock, patch

from ip_analyser.models import Host
from ip_analyser.scanner import CREATE_NO_WINDOW, Scanner


class ScannerPortDetailTests(unittest.TestCase):
    @patch.object(Scanner, "_neighbour_mac", return_value="")
    @patch.object(Scanner, "_port_open")
    def test_port_checks_are_parallel_and_latency_is_a_probe_not_scan_duration(self, port_open, _mac):
        def probe(_address, port):
            time.sleep(0.005 if port == 1000 else 0.06)
            return port == 1000

        port_open.side_effect = probe
        scanner = Scanner(ports={port: "test" for port in range(1000, 1016)})
        started = time.monotonic()
        host = scanner.inspect("192.0.2.20")
        total_ms = (time.monotonic() - started) * 1000
        self.assertEqual(host.ports, [1000])
        self.assertLess(host.latency_ms, total_ms / 2)
        self.assertLess(total_ms, 800)

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
        run.side_effect = [Mock(returncode=0, stdout=b"Reply from 192.0.2.20: bytes=32 time<1ms TTL=64"),
                           Mock(stdout="  192.0.2.20  aa-bb-cc-dd-ee-ff dynamic")]
        scanner = Scanner(ports={80: "http"})
        self.assertEqual(scanner._ping("192.0.2.20"), 0.5)
        self.assertEqual(scanner._neighbour_mac("192.0.2.20"), "AA:BB:CC:DD:EE:FF")
        self.assertTrue(all(call.kwargs["creationflags"] == CREATE_NO_WINDOW
                            for call in run.call_args_list))

    @patch("ip_analyser.scanner.os.name", "nt")
    @patch("ip_analyser.scanner.subprocess.run")
    def test_windows_unreachable_reply_does_not_mark_host_up(self, run):
        # Windows can report success and one received packet for an ICMP error
        # sent by the local PC or router rather than by the target.
        run.return_value = Mock(returncode=0, stdout=(
            b"Reply from 192.0.2.201: Destination host unreachable.\r\n"
            b"Packets: Sent = 1, Received = 1, Lost = 0 (0% loss)"))
        scanner = Scanner(ports={80: "http"})
        self.assertIsNone(scanner._ping("192.0.2.20"))

    @patch("ip_analyser.scanner.os.name", "nt")
    @patch("ip_analyser.scanner.subprocess.run")
    def test_ping_rejects_timed_reply_from_another_host(self, run):
        run.return_value = Mock(returncode=0, stdout=b"Reply from 192.0.2.1: bytes=32 time=4ms TTL=64")
        self.assertIsNone(Scanner()._ping("192.0.2.20"))

    @patch("ip_analyser.scanner.os.name", "posix")
    @patch("ip_analyser.scanner.subprocess.run")
    def test_linux_ping_accepts_only_target_reply(self, run):
        run.return_value = Mock(returncode=0, stdout=(
            b"64 bytes from 192.0.2.20: icmp_seq=1 ttl=64 time=0.312 ms\n"))
        self.assertEqual(Scanner()._ping("192.0.2.20"), 0.312)

    @patch("ip_analyser.scanner.os.name", "posix")
    @patch("ip_analyser.scanner.subprocess.run")
    def test_ipv6_ping_uses_ipv6_mode_and_accepts_scoped_target(self, run):
        run.return_value = Mock(
            returncode=0,
            stdout=b"64 bytes from fe80::1%eth0: icmp_seq=1 ttl=64 time=0.420 ms\n")
        self.assertEqual(Scanner()._ping("fe80::1%eth0"), 0.42)
        self.assertEqual(run.call_args.args[0][:2], ["ping", "-6"])

    @patch("ip_analyser.scanner.os.name", "nt")
    @patch("ip_analyser.scanner.subprocess.run")
    def test_local_router_supplies_names_when_public_dns_does_not(self, run):
        route_table = ("0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.201  25\n"
                       "192.168.1.0  255.255.255.0  On-link  192.168.1.201  281\n")
        def command(args, **_kwargs):
            if args[0] == "route.exe":
                return Mock(stdout=route_table)
            if args[0] == "nslookup":
                self.assertEqual(args[-1], "192.168.1.1")
                return Mock(stdout="Name: Tapo_SmartPlug.lan\nAddress: 192.168.1.45")
            self.fail(f"unexpected command: {args}")
        run.side_effect = command
        scanner = Scanner()
        self.assertEqual(scanner._resolve_hostname("192.168.1.45"), "Tapo_SmartPlug.lan")
        self.assertEqual(scanner._local_gateway("192.168.2.45"), "")
        self.assertEqual(scanner._local_gateway("8.8.8.8"), "")

    @patch("ip_analyser.scanner.time.monotonic", side_effect=[10.0, 10.012])
    @patch.object(Scanner, "_port_open", return_value=True)
    def test_latency_is_a_single_probe_time_not_whole_scan_duration(self, _open, _clock):
        opened, latency = Scanner()._timed_port_open("192.0.2.20", 443)
        self.assertTrue(opened)
        self.assertEqual(latency, 12.0)


if __name__ == "__main__":
    unittest.main()
