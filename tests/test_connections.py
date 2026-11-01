import io
import json
import socket
import unittest
from unittest.mock import Mock, patch

import psutil

from ip_analyser.connections import GeoLocation, is_public_address, locate_address, snapshot_connections


class _Response(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *_args): self.close()


class ConnectionMonitorTests(unittest.TestCase):
    @patch("ip_analyser.connections.psutil.Process")
    @patch("ip_analyser.connections.psutil.net_connections")
    def test_snapshot_identifies_inbound_outbound_and_owner(self, net_connections, process):
        listener = Mock(type=socket.SOCK_STREAM, laddr=("0.0.0.0", 443), raddr=(),
                        status=psutil.CONN_LISTEN, pid=10)
        inbound = Mock(type=socket.SOCK_STREAM, laddr=("192.168.1.2", 443),
                       raddr=("198.51.100.5", 50000), status=psutil.CONN_ESTABLISHED, pid=10)
        outbound = Mock(type=socket.SOCK_STREAM, laddr=("192.168.1.2", 51000),
                        raddr=("203.0.113.8", 443), status=psutil.CONN_ESTABLISHED, pid=11)
        net_connections.return_value = [listener, inbound, outbound]
        process.return_value.name.return_value = "browser.exe"
        process.return_value.exe.return_value = "C:/browser.exe"
        records = snapshot_connections()
        self.assertEqual({record.direction for record in records}, {"Listening", "Inbound", "Outbound"})
        self.assertTrue(all(record.application == "browser.exe" for record in records))

    def test_public_address_filter(self):
        self.assertTrue(is_public_address("8.8.8.8"))
        self.assertFalse(is_public_address("192.168.1.5"))
        self.assertFalse(is_public_address("127.0.0.1"))

    @patch("ip_analyser.connections.urllib.request.urlopen")
    def test_geolocation_is_bounded_and_parsed(self, urlopen):
        urlopen.return_value = _Response(json.dumps({
            "success": True, "city": "London", "region": "England", "country": "United Kingdom",
            "latitude": 51.5, "longitude": -0.1, "connection": {"isp": "Example ISP"},
        }).encode())
        location = locate_address("8.8.8.8")
        self.assertEqual(location, GeoLocation("8.8.8.8", "London", "England", "United Kingdom",
                                               "Example ISP", 51.5, -0.1))
        self.assertIn("ipwho.is/8.8.8.8", urlopen.call_args.args[0].full_url)

    @patch("ip_analyser.connections.urllib.request.urlopen")
    def test_private_addresses_are_not_sent_to_geolocation(self, urlopen):
        self.assertEqual(locate_address("192.168.1.5").country, "Private / local network")
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
