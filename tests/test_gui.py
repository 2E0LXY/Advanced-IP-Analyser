import unittest
from unittest.mock import patch

from ip_analyser.gui import Application
from ip_analyser.models import Host


class _Table:
    def selection(self):
        return ("service-row",)


class _Status:
    def __init__(self):
        self.text = ""

    def configure(self, *, text):
        self.text = text


class ServiceRowInteractionTests(unittest.TestCase):
    @patch("ip_analyser.gui.open_service")
    def test_enter_or_double_click_opens_service_row(self, open_service):
        app = object.__new__(Application)
        app.table = _Table()
        app.status = _Status()
        host = Host("192.0.2.20", reachable=True, services=["https"], ports=[443])
        app.services_by_item = {"service-row": (host, "https", 443)}
        app.hosts_by_item = {}

        app._activate_selected_row()

        open_service.assert_called_once_with("https", "192.0.2.20", 443, username="")
        self.assertEqual(app.status.text, "Opened HTTPS on 192.0.2.20:443")

    def test_service_selection_scopes_packet_capture_to_service_port(self):
        app = object.__new__(Application)
        app.table = _Table()
        host = Host("192.0.2.20", reachable=True, services=["https"], ports=[443])
        app.services_by_item = {"service-row": (host, "https", 443)}
        app.hosts_by_item = {}
        app.metadata_by_item = {}

        hosts, port = app._selected_packet_scope()

        self.assertEqual(hosts, [host])
        self.assertEqual(port, 443)


if __name__ == "__main__":
    unittest.main()
