"""Regression checks for the opt-in local control API."""

import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from ip_analyser.local_control import PORT, ControlState, make_handler, validate_router


class LocalControlTests(unittest.TestCase):
    def setUp(self):
        self.state = ControlState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.state.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path, method="GET", data=None, *, token=None, origin=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Host": host or f"127.0.0.1:{PORT}"}
        if token is not None:
            headers["X-Local-Control-Token"] = token
        if origin is not None:
            headers["Origin"] = origin
        if data is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=json.dumps(data) if data is not None else None, headers=headers)
        response = conn.getresponse()
        status, payload = response.status, response.read()
        conn.close()
        return status, payload

    def test_requires_token_for_local_data(self):
        status, _ = self.request("/api/report")
        self.assertEqual(status, 401)

    def test_rejects_foreign_origin(self):
        status, _ = self.request("/api/report", token=self.state.token, origin="https://attacker.example")
        self.assertEqual(status, 403)

    def test_rejects_dns_rebinding_host(self):
        status, _ = self.request("/api/report", token=self.state.token, host="attacker.example")
        self.assertEqual(status, 403)

    def test_report_with_token(self):
        with patch("ip_analyser.local_control.local_report", return_value={"local_only": True}):
            status, payload = self.request("/api/report", token=self.state.token)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"local_only": True})

    def test_router_unknown_action_denied_without_approval(self):
        with patch("ip_analyser.local_control.approve_router_action") as approval:
            status, _ = self.request("/api/router/action", "POST", {"action": "uci_delete_all"}, token=self.state.token)
        self.assertEqual(status, 400)
        approval.assert_not_called()

    def test_router_change_requires_local_approval(self):
        with patch("ip_analyser.local_control.approve_router_action", return_value=False) as approval, \
             patch("ip_analyser.local_control.router_ssh") as ssh:
            status, _ = self.request("/api/router/action", "POST", {"action": "reboot"}, token=self.state.token)
        self.assertEqual(status, 403)
        approval.assert_called_once()
        ssh.assert_not_called()

    def test_router_change_approved(self):
        with patch("ip_analyser.local_control.approve_router_action", return_value=True), \
             patch("ip_analyser.local_control.router_ssh", return_value="") as ssh:
            status, payload = self.request("/api/router/action", "POST", {"action": "wifi_reload"}, token=self.state.token)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["approved"])
        ssh.assert_called_once_with("192.168.1.1", "wifi reload")

    def test_router_address_must_be_private(self):
        for address in ("8.8.8.8", "127.0.0.1", "169.254.1.1"):
            with self.assertRaises(ValueError):
                validate_router(address)


if __name__ == "__main__":
    unittest.main()
