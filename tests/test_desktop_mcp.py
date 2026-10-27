"""MCP transport and authorization tests (no live LAN/router operations)."""

import io
import json
import unittest
from unittest.mock import patch

from ip_analyser.desktop_mcp import call_tool, handle_request, serve_stdio


class DesktopMcpTests(unittest.TestCase):
    def test_initialize_and_tools_list(self):
        greeting = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
        self.assertEqual(greeting["result"]["protocolVersion"], "2025-03-26")
        listing = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual({t["name"] for t in listing["result"]["tools"]},
                         {"network_report", "scan_private_network", "router_status", "router_action"})

    def test_no_reply_for_notifications(self):
        self.assertIsNone(handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_read_report_redacted_by_default(self):
        with patch("ip_analyser.desktop_mcp.local_report", return_value={"local_only": True}) as reporter:
            response = handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                       "params": {"name": "network_report", "arguments": {}}})
        reporter.assert_called_once_with(include_identifiers=False)
        self.assertTrue(json.loads(response["result"]["content"][0]["text"])["local_only"])

    def test_undocumented_tool_or_arguments_denied(self):
        with self.assertRaises(ValueError):
            call_tool("shell", {"command": "whoami"})
        with self.assertRaises(ValueError):
            call_tool("router_status", {"command": "reboot"})

    def test_router_change_never_skips_local_approval(self):
        with patch("ip_analyser.desktop_mcp.approve_router_action", return_value=False) as approval, \
             patch("ip_analyser.desktop_mcp.router_ssh") as ssh:
            result = call_tool("router_action", {"action": "reboot"})
        self.assertFalse(result["approved"])
        approval.assert_called_once()
        ssh.assert_not_called()

    def test_router_change_executes_only_allowlisted_command(self):
        with patch("ip_analyser.desktop_mcp.approve_router_action", return_value=True), \
             patch("ip_analyser.desktop_mcp.router_ssh", return_value="") as ssh:
            result = call_tool("router_action", {"action": "wifi_reload"})
        self.assertTrue(result["approved"])
        ssh.assert_called_once_with("192.168.1.1", "wifi reload")

    def test_invalid_scan_target_is_rejected_by_monitor(self):
        with patch("ip_analyser.desktop_mcp.monitor_once", side_effect=ValueError("private LAN only")):
            result = handle_request({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                                     "params": {"name": "scan_private_network", "arguments": {"target": "8.8.8.8"}}})
        self.assertTrue(result["result"]["isError"])

    def test_stdio_protocol_one_json_per_line(self):
        stdin = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
                            '{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        stdout = io.StringIO()
        serve_stdio(stdin, stdout)
        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["result"], {})


if __name__ == "__main__":
    unittest.main()
