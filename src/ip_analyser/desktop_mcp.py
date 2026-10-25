"""Local MCP stdio tools for ChatGPT Desktop/Codex (no OpenAI API key).

The desktop client launches this process on the same computer. It is not an
HTTP server and it makes no unsolicited connections to ChatGPT or the cloud.
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from .ai_network_monitor import local_report, monitor_once
from .local_control import ROUTER_ACTIONS, approve_router_action, router_ssh, validate_router

SERVER_NAME = "advanced-ip-analyser"
TOOL_DEFINITIONS = [
    {"name": "network_report", "description": "Read latest local LAN inventory and changes. Identifiers excluded unless explicitly requested.",
     "inputSchema": {"type": "object", "properties": {"include_identifiers": {"type": "boolean", "default": False}}, "additionalProperties": False}},
    {"name": "scan_private_network", "description": "Run a bounded scan of a private LAN and save results locally.",
     "inputSchema": {"type": "object", "properties": {"target": {"type": "string", "description": "Private IP/CIDR, max 1024 hosts"}},
                     "required": ["target"], "additionalProperties": False}},
    {"name": "router_status", "description": "Read GL.iNet/OpenWrt router status using an existing verified SSH key.",
     "inputSchema": {"type": "object", "properties": {"router": {"type": "string", "default": "192.168.1.1"}}, "additionalProperties": False}},
    {"name": "router_action", "description": "Request a router reboot or Wi-Fi reload; separate Windows desktop approval is mandatory.",
     "inputSchema": {"type": "object", "properties": {"router": {"type": "string", "default": "192.168.1.1"},
                                                           "action": {"type": "string", "enum": ["reboot", "wifi_reload"]}},
                     "required": ["action"], "additionalProperties": False}},
]


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    if not isinstance(arguments, dict):
        raise ValueError("tool arguments must be an object")
    definition = next((tool for tool in TOOL_DEFINITIONS if tool["name"] == name), None)
    if definition is None:
        raise ValueError("unknown MCP tool")
    schema = definition["inputSchema"]
    if set(arguments) - set(schema["properties"]):
        raise ValueError("unknown tool argument")
    if any(required not in arguments for required in schema.get("required", [])):
        raise ValueError("required tool argument missing")
    if name == "network_report":
        include = arguments.get("include_identifiers", False)
        if not isinstance(include, bool):
            raise ValueError("include_identifiers must be boolean")
        return local_report(include_identifiers=include)
    if name == "scan_private_network":
        target = arguments["target"]
        if not isinstance(target, str):
            raise ValueError("target must be a string")
        return monitor_once(target)
    router = arguments.get("router", "192.168.1.1")
    if not isinstance(router, str):
        raise ValueError("router must be a string")
    router = validate_router(router)
    if name == "router_status":
        return {"router": router, "status": json.loads(router_ssh(router, "ubus call system board"))}
    action = arguments["action"]
    if action not in ROUTER_ACTIONS:
        raise ValueError("router action is not permitted")
    if not approve_router_action(router, action):
        return {"approved": False, "action": action, "router": router}
    router_ssh(router, ROUTER_ACTIONS[action])
    return {"approved": True, "action": action, "router": router}


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method", "")
    request_id = message.get("id")
    if request_id is None:  # notifications have no reply
        return None
    response: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    try:
        if method == "initialize":
            requested = message.get("params", {}).get("protocolVersion", "2025-03-26")
            response["result"] = {"protocolVersion": requested, "capabilities": {"tools": {"listChanged": False}},
                                  "serverInfo": {"name": SERVER_NAME, "version": "2.8.4"},
                                  "instructions": "Local LAN control. No cloud telemetry. Router changes always require a separate PC approval. Use reports without identifiers unless specifically needed."}
        elif method == "tools/list":
            response["result"] = {"tools": TOOL_DEFINITIONS}
        elif method == "tools/call":
            params = message.get("params", {})
            try:
                output = call_tool(params.get("name", ""), params.get("arguments", {}))
                response["result"] = {"content": [{"type": "text", "text": json.dumps(output)}]}
            except (ValueError, OSError, RuntimeError, TimeoutError) as exc:
                response["result"] = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        elif method == "ping":
            response["result"] = {}
        else:
            response["error"] = {"code": -32601, "message": "Method not found"}
    except (AttributeError, TypeError, ValueError):
        response["error"] = {"code": -32602, "message": "Invalid request"}
    return response


def serve_stdio(input_stream: TextIO = sys.stdin, output_stream: TextIO = sys.stdout) -> None:
    for line in input_stream:
        if len(line) > 64_000:
            continue
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                continue
            result = handle_request(request)
            if result is not None:
                output_stream.write(json.dumps(result, separators=(",", ":")) + "\n")
                output_stream.flush()
        except (ValueError, UnicodeError):
            continue


if __name__ == "__main__":
    serve_stdio()
