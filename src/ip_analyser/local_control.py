"""Opt-in local-only scanner control with separately approved router writes."""

from __future__ import annotations

import hmac
import ipaddress
import json
import secrets
import subprocess
import threading
import tkinter as tk
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tkinter import messagebox
from urllib.parse import urlsplit

from .ai_network_monitor import local_report, monitor_loop, monitor_once, validate_monitor_target

PORT = 18796
ROUTER_ACTIONS = {"reboot": "reboot", "wifi_reload": "wifi reload"}


def validate_router(address: str) -> str:
    ip = ipaddress.ip_address(address)
    if not ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("router must use a private LAN address")
    return str(ip)


def router_ssh(router: str, command: str) -> str:
    """OpenWrt SSH-key access only; no passwords, shell input or host-key bypass."""
    result = subprocess.run([
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
        f"root@{validate_router(router)}", command,
    ], capture_output=True, text=True, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError("Router SSH failed; configure SSH keys and verify the host key first")
    return result.stdout[:16384]


def approve_router_action(router: str, action: str) -> bool:
    window = tk.Tk()
    window.withdraw()
    window.attributes("-topmost", True)
    try:
        return bool(messagebox.askyesno(
            "Advanced IP Analyser - router approval",
            f"Allow {action} on {router}?\n\nThis can temporarily disconnect devices.\n"
            "This approval is for this action only.", parent=window))
    finally:
        window.destroy()


class ControlState:
    def __init__(self, router: str = "192.168.1.1"):
        self.router = validate_router(router)
        self.token = secrets.token_urlsafe(32)
        self.stop_event = None
        self.worker = None
        self.lock = threading.Lock()
        self.router_lock = threading.Lock()

    def start(self, target: str, interval: int) -> dict:
        validate_monitor_target(target)
        if not 60 <= interval <= 86400:
            raise ValueError("interval must be 60 to 86400 seconds")
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError("monitor already running")
            self.stop_event = threading.Event()
            self.worker = threading.Thread(target=monitor_loop, args=(target,),
                                           kwargs={"interval": interval, "stop": self.stop_event}, daemon=True)
            self.worker.start()
        return {"running": True, "target": target}

    def stop(self) -> dict:
        with self.lock:
            if self.stop_event:
                self.stop_event.set()
        return {"stopping": True}


HTML = '''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Advanced IP Analyser - local control</title>
<style>body{font:16px system-ui;background:#142033;color:#eef;max-width:850px;margin:2rem auto}
button,input{padding:10px;margin:5px}button{cursor:pointer;background:#2867b8;color:white;border:0;border-radius:5px}
fieldset{margin:1rem 0;border-radius:9px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#24364b;padding:1rem}</style>
<h1>Local AI Control</h1><p>Local computer only. No automatic cloud uploads.</p>
<fieldset><legend>One-time session authorisation</legend><input id="secret" type="password" placeholder="Session token" size="42">
<button onclick="auth=secret.value;secret.value='';out.textContent='Authorised for this session'">Authorise</button></fieldset>
<fieldset><legend>Scanner</legend><input id="target" value="192.168.1.0/24" aria-label="LAN target">
<input id="interval" type="number" value="300" min="60" aria-label="Interval seconds">
<button onclick="call('GET','/api/report')">Read report</button>
<button onclick="call('POST','/api/scan',{target:target.value})">Scan once</button>
<button onclick="call('POST','/api/monitor/start',{target:target.value,interval:+interval.value})">Start monitoring</button>
<button onclick="call('POST','/api/monitor/stop',{})">Stop monitoring</button></fieldset>
<fieldset><legend>GL.iNet router</legend><button onclick="call('GET','/api/router/status')">Read status</button>
<button onclick="router('wifi_reload')">Reload Wi-Fi</button><button onclick="router('reboot')">Restart router</button>
<p>Every router change requires separate approval on this PC.</p></fieldset><pre id="out">Ready.</pre>
<script>let auth='';async function call(method,path,body){try{const r=await fetch(path,{method,headers:{'X-Local-Control-Token':auth,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});out.textContent=JSON.stringify(await r.json(),null,2)}catch(e){out.textContent=String(e)}}
function router(action){if(confirm('Request '+action+'? The PC will ask for separate approval.'))call('POST','/api/router/action',{action})}</script></html>'''


def make_handler(state: ControlState):
    class Handler(BaseHTTPRequestHandler):
        def send_data(self, code: int, data: dict | str, mime: str = "application/json"):
            payload = data.encode() if isinstance(data, str) else json.dumps(data).encode()
            self.send_response(code)
            for k, v in {"Content-Type": mime, "Content-Length": str(len(payload)),
                         "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                         "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'"}.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def route(self):
            if self.headers.get("Host") not in (f"localhost:{PORT}", f"127.0.0.1:{PORT}"):
                return self.send_data(403, {"error": "invalid host"})
            if self.headers.get("Origin") not in (None, f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}"):
                return self.send_data(403, {"error": "invalid origin"})
            path = urlsplit(self.path).path
            if self.command == "GET" and path == "/":
                return self.send_data(200, HTML, "text/html; charset=utf-8")
            if not hmac.compare_digest(self.headers.get("X-Local-Control-Token", ""), state.token):
                return self.send_data(401, {"error": "session token required"})
            try:
                if self.command == "GET":
                    if path == "/api/report":
                        return self.send_data(200, local_report(include_identifiers=True))
                    if path == "/api/router/status":
                        return self.send_data(200, {"router": state.router, "status": json.loads(router_ssh(state.router, "ubus call system board"))})
                if self.command == "POST":
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 <= size <= 8192:
                        return self.send_data(413, {"error": "body too large"})
                    body = json.loads(self.rfile.read(size)) if size else {}
                    if not isinstance(body, dict):
                        raise ValueError("JSON object required")
                    if path == "/api/scan":
                        return self.send_data(200, monitor_once(str(body.get("target", ""))))
                    if path == "/api/monitor/start":
                        return self.send_data(200, state.start(str(body.get("target", "")), int(body.get("interval", 300))))
                    if path == "/api/monitor/stop":
                        return self.send_data(200, state.stop())
                    if path == "/api/router/action":
                        action = body.get("action")
                        if action not in ROUTER_ACTIONS:
                            raise ValueError("router action not allowlisted")
                        if not state.router_lock.acquire(blocking=False):
                            return self.send_data(409, {"error": "another router approval is pending"})
                        try:
                            if not approve_router_action(state.router, str(action)):
                                return self.send_data(403, {"error": "router change declined"})
                            router_ssh(state.router, ROUTER_ACTIONS[action])
                        finally:
                            state.router_lock.release()
                        return self.send_data(200, {"approved": True, "action": action})
                return self.send_data(404, {"error": "unknown action"})
            except (ValueError, TypeError) as exc:
                return self.send_data(400, {"error": str(exc)})
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                return self.send_data(502, {"error": str(exc)})
            except tk.TclError:
                return self.send_data(503, {"error": "local desktop approval unavailable; router unchanged"})

        do_GET = route
        do_POST = route

        def log_message(self, *args):
            pass  # Do not log private network data.

    return Handler


def serve_control(router: str = "192.168.1.1") -> None:
    state = ControlState(router)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), make_handler(state))
    print(f"Control dashboard: http://127.0.0.1:{PORT}/", flush=True)
    print(f"Session token: {state.token}", flush=True)
    print("Close this window or Ctrl+C to revoke access.", flush=True)
    try:
        server.serve_forever(poll_interval=.2)
    finally:
        state.stop()
        server.server_close()
