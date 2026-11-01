"""Opt-in local-only scanner control with separately approved router writes."""

from __future__ import annotations

import hmac
import ipaddress
import json
import secrets
import hashlib
import socket
import time
import urllib.request
import subprocess
import threading
import tkinter as tk
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tkinter import messagebox
from urllib.parse import urlsplit

from .ai_network_monitor import local_report, monitor_loop, monitor_once, validate_monitor_target
from .peer_credentials import load_or_create_pairing, rotate_pairing, save_pairing

PORT = 18796
ANDROID_PORT = 18797
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


def private_lan_address() -> str:
    """Return the active private IPv4 address without opening a connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))
        value = sock.getsockname()[0]
        return value if ipaddress.ip_address(value).is_private else "127.0.0.1"
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


class ControlState:
    def __init__(self, router: str = "192.168.1.1", *, persistent: bool = False):
        self.router = validate_router(router)
        pairing = load_or_create_pairing() if persistent else {
            "token": secrets.token_urlsafe(32), "device_id": "", "peer_address": ""}
        self.token = pairing["token"]
        self.device_id = pairing["device_id"]
        self.peer_address = pairing["peer_address"]
        self.persistent = persistent
        self.nonces: dict[str, float] = {}
        self.stop_event = None
        self.worker = None
        self.lock = threading.Lock()
        self.router_lock = threading.Lock()

    def pair(self, device_id: str, peer_address: str) -> dict:
        if not 16 <= len(device_id) <= 128 or any(ord(char) < 33 for char in device_id):
            raise ValueError("invalid Android device identity")
        address = ipaddress.ip_address(peer_address)
        if not address.is_private or address.is_loopback or address.is_link_local:
            raise ValueError("Android peer must use a private LAN address")
        with self.lock:
            if self.device_id and not hmac.compare_digest(self.device_id, device_id):
                raise PermissionError("a different Android device is already paired; revoke it first")
            self.device_id = device_id
            self.peer_address = str(address)
            if self.persistent:
                save_pairing({"token": self.token, "device_id": self.device_id,
                              "peer_address": self.peer_address})
        return {"paired": True, "device_id": device_id, "peer_address": self.peer_address}

    def revoke(self) -> None:
        pairing = rotate_pairing() if self.persistent else {
            "token": secrets.token_urlsafe(32), "device_id": "", "peer_address": ""}
        with self.lock:
            self.token = pairing["token"]
            self.device_id = ""
            self.peer_address = ""
            self.nonces.clear()

    def verify_peer(self, method: str, path: str, body: bytes, headers) -> bool:
        device = headers.get("X-Peer-Device", "")
        timestamp = headers.get("X-Peer-Timestamp", "")
        nonce = headers.get("X-Peer-Nonce", "")
        signature = headers.get("X-Peer-Signature", "")
        try:
            moment = int(timestamp)
        except ValueError:
            return False
        now = int(time.time())
        if abs(now - moment) > 60 or not 16 <= len(nonce) <= 128:
            return False
        with self.lock:
            self.nonces = {key: seen for key, seen in self.nonces.items() if now - seen < 120}
            if nonce in self.nonces or (self.device_id and not hmac.compare_digest(self.device_id, device)):
                return False
            digest = hashlib.sha256(body).hexdigest()
            message = "\n".join((method, path, timestamp, nonce, device, digest)).encode()
            expected = hmac.new(self.token.encode(), message, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                return False
            self.nonces[nonce] = now
        return True

    def scan_android_peer(self) -> dict:
        if not self.device_id or not self.peer_address:
            raise ValueError("pair the Android app first")
        path = "/api/scan"
        body = b"{}"
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(18)
        digest = hashlib.sha256(body).hexdigest()
        message = "\n".join(("POST", path, timestamp, nonce, "desktop", digest)).encode()
        signature = hmac.new(self.token.encode(), message, hashlib.sha256).hexdigest()
        request = urllib.request.Request(
            f"http://{self.peer_address}:{ANDROID_PORT}{path}", data=body, method="POST",
            headers={"Content-Type": "application/json", "X-Peer-Device": "desktop",
                     "X-Peer-Timestamp": timestamp, "X-Peer-Nonce": nonce,
                     "X-Peer-Signature": signature})
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.loads(response.read(2_000_000))

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
            host = self.headers.get("Host", "").split(":", 1)[0].strip("[]")
            try:
                allowed_host = host == "localhost" or ipaddress.ip_address(host).is_private
            except ValueError:
                allowed_host = False
            if not allowed_host:
                return self.send_data(403, {"error": "invalid host"})
            if self.headers.get("Origin") not in (None, f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}"):
                return self.send_data(403, {"error": "invalid origin"})
            path = urlsplit(self.path).path
            if self.command == "GET" and path == "/":
                return self.send_data(200, HTML, "text/html; charset=utf-8")
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= 8192:
                return self.send_data(413, {"error": "body too large"})
            raw_body = self.rfile.read(size) if size else b""
            legacy = hmac.compare_digest(self.headers.get("X-Local-Control-Token", ""), state.token)
            peer = state.verify_peer(self.command, path, raw_body, self.headers)
            if not legacy and not peer:
                return self.send_data(401, {"error": "valid local or paired-device authentication required"})
            try:
                if self.command == "GET":
                    if path == "/api/report":
                        return self.send_data(200, local_report(include_identifiers=True))
                    if path == "/api/router/status":
                        return self.send_data(200, {"router": state.router, "status": json.loads(router_ssh(state.router, "ubus call system board"))})
                if self.command == "POST":
                    body = json.loads(raw_body) if raw_body else {}
                    if not isinstance(body, dict):
                        raise ValueError("JSON object required")
                    if path == "/api/pair":
                        return self.send_data(200, state.pair(
                            self.headers.get("X-Peer-Device", ""), str(body.get("peer_address", ""))))
                    if path == "/api/pair/revoke":
                        if not peer:
                            return self.send_data(403, {"error": "paired-device authentication required"})
                        self.send_data(200, {"revoked": True})
                        state.revoke()
                        return None
                    if path == "/api/scan":
                        return self.send_data(200, monitor_once(str(body.get("target", ""))))
                    if path == "/api/peer/scan":
                        return self.send_data(200, state.scan_android_peer())
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
            except PermissionError as exc:
                return self.send_data(403, {"error": str(exc)})
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
