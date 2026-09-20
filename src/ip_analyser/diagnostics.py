"""Bounded, read-only network diagnostics for the desktop workbench."""

from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import urllib.request
from urllib.parse import urlsplit

_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}")
_SELECTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")


def valid_host(value: str) -> str:
    host = value.strip()
    if not _HOST.fullmatch(host) or host.endswith("."):
        raise ValueError("Enter a valid hostname or IP address.")
    return host


def _command(args: list[str], timeout: int = 25) -> str:
    executable = shutil.which(args[0])
    if not executable:
        raise RuntimeError(f"{args[0]} is not installed on this system")
    completed = subprocess.run([executable, *args[1:]], capture_output=True,
                               text=True, errors="replace", timeout=timeout, check=False)
    output = (completed.stdout + "\n" + completed.stderr).strip()
    return output[:100_000] or f"Command exited with code {completed.returncode}."


def run_diagnostic(kind: str, target: str = "", selector: str = "") -> str:
    """Run one diagnostic without a shell and return printable output."""
    if kind == "netstat":
        return _command(["netstat", "-ano"] if os.name == "nt" else ["ss", "-tuna"])
    if kind == "http":
        raw = target.strip()
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        parts = urlsplit(raw)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError("Enter an HTTP or HTTPS URL without credentials.")
        request = urllib.request.Request(raw, headers={"User-Agent": "AdvancedIPAnalyser/2"})
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(16_384).decode("utf-8", "replace")
            headers = "\n".join(f"{name}: {value}" for name, value in response.headers.items())
            return f"HTTP {response.status} {response.reason}\n{response.url}\n\n{headers}\n\n{body}"
    host = valid_host(target)
    if kind == "ping":
        return _command(["ping", "-n", "4", host] if os.name == "nt" else ["ping", "-c", "4", host])
    if kind == "trace":
        return _command(["tracert", "-d", host] if os.name == "nt" else ["tracepath", host], timeout=45)
    if kind in {"A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA", "PTR", "SPF", "DMARC", "DKIM"}:
        record = "TXT" if kind in {"SPF", "DMARC", "DKIM"} else kind
        query = host
        if kind == "DMARC":
            query = "_dmarc." + host
        elif kind == "DKIM":
            if not _SELECTOR.fullmatch(selector.strip()):
                raise ValueError("Enter a DKIM selector first.")
            query = selector.strip() + "._domainkey." + host
        return _command(["nslookup", f"-type={record}", query])
    if kind == "tls":
        context = ssl.create_default_context()
        with (socket.create_connection((host, 443), timeout=10) as connection,
              context.wrap_socket(connection, server_hostname=host) as secure):
            certificate = secure.getpeercert()
            lines = [f"Host: {host}:443", f"Protocol: {secure.version()}",
                     f"Cipher: {secure.cipher()[0]}"]
            for key in ("subject", "issuer", "notBefore", "notAfter", "serialNumber"):
                lines.append(f"{key}: {certificate.get(key, '')}")
            return "\n".join(lines)
    raise ValueError(f"Unsupported diagnostic: {kind}")
