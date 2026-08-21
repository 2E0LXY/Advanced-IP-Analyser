from __future__ import annotations

import html
import http.client
import re
import socket
import ssl

MAX_RESPONSE_BYTES = 65_536
MAX_VALUE_LENGTH = 500
_TITLE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAGS = re.compile(r"<[^>]+>")
_BANNER_SERVICES = {"ftp", "ssh", "smtp", "submission", "pop3", "imap"}


def _clean(value: str, limit: int = MAX_VALUE_LENGTH) -> str:
    """Return a compact, display-safe value from untrusted network text."""
    value = " ".join(value.replace("\x00", "").split())
    value = "".join(character for character in value if character.isprintable())
    return value[:limit]


def probe_service(address: str, port: int, service: str, timeout: float = 1.0) -> dict[str, str]:
    """Collect a small amount of passive service metadata from an open port.

    Probes are deliberately bounded and unauthenticated. Network and protocol
    failures simply produce no metadata so discovery cannot fail a host scan.
    """
    timeout = min(3.0, max(0.2, timeout))
    try:
        if service in {"http", "https"}:
            return _probe_http(address, port, service == "https", timeout)
        if service in _BANNER_SERVICES:
            return _probe_banner(address, port, timeout)
    except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException, ValueError):
        pass
    return {}


def _probe_http(address: str, port: int, secure: bool, timeout: float) -> dict[str, str]:
    if secure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(address, port, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(address, port, timeout=timeout)

    details: dict[str, str] = {}
    try:
        connection.request("GET", "/", headers={
            "User-Agent": "Advanced-IP-Analyser service discovery",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
            "Connection": "close",
        })
        response = connection.getresponse()
        details["Status"] = _clean(f"{response.status} {response.reason}")
        for header, label in (
            ("Server", "Server"),
            ("X-Powered-By", "Powered by"),
            ("Content-Type", "Content type"),
            ("Location", "Redirect"),
            ("WWW-Authenticate", "Authentication"),
        ):
            value = response.getheader(header)
            if value:
                details[label] = _clean(value)

        if secure and connection.sock:
            details["TLS"] = _clean(connection.sock.version() or "")
            cipher = connection.sock.cipher()
            if cipher:
                details["Cipher"] = _clean(cipher[0])

        content_type = response.getheader("Content-Type", "").casefold()
        body = response.read(MAX_RESPONSE_BYTES)
        if "html" in content_type or b"<title" in body.lower():
            charset = response.headers.get_content_charset() or "utf-8"
            page = body.decode(charset, errors="replace")
            match = _TITLE.search(page)
            if match:
                title = html.unescape(_TAGS.sub("", match.group(1)))
                if cleaned := _clean(title):
                    details["Page title"] = cleaned
    finally:
        connection.close()
    return {key: value for key, value in details.items() if value}


def _probe_banner(address: str, port: int, timeout: float) -> dict[str, str]:
    with socket.create_connection((address, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        banner = connection.recv(1024).decode("utf-8", errors="replace")
    cleaned = _clean(banner)
    return {"Banner": cleaned} if cleaned else {}
