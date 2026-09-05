from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

MAX_PAGES = 100
MAX_PAGE_BYTES = 1_048_576
MAX_TOTAL_BYTES = 20 * 1_048_576
MAX_PAGE_LINKS = 10_000
MAX_PAGE_FORMS = 1_000
MAX_PAGE_RESOURCES = 10_000
MAX_DISCOVERED_URLS = 10_000


@dataclass(frozen=True, slots=True)
class WebFinding:
    severity: str
    title: str
    url: str
    evidence: str
    recommendation: str
    category: str = "Configuration"


@dataclass(slots=True)
class WebPage:
    url: str
    status: int
    title: str = ""
    content_type: str = ""
    size: int = 0
    technologies: list[str] = field(default_factory=list)
    links: int = 0
    forms: int = 0


@dataclass(slots=True)
class WebAuditReport:
    target: str
    started_at: str
    completed_at: str = ""
    pages: list[WebPage] = field(default_factory=list)
    findings: list[WebFinding] = field(default_factory=list)
    tls: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class _Document(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, object]] = []
        self.resources: list[str] = []
        self.generator = ""
        self.title = ""
        self._in_title = False
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.casefold(): value or "" for name, value in attrs}
        tag = tag.casefold()
        if tag == "a" and values.get("href") and len(self.links) < MAX_PAGE_LINKS:
            self.links.append(values["href"])
        if tag in {"script", "img", "iframe", "link", "source", "video", "audio"}:
            resource = values.get("src") or values.get("href")
            if resource and len(self.resources) < MAX_PAGE_RESOURCES:
                self.resources.append(resource)
        if tag == "meta" and values.get("name", "").casefold() == "generator":
            self.generator = values.get("content", "")[:200]
        if tag == "title":
            self._in_title = True
        if tag == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "get").casefold(),
                          "password": False, "csrf": False}
        elif tag == "input" and self._form is not None:
            input_type = values.get("type", "text").casefold()
            name = values.get("name", "").casefold()
            self._form["password"] = bool(self._form["password"] or input_type == "password")
            self._form["csrf"] = bool(self._form["csrf"] or any(
                marker in name for marker in ("csrf", "xsrf", "authenticity_token", "nonce")))

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "title":
            self._in_title = False
        if tag.casefold() == "form" and self._form is not None:
            if len(self.forms) < MAX_PAGE_FORMS:
                self.forms.append(self._form)
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 500:
            self.title += data


def _origin(value: str) -> tuple[str, str, int | None]:
    parts = urlsplit(value)
    default_port = 443 if parts.scheme.casefold() == "https" else 80 if parts.scheme.casefold() == "http" else None
    return parts.scheme.casefold(), (parts.hostname or "").casefold(), parts.port or default_port


class _SameHostRedirect(HTTPRedirectHandler):
    _CROSS_ORIGIN_HEADERS = frozenset({"user-agent", "accept", "connection"})

    def __init__(self, allowed_hosts: set[str]):
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if (urlsplit(newurl).hostname or "").casefold() not in self.allowed_hosts:
            raise HTTPError(newurl, code, "redirect leaves the allowed host scope", headers, fp)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and _origin(req.full_url) != _origin(newurl):
            for name, _value in redirected.header_items():
                if name.casefold() not in self._CROSS_ORIGIN_HEADERS:
                    redirected.remove_header(name)
        return redirected


def _normal_url(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
        raise ValueError("target must be an http:// or https:// URL")
    if parts.username or parts.password:
        raise ValueError("credentials must not be embedded in the target URL")
    if len(value) > 2_048:
        raise ValueError("target URL is too long")
    port = parts.port
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{port}" if port else "")
    path = parts.path or "/"
    return urlunsplit((parts.scheme.casefold(), netloc, path, parts.query, ""))


def _technologies(headers: dict[str, str], document: _Document) -> list[str]:
    values = " ".join((headers.get("server", ""), headers.get("x-powered-by", ""),
                       document.generator)).strip()
    found = []
    for pattern, label in (
        (r"nginx", "nginx"), (r"apache", "Apache HTTP Server"),
        (r"microsoft-iis", "Microsoft IIS"), (r"php", "PHP"),
        (r"asp\.net", "ASP.NET"), (r"wordpress", "WordPress"),
        (r"drupal", "Drupal"), (r"joomla", "Joomla"),
        (r"express", "Express"), (r"cloudflare", "Cloudflare"),
    ):
        if re.search(pattern, values, re.IGNORECASE):
            found.append(label)
    return found


def _tls_details(host: str, port: int, timeout: float) -> dict[str, str]:
    validation = "Valid"
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw, \
                ssl.create_default_context().wrap_socket(raw, server_hostname=host):
            pass
    except ssl.SSLCertVerificationError as error:
        validation = f"Failed: {error.verify_message or error}"

    # The crawler never bypasses TLS verification. The separate metadata probe
    # can report an invalid certificate without sending HTTP headers or bodies.
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw, \
            context.wrap_socket(raw, server_hostname=host) as secure:
        certificate = secure.getpeercert(binary_form=True) or b""
        cipher = secure.cipher()
        return {
            "Certificate validation": validation,
            "Protocol": secure.version() or "",
            "Cipher": cipher[0] if cipher else "",
            "Certificate SHA-256": hashlib.sha256(certificate).hexdigest() if certificate else "",
        }


def audit_site(target: str, *, max_pages: int = 25, max_depth: int = 2,
               timeout: float = 5.0, excluded_paths: tuple[str, ...] = (),
               allowed_hosts: tuple[str, ...] = (), user_agent: str = "Advanced-IP-Analyser/2 web-audit",
               request_headers: dict[str, str] | None = None,
               progress: Callable[[int, str], None] | None = None) -> WebAuditReport:
    """Crawl and audit an explicitly authorized website using bounded read-only requests."""
    target = _normal_url(target)
    max_pages = min(MAX_PAGES, max(1, int(max_pages)))
    max_depth = min(5, max(0, int(max_depth)))
    timeout = min(20.0, max(0.5, float(timeout)))
    initial = urlsplit(target)
    scope = {(initial.hostname or "").casefold()}
    scope.update(host.casefold().strip() for host in allowed_hosts if host.strip())
    excludes = tuple(path.strip() for path in excluded_paths if path.strip())
    if len(scope) > 20 or len(excludes) > 100:
        raise ValueError("web audit scope is too large")
    report = WebAuditReport(target=target, started_at=datetime.now(UTC).isoformat())
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    opener = build_opener(_SameHostRedirect(scope), HTTPSHandler(context=context))
    headers = {"User-Agent": user_agent[:256], "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
               "Connection": "close"}
    for name, value in (request_headers or {}).items():
        if (not isinstance(name, str) or not isinstance(value, str) or
                not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name) or "\r" in value or "\n" in value or
                len(value) > 2_048):
            raise ValueError("custom HTTP header is invalid")
        if name.casefold() in {"host", "content-length", "transfer-encoding", "connection"}:
            raise ValueError(f"custom {name} header is not allowed")
        headers[name] = value

    cross_origin_headers = {"user-agent", "accept", "connection"}
    initial_origin = _origin(target)

    def headers_for(url: str) -> dict[str, str]:
        """Keep credentials scoped to the original host, even for explicitly allowed neighbours."""
        if _origin(url) == initial_origin:
            return headers
        return {name: value for name, value in headers.items()
                if name.casefold() in cross_origin_headers}

    if initial.scheme == "https":
        try:
            report.tls = _tls_details(initial.hostname or "", initial.port or 443, timeout)
        except (OSError, ssl.SSLError) as error:
            report.errors.append(f"TLS metadata: {error}")

    queued = deque([(target, 0)])
    queued_urls = {target}
    seen: set[str] = set()
    finding_keys: set[tuple[str, str]] = set()
    total_bytes = 0

    def finding(severity: str, title: str, url: str, evidence: str, recommendation: str,
                category: str = "Configuration") -> None:
        key = (title, url)
        if key not in finding_keys:
            finding_keys.add(key)
            report.findings.append(WebFinding(severity, title, url, evidence[:500], recommendation, category))

    if report.tls.get("Certificate validation", "Valid") != "Valid":
        finding("High", "TLS certificate validation failed", target,
                report.tls["Certificate validation"],
                "Install a valid, trusted certificate whose name matches the target host.", "Transport")

    while queued and len(report.pages) < max_pages and total_bytes < MAX_TOTAL_BYTES:
        url, depth = queued.popleft()
        url, _fragment = urldefrag(url)
        try:
            url = _normal_url(url)
        except ValueError:
            continue
        parts = urlsplit(url)
        if (parts.hostname or "").casefold() not in scope or any(parts.path.startswith(path) for path in excludes):
            continue
        if url in seen:
            continue
        seen.add(url)
        if progress:
            progress(len(report.pages) + 1, url)
        request = Request(url, headers=headers_for(url), method="GET")
        try:
            try:
                response = opener.open(request, timeout=timeout)
            except HTTPError as error:
                if str(error.reason) == "redirect leaves the allowed host scope":
                    error.close()
                    report.errors.append(f"{url}: redirect blocked because it leaves the allowed host scope")
                    continue
                response = error
            status = getattr(response, "status", response.getcode())
            content_type = response.headers.get("Content-Type", "")[:256]
            body = response.read(min(MAX_PAGE_BYTES, MAX_TOTAL_BYTES - total_bytes))
            total_bytes += len(body)
            final_url = response.geturl()
            raw_headers = {name.casefold(): value for name, value in response.headers.items()}
            set_cookies = response.headers.get_all("Set-Cookie") or []
            response.close()
        except (OSError, TimeoutError, URLError, ValueError) as error:
            report.errors.append(f"{url}: {error}")
            continue

        document = _Document()
        if "html" in content_type.casefold() or b"<html" in body[:4096].lower():
            charset_match = re.search(r"charset=([\w.-]+)", content_type, re.IGNORECASE)
            charset = charset_match.group(1) if charset_match else "utf-8"
            try:
                document.feed(body.decode(charset, errors="replace"))
            except (LookupError, ValueError):
                document.feed(body.decode("utf-8", errors="replace"))
        technologies = _technologies(raw_headers, document)
        report.pages.append(WebPage(final_url, int(status), " ".join(document.title.split())[:300],
                                    content_type, len(body), technologies,
                                    len(document.links), len(document.forms)))

        if parts.scheme == "http":
            finding("Medium", "Cleartext HTTP in use", final_url, "Content was served without TLS.",
                    "Redirect HTTP to HTTPS and enable TLS.", "Transport")
        if parts.scheme == "https" and "strict-transport-security" not in raw_headers:
            finding("Low", "HSTS header missing", final_url, "Strict-Transport-Security was not returned.",
                    "Add an appropriate Strict-Transport-Security header after validating HTTPS everywhere.")
        for header, title, recommendation in (
            ("content-security-policy", "Content Security Policy missing", "Deploy a restrictive Content-Security-Policy."),
            ("x-content-type-options", "MIME sniffing protection missing", "Return X-Content-Type-Options: nosniff."),
            ("referrer-policy", "Referrer Policy missing", "Return an appropriate Referrer-Policy."),
        ):
            if header not in raw_headers:
                finding("Low", title, final_url, f"The {header} response header was not returned.", recommendation)
        if ("x-frame-options" not in raw_headers and
                "frame-ancestors" not in raw_headers.get("content-security-policy", "").casefold()):
            finding("Low", "Clickjacking protection missing", final_url,
                    "Neither X-Frame-Options nor CSP frame-ancestors was returned.",
                    "Restrict framing with CSP frame-ancestors or X-Frame-Options.")
        if raw_headers.get("access-control-allow-origin", "").strip() == "*":
            finding("Info", "Wildcard CORS policy", final_url, "Access-Control-Allow-Origin: *",
                    "Confirm that public cross-origin read access is intended.")
        for disclosure in ("server", "x-powered-by"):
            if raw_headers.get(disclosure):
                finding("Info", "Server technology disclosed", final_url,
                        f"{disclosure}: {raw_headers[disclosure]}",
                        "Remove unnecessary version/product disclosure where practical.", "Information disclosure")
        for cookie in set_cookies:
            cookie_lower = cookie.casefold()
            name = cookie.split("=", 1)[0].strip()[:80] or "cookie"
            if parts.scheme == "https" and "; secure" not in cookie_lower:
                finding("Medium", "Cookie missing Secure attribute", final_url, name,
                        "Mark sensitive cookies Secure.", "Session")
            if "; httponly" not in cookie_lower:
                finding("Low", "Cookie missing HttpOnly attribute", final_url, name,
                        "Mark session cookies HttpOnly unless script access is required.", "Session")
            if "; samesite" not in cookie_lower:
                finding("Low", "Cookie missing SameSite attribute", final_url, name,
                        "Set an appropriate SameSite policy.", "Session")
        if re.search(r"<title>\s*index of /", body.decode("latin-1", errors="ignore"), re.IGNORECASE):
            finding("Medium", "Directory listing enabled", final_url, "Page title indicates an index listing.",
                    "Disable directory listing unless it is explicitly required.", "Exposure")
        for form in document.forms:
            action = urljoin(final_url, str(form["action"]) or final_url)
            if form["password"] and urlsplit(action).scheme != "https":
                finding("High", "Password form submits without HTTPS", final_url, action,
                        "Submit credentials only to an HTTPS endpoint.", "Authentication")
            if form["password"] and str(form["method"]) == "get":
                finding("High", "Password form uses GET", final_url, action,
                        "Use POST so credentials are not placed in URLs and logs.", "Authentication")
            if str(form["method"]) == "post" and not form["csrf"]:
                finding("Info", "POST form has no visible anti-CSRF token", final_url, action,
                        "Confirm server-side CSRF defenses; token names may be application-specific.", "Request integrity")
        if parts.scheme == "https":
            for resource in document.resources:
                if urlsplit(urljoin(final_url, resource)).scheme == "http":
                    finding("Medium", "Mixed active content reference", final_url, resource,
                            "Load page resources over HTTPS.", "Transport")
                    break

        if depth < max_depth:
            for link in document.links:
                candidate = urljoin(final_url, link)
                link_parts = urlsplit(candidate)
                candidate, _fragment = urldefrag(candidate)
                if ((link_parts.hostname or "").casefold() in scope and
                        link_parts.scheme in {"http", "https"} and
                        candidate not in queued_urls and
                        len(queued_urls) < MAX_DISCOVERED_URLS):
                    queued_urls.add(candidate)
                    queued.append((candidate, depth + 1))

    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    report.findings.sort(key=lambda item: (severity_order.get(item.severity, 9), item.title, item.url))
    report.completed_at = datetime.now(UTC).isoformat()
    return report


def export_web_audit(path: Path, report: WebAuditReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.casefold() == ".json":
        path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
        return
    if path.suffix.casefold() not in {".html", ".htm"}:
        raise ValueError("web audit report must end in .json or .html")
    counts = {severity: sum(item.severity == severity for item in report.findings)
              for severity in ("High", "Medium", "Low", "Info")}
    findings = "".join(
        f"<tr><td>{escape(item.severity)}</td><td>{escape(item.title)}</td>"
        f"<td>{escape(item.url)}</td><td>{escape(item.evidence)}</td>"
        f"<td>{escape(item.recommendation)}</td></tr>" for item in report.findings)
    pages = "".join(
        f"<tr><td>{page.status}</td><td>{escape(page.url)}</td><td>{escape(page.title)}</td>"
        f"<td>{escape(', '.join(page.technologies))}</td><td>{page.size}</td></tr>"
        for page in report.pages)
    path.write_text("<!doctype html><meta charset=utf-8><title>Web security audit</title>"
                    "<style>body{font:14px system-ui;margin:2rem;color:#17324d}table{border-collapse:collapse;width:100%}"
                    "th,td{border:1px solid #bdd1df;padding:.5rem;text-align:left;vertical-align:top}th{background:#102f49;color:white}"
                    ".summary{padding:1rem;background:#e4f5ff}</style>"
                    f"<h1>Web security audit</h1><p><b>Target:</b> {escape(report.target)}</p>"
                    f"<p class=summary>High {counts['High']} · Medium {counts['Medium']} · Low {counts['Low']} · Info {counts['Info']}</p>"
                    "<h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>URL</th><th>Evidence</th><th>Recommendation</th></tr>"
                    f"{findings}</table><h2>Pages</h2><table><tr><th>Status</th><th>URL</th><th>Title</th><th>Technology</th><th>Bytes</th></tr>{pages}</table>",
                    encoding="utf-8")
