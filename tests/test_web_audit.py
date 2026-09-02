from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tempfile
import threading
from pathlib import Path
import unittest

from ip_analyser.web_audit import audit_site, export_web_audit


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/next":
            body = b"<html><title>Next</title><p>done</p></html>"
        else:
            body = (b"<html><title>Index of /</title><a href='/next'>next</a>"
                    b"<form method='get' action='http://example.invalid/login'>"
                    b"<input type='password' name='password'></form>"
                    b"<script src='http://example.invalid/app.js'></script></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Example/1.2")
        self.send_header("Set-Cookie", "session=abc")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class _HeaderCaptureHandler(BaseHTTPRequestHandler):
    received_headers = None

    def do_GET(self):
        type(self).received_headers = self.headers
        body = b"<html><title>Neighbour</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class _RedirectHandler(BaseHTTPRequestHandler):
    destination = ""

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", type(self).destination)
        self.end_headers()

    def log_message(self, _format, *_args):
        pass


class WebAuditTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_bounded_crawl_and_safe_configuration_findings(self):
        report = audit_site(self.url, max_pages=5, max_depth=1, timeout=2)
        self.assertEqual(len(report.pages), 2)
        titles = {finding.title for finding in report.findings}
        self.assertIn("Cleartext HTTP in use", titles)
        self.assertIn("Directory listing enabled", titles)
        self.assertIn("Password form uses GET", titles)
        self.assertIn("Content Security Policy missing", titles)
        self.assertIn("Server technology disclosed", titles)

    def test_excluded_paths_and_report_exports(self):
        report = audit_site(self.url, max_pages=5, max_depth=2, excluded_paths=("/next",))
        self.assertEqual(len(report.pages), 1)
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            html_path = Path(directory) / "report.html"
            export_web_audit(json_path, report)
            export_web_audit(html_path, report)
            self.assertIn('"findings"', json_path.read_text(encoding="utf-8"))
            self.assertIn("Web security audit", html_path.read_text(encoding="utf-8"))

    def test_invalid_or_credential_bearing_urls_are_rejected(self):
        with self.assertRaises(ValueError):
            audit_site("ftp://example.test/")
        with self.assertRaises(ValueError):
            audit_site("https://user:secret@example.test/")
        with self.assertRaises(ValueError):
            audit_site(self.url, request_headers={"X-Test": "line1\r\nX-Evil: yes"})

    def test_sensitive_custom_headers_are_not_forwarded_to_allowed_neighbours(self):
        neighbour = ThreadingHTTPServer(("localhost", 0), _HeaderCaptureHandler)
        neighbour_thread = threading.Thread(target=neighbour.serve_forever, daemon=True)
        neighbour_thread.start()
        try:
            neighbour_url = f"http://localhost:{neighbour.server_port}/"
            report = audit_site(
                neighbour_url,
                allowed_hosts=("127.0.0.1",),
                request_headers={"Authorization": "Bearer secret", "Cookie": "session=secret"},
            )
            self.assertEqual(len(report.pages), 1)

            # The initial host is allowed to receive explicitly supplied credentials.
            received = _HeaderCaptureHandler.received_headers
            self.assertEqual(received.get("Authorization"), "Bearer secret")
            self.assertEqual(received.get("Cookie"), "session=secret")

            # A direct audit of the neighbour exercises the host-scoping helper through a linked page.
            class _LinkHandler(_Handler):
                def do_GET(self):
                    body = f"<html><a href='{neighbour_url}'>neighbour</a></html>".encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(body)

            origin = ThreadingHTTPServer(("127.0.0.1", 0), _LinkHandler)
            origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
            origin_thread.start()
            try:
                _HeaderCaptureHandler.received_headers = None
                audit_site(
                    f"http://127.0.0.1:{origin.server_port}/",
                    max_pages=2,
                    max_depth=1,
                    allowed_hosts=("localhost",),
                    request_headers={"Authorization": "Bearer secret", "Cookie": "session=secret"},
                )
                received = _HeaderCaptureHandler.received_headers
                self.assertIsNotNone(received)
                self.assertIsNone(received.get("Authorization"))
                self.assertIsNone(received.get("Cookie"))
            finally:
                origin.shutdown()
                origin.server_close()
                origin_thread.join(timeout=2)

            redirector = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
            redirect_thread = threading.Thread(target=redirector.serve_forever, daemon=True)
            _RedirectHandler.destination = neighbour_url
            redirect_thread.start()
            try:
                _HeaderCaptureHandler.received_headers = None
                audit_site(
                    f"http://127.0.0.1:{redirector.server_port}/",
                    allowed_hosts=("localhost",),
                    request_headers={"Authorization": "Bearer secret", "Cookie": "session=secret"},
                )
                received = _HeaderCaptureHandler.received_headers
                self.assertIsNotNone(received)
                self.assertIsNone(received.get("Authorization"))
                self.assertIsNone(received.get("Cookie"))
            finally:
                redirector.shutdown()
                redirector.server_close()
                redirect_thread.join(timeout=2)
        finally:
            neighbour.shutdown()
            neighbour.server_close()
            neighbour_thread.join(timeout=2)

    def test_redirect_outside_scope_is_blocked_and_not_reported_as_crawled(self):
        redirector = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        redirect_thread = threading.Thread(target=redirector.serve_forever, daemon=True)
        _RedirectHandler.destination = "http://example.invalid/outside"
        redirect_thread.start()
        try:
            report = audit_site(f"http://127.0.0.1:{redirector.server_port}/")
            self.assertEqual(report.pages, [])
            self.assertTrue(any("redirect blocked" in error for error in report.errors))
        finally:
            redirector.shutdown()
            redirector.server_close()
            redirect_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
