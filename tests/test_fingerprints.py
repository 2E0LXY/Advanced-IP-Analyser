import http.server
import socket
import threading
import unittest

from ip_analyser.fingerprints import probe_service


class _WebHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4-test"
    sys_version = ""

    def do_GET(self):
        body = b"<!doctype html><title>Network &amp; Storage</title><h1>Ready</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "TestStack/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class FingerprintTests(unittest.TestCase):
    def test_http_metadata_includes_server_status_title_and_headers(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _WebHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            details = probe_service("127.0.0.1", server.server_port, "http", 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(details["Status"], "200 OK")
        self.assertIn("Apache/2.4-test", details["Server"])
        self.assertEqual(details["Powered by"], "TestStack/1.0")
        self.assertEqual(details["Page title"], "Network & Storage")
        self.assertIn("text/html", details["Content type"])

    def test_protocol_greeting_is_recorded_without_sending_credentials(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        received = []

        def serve():
            connection, _peer = listener.accept()
            with connection:
                connection.sendall(b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n")
                connection.settimeout(0.2)
                try:
                    received.append(connection.recv(32))
                except socket.timeout:
                    received.append(b"")

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            details = probe_service("127.0.0.1", listener.getsockname()[1], "ssh", 0.5)
        finally:
            thread.join(timeout=2)
            listener.close()
        self.assertIn("OpenSSH_9.2p1", details["Banner"])
        self.assertEqual(received, [b""])

    def test_unresponsive_or_closed_service_returns_no_metadata(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        self.assertEqual(probe_service("127.0.0.1", port, "http", 0.2), {})


if __name__ == "__main__":
    unittest.main()
