import http.client
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from satan_reborn.server import make_handler, serve


class ServerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.report = Path(temporary.name) / "report.html"
        self.report.write_text("<!doctype html><title>FAKE report</title>", encoding="utf-8")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.report))
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True,
        )
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path="/", method="GET"):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_report_and_security_headers(self):
        status, headers, body = self.request()
        self.assertEqual(status, 200)
        self.assertIn(b"FAKE report", body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_no_source_files_traversal_or_directory_listing(self):
        for path in ("/report.html", "/app.py", "/../app.py", "/%2e%2e/app.py", "/reports/"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)

    def test_head_and_index(self):
        status, headers, body = self.request("/index.html?refresh=1", "HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertGreater(int(headers["Content-Length"]), 0)

    def test_report_refresh_and_missing_report(self):
        self.report.write_text("new report")
        self.assertEqual(self.request()[2], b"new report")
        self.report.unlink()
        self.assertEqual(self.request()[0], 404)

    def test_serve_always_binds_loopback(self):
        with patch("satan_reborn.server.ThreadingHTTPServer") as server:
            server.return_value.__enter__.return_value.serve_forever.side_effect = KeyboardInterrupt
            serve(self.report, 1995)
        self.assertEqual(server.call_args.args[0], ("127.0.0.1", 1995))
