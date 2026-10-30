"""Loopback-only report viewer; never serves a directory or scanned source."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .report import CSP

DEFAULT_REPORT = Path("reports/last-report.html")


def make_handler(report_path):
    report_path = Path(report_path).expanduser().resolve()

    class ReportHandler(BaseHTTPRequestHandler):
        server_version = "SATAN-Reborn"
        sys_version = ""

        def do_GET(self):
            self._respond(send_body=True)

        def do_HEAD(self):
            self._respond(send_body=False)

        def _respond(self, *, send_body: bool):
            path = urlsplit(self.path).path
            if path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            if path not in {"/", "/index.html"}:
                self.send_error(404, "Only the report is available")
                return
            try:
                body = report_path.read_bytes()
            except OSError:
                self.send_error(404, "No report yet; run a scan first")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP + "; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if send_body:
                self.wfile.write(body)

        def log_message(self, _format, *args):
            # Request strings may contain control characters; do not log them.
            pass

    return ReportHandler


def serve(report_path=DEFAULT_REPORT, port: int = 1995) -> None:
    if not Path(report_path).expanduser().is_file():
        raise ValueError("No report found. Run a scan first, or pass --report to serve.")
    with ThreadingHTTPServer(("127.0.0.1", port), make_handler(report_path)) as server:
        print(f"SATAN Reborn: http://127.0.0.1:{server.server_port} (Ctrl+C to stop)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
