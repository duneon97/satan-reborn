import json
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from satan_reborn.models import Finding, Report, Severity
from satan_reborn.report import render_html, write_json, write_text_atomic


class HTMLAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)


class ReportTests(unittest.TestCase):
    def test_report_is_self_contained_accessible_and_escaped(self):
        payload = '<script>alert("FAKE")</script>'
        report = Report(payload, "2026-10-30", findings=[
            Finding("test", Severity.CRYPT, payload, payload + ".py", 7, payload, "CWE-798", "[REDACTED]")
        ], warnings=[payload])
        html = render_html(report)
        audit = HTMLAudit()
        audit.feed(html)
        self.assertNotIn("script", audit.tags)
        self.assertNotIn(payload, html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Soul Integrity", html)
        self.assertIn("prefers-reduced-motion:reduce", html)
        self.assertIn("animation:none!important", html)
        self.assertIn(("lang", "en"), audit.attributes)
        self.assertIn(("scope", "col"), audit.attributes)
        self.assertIn(("name", "viewport"), audit.attributes)
        self.assertIn("Content-Security-Policy", html)
        self.assertFalse(any(key == "src" or key.startswith("on") for key, _ in audit.attributes))
        self.assertIn(".py:7", html)
        self.assertIn("[REDACTED]", html)

    def test_empty_state(self):
        html = render_html(Report("clean", "now"))
        self.assertIn("No apparitions detected", html)
        self.assertIn('value="100"', html)

    def test_atomic_write_and_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "report.json"
            report = Report("demo", "now")
            write_json(report, path)
            self.assertEqual(json.loads(path.read_text())["soul_integrity"], 100)
            self.assertEqual(list(path.parent.glob(".satan-*.tmp")), [])
            write_text_atomic(path, "replacement")
            self.assertEqual(path.read_text(), "replacement")

    def test_failed_atomic_write_leaves_original_and_no_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            path.write_text("original")
            with patch("satan_reborn.report.os.replace", side_effect=OSError("test")):
                with self.assertRaises(OSError):
                    write_text_atomic(path, "replacement")
            self.assertEqual(path.read_text(), "original")
            self.assertEqual(list(path.parent.glob(".satan-*.tmp")), [])
