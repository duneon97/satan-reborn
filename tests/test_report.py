import json
import re
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
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)
        self.elements.append((tag, dict(attrs)))


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
        self.assertIn(("aside", {"class": "triage", "aria-label": "Triage guidance"}),
                      audit.elements)
        self.assertFalse(any(key == "src" or key.startswith("on") for key, _ in audit.attributes))
        self.assertTrue(all(value.startswith("#") for key, value in audit.attributes if key == "href"))
        self.assertTrue({"script", "link", "iframe", "img", "object", "embed", "form"}.isdisjoint(audit.tags))
        self.assertIn(".py:7", html)
        self.assertIn("[REDACTED]", html)

    def test_severity_cards_jump_to_first_matching_finding_and_links_resolve(self):
        report = Report("demo", "now", findings=[
            Finding("test", severity, "Test finding", "app.py", index, "Fix it", "CWE-798")
            for index, severity in enumerate((Severity.CRYPT, Severity.CRYPT, Severity.SPOOK), 1)
        ])
        audit = HTMLAudit()
        audit.feed(render_html(report))
        ids = [attrs["id"] for _, attrs in audit.elements if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        cards = [attrs for tag, attrs in audit.elements if tag == "a"
                 and attrs.get("class", "").startswith("count ")]
        self.assertEqual([attrs["href"] for attrs in cards],
                         ["#finding-1", "#findings", "#finding-3", "#findings"])
        self.assertTrue(all(attrs["href"][1:] in ids for tag, attrs in audit.elements
                            if tag == "a" and attrs.get("href", "").startswith("#")))
        self.assertIn(("section", {"id": "findings", "tabindex": "-1",
                                  "aria-labelledby": "findings-heading"}), audit.elements)
        region = next(attrs for _, attrs in audit.elements if attrs.get("role") == "region")
        self.assertEqual(region["tabindex"], "0")

    def test_triage_and_coverage_are_independent_of_score(self):
        report = Report("demo", "now", warnings=["Unreadable <FAKE> file"])
        html = render_html(report)
        self.assertIn("NO HIGH-SEVERITY SIGNALS", html)
        self.assertIn("COVERAGE NEEDS REVIEW", html)
        self.assertIn('href="#warning-heading"', html)
        self.assertIn("Unreadable &lt;FAKE&gt; file", html)
        self.assertIn("not a security guarantee", html)
        self.assertIn("clear-status", html)
        report.findings.append(Finding("test", Severity.HAUNT, "Test", "a.py", 1, "Fix", "CWE-95"))
        html = render_html(report)
        self.assertIn("1 critical/high finding(s)", html)
        self.assertIn('class="integrity compromised"', html)

    def test_disclosures_have_context_and_motion_is_bounded(self):
        html = render_html(Report("demo", "now", findings=[
            Finding("test", Severity.HAUNT, "Unsafe call", "a.py", 9, "Use a parser", "CWE-95")
        ]))
        self.assertIn('class="sr-only"> for Unsafe call at a.py:9', html)
        self.assertNotIn("infinite", html)
        self.assertIn("animation:blink 1s steps(1,end) 4", html)
        self.assertIn("animation:flicker 4s linear 1", html)
        self.assertIn("transition:none!important;scroll-behavior:auto!important", html)
        self.assertIn("@media(forced-colors:active)", html)
        self.assertIn(":focus-visible{outline:", html)
        self.assertIn("details::details-content{content-visibility:visible", html)
        self.assertFalse(re.search(r"url\s*\(|@import", html, re.I))

    def test_empty_state(self):
        html = render_html(Report("clean", "now"))
        self.assertIn("No apparitions detected", html)
        self.assertIn('value="100"', html)
        self.assertNotIn("COVERAGE NEEDS REVIEW", html)

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
