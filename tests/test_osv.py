import io
import json
import unittest
from http.client import IncompleteRead
from urllib.error import URLError
from unittest.mock import patch

from satan_reborn.checks.dependencies import Dependency
from satan_reborn.models import Severity
from satan_reborn.osv import MAX_RESPONSE, OSVClient


class OSVTests(unittest.TestCase):
    def setUp(self):
        self.dep = Dependency("PyPI", "fake-demo", "1.2.3", "requirements.txt", 4)

    def response(self, data):
        return io.BytesIO(json.dumps(data).encode())

    def test_payload_contains_only_package_metadata_and_is_cached(self):
        client = OSVClient()
        with patch.object(client.opener, "open", return_value=self.response({"vulns": []})) as opened:
            self.assertEqual(client.query(self.dep), [])
            self.assertEqual(client.query(self.dep), [])
        opened.assert_called_once()
        req = opened.call_args.args[0]
        self.assertEqual(req.full_url, "https://api.osv.dev/v1/query")
        self.assertEqual(req.method, "POST")
        self.assertEqual(json.loads(req.data), {
            "package": {"ecosystem": "PyPI", "name": "fake-demo"}, "version": "1.2.3",
        })
        self.assertEqual(opened.call_args.kwargs["timeout"], 3.0)

    def test_osv_findings_and_severity_mapping(self):
        for standard, spooky in (("CRITICAL", Severity.CRYPT), ("HIGH", Severity.HAUNT),
                                 ("MODERATE", Severity.SPOOK), ("LOW", Severity.WHISPER),
                                 ("unknown", Severity.HAUNT)):
            with self.subTest(standard=standard):
                client = OSVClient()
                data = {"vulns": [{"id": "DEMO-2026-0001", "database_specific": {"severity": standard}}]}
                with patch.object(client.opener, "open", return_value=self.response(data)):
                    finding = client.findings(self.dep)[0]
                self.assertEqual(finding.severity, spooky)
                self.assertEqual(finding.file, "requirements.txt")
                self.assertEqual(finding.line, 4)
                self.assertEqual(finding.cwe, "CWE-1395")

    def test_offline_is_graceful_and_only_tried_once(self):
        client = OSVClient()
        with patch.object(client.opener, "open", side_effect=URLError("FAKE-sensitive-detail")) as opened:
            self.assertEqual(client.findings(self.dep), [])
            self.assertEqual(client.query(Dependency("npm", "fake", "1.0.0", "package.json", 1)), [])
        opened.assert_called_once()
        self.assertTrue(client.offline)
        self.assertEqual(len(client.warnings), 1)
        self.assertNotIn("FAKE-sensitive-detail", str(client.warnings))

    def test_bad_responses_do_not_crash(self):
        for data in (b"not-json", b"[]", b'{"vulns":{}}', b'{"vulns":[null]}', b"x" * (MAX_RESPONSE + 1)):
            with self.subTest(size=len(data)):
                client = OSVClient()
                with patch.object(client.opener, "open", return_value=io.BytesIO(data)):
                    self.assertEqual(client.query(self.dep), [])
                self.assertTrue(client.warnings)

    def test_interrupted_http_response_is_offline_not_a_crash(self):
        client = OSVClient()
        with patch.object(client.opener, "open", side_effect=IncompleteRead(b"partial")):
            self.assertEqual(client.query(self.dep), [])
        self.assertTrue(client.offline)
        self.assertNotIn("partial", str(client.warnings))

    def test_withdrawn_advisory_and_untrusted_text(self):
        client = OSVClient()
        with patch.object(client, "query", return_value=[
            {"id": "DEMO-WITHDRAWN", "withdrawn": "2026-01-01"},
            {"id": "<script>alert(1)</script>", "summary": "FAKE-secret-not-to-echo"},
        ]):
            findings = client.findings(self.dep)
        self.assertEqual(len(findings), 1)
        self.assertIn("OSV-advisory", findings[0].title)
        self.assertNotIn("FAKE-secret", str(findings))

    def test_query_budget(self):
        client = OSVClient(max_queries=1)
        with patch.object(client.opener, "open", return_value=self.response({})) as opened:
            client.query(self.dep)
            client.query(Dependency("npm", "fake", "1.0.0", "package.json", 1))
        opened.assert_called_once()
        self.assertIn("query limit", client.warnings[0])
