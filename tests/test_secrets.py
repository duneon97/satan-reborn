import json
import unittest

from satan_reborn.checks.hardcoded_secrets import analyze
from satan_reborn.models import Severity, Source


class SecretTests(unittest.TestCase):
    def test_fake_aws_key_is_critical_and_masked(self):
        fake = "AKIA" + "EXAMPLEFAKE00000"
        findings = analyze(Source("app.py", f'# demo\nAWS_KEY = "{fake}"'))
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity, Severity.CRYPT)
        self.assertEqual(finding.line, 2)
        self.assertEqual(finding.evidence, "[REDACTED]")
        self.assertNotIn(fake, json.dumps(finding.to_dict()))

    def test_fake_temporary_aws_key(self):
        findings = analyze(Source(".env", "ASIA" + "EXAMPLEFAKE00000"))
        self.assertEqual(findings[0].rule_id, "secret.aws")

    def test_fake_github_tokens(self):
        for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"):
            with self.subTest(prefix=prefix):
                fake = prefix + "FAKEPLACEHOLDER" + "0" * 30
                findings = analyze(Source("secrets.txt", fake))
                self.assertEqual(findings[0].rule_id, "secret.github")
                self.assertNotIn(fake, str(findings))

    def test_private_key_variants(self):
        for kind in ("", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED "):
            with self.subTest(kind=kind):
                text = f"-----BEGIN {kind}PRIVATE KEY-----\nFAKE-NOT-A-KEY"
                finding = analyze(Source("fake.pem", text))[0]
                self.assertEqual(finding.line, 1)
                self.assertEqual(finding.rule_id, "secret.private-key")
                self.assertNotIn("FAKE-NOT-A-KEY", str(finding))

    def test_high_entropy_sensitive_assignments(self):
        for name in ("API_SECRET", "token", "api_key", "password", "db_password"):
            with self.subTest(name=name):
                fake = "FAKE-only-placeholder-9x7Q2m8R4v6T"
                findings = analyze(Source("settings.py", f'{name} = "{fake}"'))
                self.assertEqual(findings[0].rule_id, "secret.entropy")
                self.assertEqual(findings[0].severity, Severity.HAUNT)
                self.assertNotIn(fake, str(findings))

    def test_json_assignment(self):
        self.assertTrue(analyze(Source("config.json", '{"token":"FAKE-demo-9x7Q2m8R4v6T3c5Y"}')))

    def test_low_entropy_and_ordinary_strings_are_not_secrets(self):
        text = 'password = "' + "a" * 40 + '"\n'
        text += 'greeting = "FAKE-only-placeholder-9x7Q2m8R4v6T"'
        self.assertEqual(analyze(Source("app.py", text)), [])

    def test_specific_token_does_not_duplicate_entropy(self):
        fake = "ghp_" + "FAKEPLACEHOLDER" + "0" * 30
        findings = analyze(Source("app.py", f'github_token = "{fake}"'))
        self.assertEqual(len(findings), 1)
