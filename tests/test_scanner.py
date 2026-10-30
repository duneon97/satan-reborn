import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from satan_reborn.models import Finding, Report, Severity
from satan_reborn.scanner import MAX_FILE_BYTES, scan


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_offline_by_default_and_source_never_runs(self):
        self.write("app.py", "raise RuntimeError('DO NOT EXECUTE')\neval(user_input)\n")
        with patch("satan_reborn.scanner.OSVClient", side_effect=AssertionError("network used")):
            report = scan(self.root)
        self.assertEqual(report.files_scanned, 1)
        self.assertTrue(report.has_blockers)
        self.assertEqual(report.findings[0].line, 2)
        self.assertFalse(report.osv_enabled)

    def test_ignored_directories_binary_files_large_files_and_symlinks(self):
        self.write("safe.py", "x = 1\n")
        for directory in (".git", "node_modules", ".venv", "reports", "__pycache__"):
            self.write(f"{directory}/bad.py", "eval(untrusted)")
        (self.root / "binary.dat").write_bytes(b"\0eval(untrusted)")
        (self.root / "large.txt").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
        self.write("photo.png", "eval(untrusted)")
        self.write("old.satan.html", "eval(untrusted)")
        if hasattr(os, "symlink"):
            (self.root / "linked.py").symlink_to(self.root / "safe.py")
            (self.root / "linked-directory").symlink_to(self.root / ".git", target_is_directory=True)
        report = scan(self.root)
        self.assertEqual(report.files_scanned, 1)
        self.assertEqual(report.findings, [])
        self.assertGreaterEqual(report.files_skipped, 4)
        self.assertIn("oversized", str(report.warnings))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_fifo_is_skipped_without_hanging(self):
        os.mkfifo(self.root / "input.fifo")
        report = scan(self.root)
        self.assertEqual(report.files_scanned, 0)
        self.assertEqual(report.files_skipped, 1)

    def test_explicit_outputs_are_excluded(self):
        self.write("safe.py", "pass")
        output = self.write("audit.html", "FAKE AWS " + "AKIA" + "EXAMPLEFAKE00000")
        self.assertEqual(scan(self.root, exclude_paths=[output]).findings, [])

    def test_utf8_bom_and_non_utf8(self):
        (self.root / "app.py").write_bytes(b"\xef\xbb\xbfeval(x)")
        (self.root / "legacy.dat").write_bytes(b"\xff\xfeold")
        report = scan(self.root)
        self.assertEqual(report.files_scanned, 1)
        self.assertEqual(report.files_skipped, 1)
        self.assertEqual(report.findings[0].line, 1)

    def test_invalid_python_preserves_text_checks_and_warns(self):
        self.write("broken.py", 'def broken syntax\nSECRET = "FAKE-only-placeholder-9x7Q2m8R4v6T"\n')
        report = scan(self.root)
        self.assertTrue(report.findings)
        self.assertIn("AST checks skipped", report.warnings[0])

    def test_missing_or_file_target_is_an_error(self):
        file = self.write("file.py", "pass")
        for target in (self.root / "missing", file):
            with self.assertRaises(ValueError):
                scan(target)

    def test_osv_opt_in_uses_pinned_versions(self):
        self.write("requirements.txt", "Flask\nrequests==2.19.1")
        with patch("satan_reborn.scanner.OSVClient") as client:
            client.return_value.findings.return_value = []
            client.return_value.warnings = ["OSV offline (test)"]
            report = scan(self.root, osv=True)
        dependency = client.return_value.findings.call_args.args[0]
        self.assertEqual(dependency.name, "requests")
        self.assertEqual(dependency.version, "2.19.1")
        self.assertTrue(report.osv_enabled)
        self.assertEqual(report.warnings, ["OSV offline (test)"])
        self.assertEqual(report.findings[0].rule_id, "deps.unpinned")

    def test_order_and_no_secret_values_in_json(self):
        fake = "AKIA" + "EXAMPLEFAKE00000"
        self.write("a.py", "eval(data)\n")
        self.write("nested/b.env", f'key = "{fake}"\n')
        report = scan(self.root)
        self.assertEqual([f.severity for f in report.findings], [Severity.CRYPT, Severity.HAUNT])
        self.assertEqual(report.findings[0].file, "nested/b.env")
        self.assertNotIn(fake, json.dumps(report.to_dict()))


class ModelTests(unittest.TestCase):
    def test_severity_mapping_and_score(self):
        report = Report("demo", "2026-10-30T00:00:00+00:00")
        self.assertEqual(report.soul_integrity, 100)
        self.assertFalse(report.has_blockers)
        for severity in Severity:
            report.findings.append(Finding("test", severity, "test", "x", 1, "fix", "CWE-798"))
        self.assertEqual(report.soul_integrity, 57)
        self.assertEqual(report.counts, {"CRYPT": 1, "HAUNT": 1, "SPOOK": 1, "WHISPER": 1})
        self.assertEqual([f["standard_severity"] for f in report.to_dict()["findings"]],
                         ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_score_is_clamped_to_zero(self):
        finding = Finding("test", Severity.CRYPT, "test", "x", 1, "fix", "CWE-798")
        report = Report("demo", "now", findings=[finding] * 10)
        self.assertEqual(report.soul_integrity, 0)
