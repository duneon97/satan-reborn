import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()

    def invoke(self, *args):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(PROJECT)
        return subprocess.run([sys.executable, "-m", "satan_reborn", *map(str, args)],
                              cwd=self.root, env=environment, capture_output=True,
                              text=True, timeout=15)

    def test_haunted_scan_exits_one_and_exports_both_reports(self):
        result = self.invoke("scan", PROJECT / "examples/haunted_app",
                             "--html", "reports/demo.html", "--json", "reports/demo.json")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Soul Integrity", result.stdout)
        data = json.loads((self.root / "reports/demo.json").read_text())
        self.assertGreater(data["counts"]["CRYPT"], 0)
        self.assertGreater(data["counts"]["HAUNT"], 0)
        self.assertGreater(data["counts"]["SPOOK"], 0)
        self.assertGreater(data["counts"]["WHISPER"], 0)
        self.assertEqual((self.root / "reports/demo.html").read_bytes(),
                         (self.root / "reports/last-report.html").read_bytes())
        fake = "AKIA" + "EXAMPLEFAKE00000"
        self.assertNotIn(fake, result.stdout + json.dumps(data))
        self.assertNotIn(fake, (self.root / "reports/demo.html").read_text())

    def test_clean_scan_exits_zero_and_creates_last_report(self):
        (self.target / "clean.py").write_text("print('boo')")
        result = self.invoke("scan", self.target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("100/100", result.stdout)
        self.assertTrue((self.root / "reports/last-report.html").is_file())

    def test_only_low_medium_findings_exit_zero(self):
        (self.target / "requirements.txt").write_text("Flask")
        (self.target / "config.ini").write_text("url=http://example.invalid")
        result = self.invoke("scan", self.target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SPOOK=1", result.stdout)
        self.assertIn("WHISPER=1", result.stdout)

    def test_invalid_target_exits_two_without_traceback(self):
        result = self.invoke("scan", self.root / "missing")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_same_html_json_path_is_rejected_before_writing(self):
        result = self.invoke("scan", self.target, "--html", "same", "--json", "./same")
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / "same").exists())

    def test_invalid_port_and_missing_report(self):
        for args in (("serve", "--port", "70000"), ("serve", "--port", "nope"), ("serve",)):
            result = self.invoke(*args)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("Traceback", result.stderr)

    def test_cli_escapes_terminal_control_characters_in_filenames(self):
        if os.name == "nt":
            self.skipTest("Windows filenames do not support these characters")
        (self.target / "evil\x1b[31m.py").write_text("eval(x)")
        result = self.invoke("scan", self.target)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("\x1b", result.stdout)
        self.assertIn("\\x1b", result.stdout)

    def test_help_and_version(self):
        result = self.invoke("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("serve", result.stdout)
        result = self.invoke("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("1.0.0", result.stdout)
