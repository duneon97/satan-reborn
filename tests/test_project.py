import ast
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from satan_reborn.models import Severity
from satan_reborn.scanner import scan

PROJECT = Path(__file__).resolve().parents[1]


class ProjectTests(unittest.TestCase):
    def test_package_and_tests_use_python_310_syntax(self):
        for directory in ("satan_reborn", "tests"):
            for path in sorted((PROJECT / directory).rglob("*.py")):
                with self.subTest(file=path.relative_to(PROJECT).as_posix()):
                    ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 10))

    def test_two_kiro_hooks_use_standalone_schema_and_safe_triggers(self):
        paths = sorted((PROJECT / ".kiro/hooks").glob("*.json"))
        self.assertEqual(len(paths), 2)
        hooks = []
        for path in paths:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["version"], "v1")
            hooks.extend(data["hooks"])
        self.assertEqual(len(hooks), 2)
        for hook in hooks:
            self.assertEqual(hook["trigger"], "PostFileSave")
            self.assertEqual(hook["action"]["type"], "command")
            self.assertNotIn("--osv", hook["action"]["command"])
            self.assertFalse(re.search(hook["matcher"], "reports/haunted.html"))
        test_hook = next(h for h in hooks if "unittest" in h["action"]["command"])
        self.assertTrue(re.search(test_hook["matcher"], "satan_reborn/models.py"))
        rescan = next(h for h in hooks if "haunted_app" in h["action"]["command"])
        self.assertTrue(re.search(rescan["matcher"], "/repo/satan_reborn/report.py"))
        self.assertTrue(re.search(rescan["matcher"], "examples/haunted_app/Dockerfile"))
        self.assertTrue(re.search(rescan["matcher"], r"C:\repo\satan_reborn\models.py"))

    def test_demo_exercises_every_local_rule(self):
        report = scan(PROJECT / "examples/haunted_app")
        self.assertEqual({f.rule_id for f in report.findings}, {
            "secret.aws", "secret.github", "secret.private-key", "secret.entropy",
            "config.docker-root", "config.chmod", "config.curl-shell", "config.debug", "config.http",
            "code.dynamic-execution", "code.shell", "code.pickle", "code.yaml", "code.password-hash",
            "deps.unpinned",
        })
        self.assertTrue(all(f.advice and re.fullmatch(r"CWE-\d+", f.cwe) and f.line >= 1
                            for f in report.findings))
        self.assertEqual(report.warnings, [])
        self.assertEqual({f.severity for f in report.findings}, set(Severity))

    def test_demo_is_fake_text_with_a_fail_closed_guard(self):
        fixture = PROJECT / "examples/haunted_app"
        text = (fixture / "app.py").read_text(encoding="utf-8")
        tree = ast.parse(text)
        guard = tree.body[1]
        self.assertIsInstance(guard, ast.Raise)
        self.assertIsInstance(guard.exc, ast.Call)
        self.assertEqual(guard.exc.func.id, "SystemExit")
        self.assertIn("FAKE", guard.exc.args[0].value)
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    self.assertIn("FAKE", node.value.value)
        for filename in ("app.py", "requirements.txt", "Dockerfile", "README.md"):
            self.assertIn("DO NOT", (fixture / filename).read_text(encoding="utf-8").upper())
        urls = re.findall(r"https?://([^/\s]+)", (fixture / "settings.env").read_text()
                          + (fixture / "Dockerfile").read_text())
        self.assertTrue(urls)
        self.assertTrue(all(host.endswith(".invalid") for host in urls))

    def test_rescan_hook_command_accepts_findings_and_preserves_errors(self):
        data = json.loads((PROJECT / ".kiro/hooks/rescan-example-on-save.json").read_text())
        command = shlex.split(data["hooks"][0]["action"]["command"])
        self.assertEqual(command[0], "python")
        command[0] = sys.executable
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(PROJECT)
        for exists in (True, False):
            with self.subTest(fixture_exists=exists), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if exists:
                    shutil.copytree(PROJECT / "examples/haunted_app", root / "examples/haunted_app")
                result = subprocess.run(command, cwd=root, env=environment,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0 if exists else 2, result.stderr)
                output = root / "reports/haunted.json"
                self.assertEqual(output.exists(), exists)
                if exists:
                    report = json.loads(output.read_text())
                    self.assertTrue(report["has_blockers"])
                    self.assertFalse(report["osv_enabled"])
                    self.assertTrue((root / "reports/haunted.html").is_file())

    def test_submission_docs_and_real_png_are_present(self):
        for filename in ("docs/DEMO_SCRIPT.md", "docs/DEVPOST.md"):
            self.assertGreater(len((PROJECT / filename).read_text(encoding="utf-8")), 1000)
        readme = (PROJECT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/screenshots/report.png", readme)
        screenshot = (PROJECT / "docs/screenshots/report.png").read_bytes()
        self.assertEqual(screenshot[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(screenshot[12:16], b"IHDR")
        width, height = struct.unpack(">II", screenshot[16:24])
        self.assertGreaterEqual(width, 1000)
        self.assertGreaterEqual(height, 800)
