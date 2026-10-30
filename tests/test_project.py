import ast
import json
import re
import unittest
from pathlib import Path

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
