import unittest

from satan_reborn.checks import insecure_config, risky_code
from satan_reborn.models import Severity, Source


class ConfigTests(unittest.TestCase):
    def test_docker_missing_user(self):
        findings = insecure_config.analyze(Source("Dockerfile", "# hello\nFROM python:3.10\nRUN true\n"))
        self.assertEqual([(f.rule_id, f.line) for f in findings], [("config.docker-root", 2)])

    def test_docker_root_variants(self):
        for user in ("root", "0", "0:1000", "root:root"):
            with self.subTest(user=user):
                findings = insecure_config.analyze(Source("Dockerfile", f"FROM base\nUSER {user}\n"))
                self.assertEqual(findings[0].rule_id, "config.docker-root")

    def test_docker_nonroot_and_last_user(self):
        for text in ("FROM base\nUSER 1000:1000", "FROM base\nUSER root\nUSER app"):
            self.assertEqual(insecure_config.analyze(Source("Dockerfile", text)), [])

    def test_docker_each_stage_resets_user(self):
        text = "FROM base AS build\nUSER 1000\nFROM base\nCOPY --from=build /x /x\n"
        findings = insecure_config.analyze(Source("Dockerfile.prod", text))
        self.assertEqual([f.line for f in findings], [3])

    def test_debug_assignments_and_flask_call(self):
        text = "DEBUG = True\napp.run(\n debug=True\n)\napp.config['DEBUG'] = True\n"
        findings = insecure_config.analyze(Source("settings.py", text))
        self.assertEqual([f.line for f in findings], [1, 3, 5])
        self.assertTrue(all(f.cwe == "CWE-489" for f in findings))

    def test_debug_attributes_annotations_and_safe_negatives(self):
        text = (
            "config.DEBUG = True\n"
            "app.config.DEBUG: bool = True\n"
            "settings.debug = True\n"
            "config.DEBUG = False\n"
            "config.NOT_DEBUG = True\n"
            "example = 'config.DEBUG = True'\n"
            "# config.DEBUG = True\n"
        )
        findings = insecure_config.analyze(Source("config.py", text))
        self.assertEqual([(f.rule_id, f.line) for f in findings],
                         [("config.debug", 1), ("config.debug", 2), ("config.debug", 3)])

    def test_safe_config_and_comments(self):
        text = "# chmod 777 foo\n# curl https://example.invalid | sh\nDEBUG = False\n"
        self.assertEqual(insecure_config.analyze(Source("settings.py", text)), [])

    def test_shell_patterns(self):
        text = "chmod -R 0777 /app\ncurl -fsSL https://example.invalid/install | sudo bash\n"
        findings = insecure_config.analyze(Source("setup.sh", text))
        self.assertEqual([f.rule_id for f in findings], ["config.chmod", "config.curl-shell"])
        self.assertEqual([f.line for f in findings], [1, 2])

    def test_http_configs_only(self):
        for name in ("settings.env", ".env.production", "app.toml", "config.py"):
            findings = insecure_config.analyze(Source(name, 'endpoint = "http://example.invalid"'))
            self.assertEqual(findings[0].severity, Severity.SPOOK)
        self.assertEqual(insecure_config.analyze(Source("README.md", "http://example.invalid")), [])
        self.assertEqual(insecure_config.analyze(Source("app.yaml", "url: https://example.invalid")), [])


class RiskyCodeTests(unittest.TestCase):
    def rules(self, text):
        return [f.rule_id for f in risky_code.analyze(Source("app.py", text))]

    def test_dynamic_execution(self):
        self.assertEqual(self.rules("eval(value)\nexec(value)"),
                         ["code.dynamic-execution", "code.dynamic-execution"])

    def test_subprocess_alias_and_multiline(self):
        text = "import subprocess as sp\nsp.run(\n value,\n shell=True\n)\n"
        findings = risky_code.analyze(Source("app.py", text))
        self.assertEqual(findings[0].rule_id, "code.shell")
        self.assertEqual(findings[0].line, 2)

    def test_from_import_alias(self):
        self.assertEqual(self.rules("from subprocess import run as invoke\ninvoke(x, shell=True)"),
                         ["code.shell"])
        self.assertEqual(self.rules("from pickle import loads as restore\nrestore(blob)"),
                         ["code.pickle"])

    def test_pickle(self):
        self.assertEqual(self.rules("import pickle\npickle.loads(blob)\npickle.load(stream)"),
                         ["code.pickle", "code.pickle"])

    def test_yaml_unsafe_loaders(self):
        for call in ("yaml.load(x)", "yaml.load(x, Loader=yaml.Loader)", "yaml.load(x, yaml.FullLoader)"):
            with self.subTest(call=call):
                self.assertEqual(self.rules("import yaml\n" + call), ["code.yaml"])

    def test_yaml_safe_loaders_and_aliases(self):
        for text in (
            "import yaml\nyaml.safe_load(x)",
            "import yaml\nyaml.load(x, Loader=yaml.SafeLoader)",
            "import yaml as y\ny.load(x, y.CSafeLoader)",
            "from yaml import load, SafeLoader as S\nload(x, Loader=S)",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.rules(text), [])

    def test_weak_password_hashes(self):
        for text in (
            "import hashlib\nhashlib.md5(password.encode())",
            "from hashlib import sha1 as digest\npassword_hash = digest(value)",
            "import hashlib\nhashlib.new('sha-1', password)",
            "import hashlib\ndef hash_password(data):\n return hashlib.md5(data)",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.rules(text), ["code.password-hash"])

    def test_safe_code_comments_strings_and_checksum(self):
        text = (
            "import hashlib, subprocess\n"
            "# eval(untrusted)\n"
            "example = 'exec(user_input)'\n"
            "subprocess.run(['echo', 'safe'], shell=False)\n"
            "checksum = hashlib.md5(content)\n"
        )
        self.assertEqual(self.rules(text), [])

    def test_nonpython_and_invalid_python(self):
        self.assertEqual(risky_code.analyze(Source("README.md", "eval(x)")), [])
        self.assertEqual(self.rules("def not valid python"), [])
