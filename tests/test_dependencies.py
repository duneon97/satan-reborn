import json
import unittest

from satan_reborn.checks.dependencies import analyze, pinned_dependencies
from satan_reborn.models import Severity, Source


class DependencyTests(unittest.TestCase):
    def test_requirements_unpinned_and_exact_pins(self):
        source = Source("requirements.txt", (
            "# demo\nFlask\nrequests>=2.0\nPyYAML==6.0.2\n"
            "package==1.*\n-r extra.txt\n--index-url https://example.invalid\n"
            "other[extra]==1.2.3 ; python_version >= '3.10'\n"
        ))
        findings = analyze(source)
        self.assertEqual([f.line for f in findings], [2, 3, 5])
        self.assertTrue(all(f.severity == Severity.WHISPER for f in findings))
        self.assertEqual([(d.name, d.version) for d in pinned_dependencies(source)],
                         [("pyyaml", "6.0.2"), ("other", "1.2.3")])

    def test_requirements_normalizes_pypi_names(self):
        deps = pinned_dependencies(Source("requirements-dev.txt", "My_Package.Name==1.0.0"))
        self.assertEqual(deps[0].name, "my-package-name")

    def test_exact_pins_reject_trailing_constraints_but_allow_hashes_and_markers(self):
        source = Source("requirements.txt", (
            "fake-demo==1.0 , !=1.0\n"
            "fake-demo==1.0 unexpected-text\n"
            "fake-demo==1.0 --hash=sha256:FAKE\n"
            "fake-other==2.0 ; python_version >= '3.10'\n"
            "fake-third==3.0 \\\n"
            "    --hash=sha256:FAKE\n"
        ))
        self.assertEqual([f.line for f in analyze(source)], [1, 2])
        self.assertEqual([(d.name, d.version, d.line) for d in pinned_dependencies(source)],
                         [("fake-demo", "1.0", 3), ("fake-other", "2.0", 4),
                          ("fake-third", "3.0", 5)])

    def test_editable_installs_are_unpinned_not_option_lines(self):
        source = Source("requirements.txt", "-e ../fake-demo\n--editable=../fake-other\n")
        self.assertEqual([f.line for f in analyze(source)], [1, 2])
        self.assertEqual(pinned_dependencies(source), [])

    def test_nonmanifest_is_ignored(self):
        source = Source("README.md", "Flask\nrequests==2.0")
        self.assertEqual(analyze(source), [])
        self.assertEqual(pinned_dependencies(source), [])

    def test_npm_exact_versions_only(self):
        source = Source("package.json", json.dumps({
            "dependencies": {"lodash": "4.17.15", "minimist": "^1.2.0", "@demo/fake": "1.0.0-beta.1"},
            "devDependencies": {"fake-test": "2.3.4"},
            "optionalDependencies": {"fake-extra": "1.2.3"},
        }, indent=2))
        deps = pinned_dependencies(source)
        self.assertEqual([d.name for d in deps], ["lodash", "@demo/fake", "fake-test", "fake-extra"])
        self.assertTrue(all(d.ecosystem == "npm" and d.line > 1 for d in deps))

    def test_npm_lockfile_v2_nested_and_scoped(self):
        source = Source("package-lock.json", json.dumps({"packages": {
            "": {"version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/parent/node_modules/@demo/child": {"version": "1.2.3"},
        }}, indent=2))
        self.assertEqual([d.name for d in pinned_dependencies(source)], ["lodash", "@demo/child"])

    def test_npm_lockfile_v1(self):
        source = Source("package-lock.json", json.dumps({"dependencies": {
            "parent": {"version": "1.0.0", "dependencies": {"child": {"version": "2.0.0"}}},
        }}))
        self.assertEqual([d.name for d in pinned_dependencies(source)], ["parent", "child"])

    def test_npm_lockfile_v3_ignores_links_and_handles_scoped_packages(self):
        source = Source("package-lock.json", json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "fake-demo", "version": "1.0.0"},
                "node_modules/@demo/fake": {"version": "1.2.3"},
                "node_modules/fake-link": {"link": True, "resolved": "../fake-local"},
                "node_modules/fake-range": {"version": "^2.0.0"},
            },
        }, indent=2))
        dependencies = pinned_dependencies(source)
        self.assertEqual([(d.ecosystem, d.name, d.version) for d in dependencies],
                         [("npm", "@demo/fake", "1.2.3")])
        self.assertGreater(dependencies[0].line, 1)

    def test_malformed_manifest_is_safe(self):
        for text in ("not json", "[]", '{"dependencies":null}', '{"packages":{"x":null}}'):
            with self.subTest(text=text):
                self.assertEqual(pinned_dependencies(Source("package.json", text)), [])
