# SATAN Reborn

**Old-school paranoia. New-world code.**

A Kiroween 2026 **Resurrection** project: the spirit of the 1995 Security
Administrator Tool for Analyzing Networks (SATAN), resurrected as a modern,
offline-first security auditor for a **local code folder**.

This is a new implementation, not the original SATAN code and not a network
scanner. It never executes or imports scanned code, installs dependencies, or
probes services. Its browser report brings back black screens, red/green
terminals, an ASCII skull, a blinking cursor, and a little haunted CRT flicker.

## Features

- **15 local rules** for credential patterns, unsafe configuration, risky Python
  APIs, and unpinned Python requirements. Python checks use the AST, not execution.
- **Private by design:** no source excerpts in findings, redacted credentials,
  bounded traversal, and no network requests during default scans.
- **A haunted report worth opening:** ASCII skull, CRT scanlines, severity jump
  links, contextual fix disclosures, visible coverage warnings, and Soul Integrity.
- **Portable outputs:** self-contained HTML, schema-versioned JSON, atomic writes,
  CI exit codes, and an optional loopback-only viewer.
- **Optional OSV advisories:** explicit `--osv` opt-in for exact PyPI/npm versions.
  This is the only network feature, not required for the demo or tests.

## Quickstart

From the repository root, with **Python 3.10+**:

```sh
python3 -m satan_reborn scan examples/haunted_app \
  --html reports/haunted.html --json reports/haunted.json
# Expected exit code: 1 (findings detected, not a scanner failure).
# Open reports/haunted.html directly in your browser.

python3 -m unittest -v
```

No install, API key, account, or internet connection is needed. Do **not** install
the haunted app's requirements. For a narrated walkthrough and submission text,
see [the 3-minute demo script](docs/DEMO_SCRIPT.md) and
[the Devpost draft](docs/DEVPOST.md).

## Setup (optional virtual environment)

Requires **Python 3.10+**. No pip packages, build step, JavaScript framework, or
internet connection is needed. Run from this repository's root.

```sh
# Optional: gives systems with only `python3` a local `python` command.
# No pip is needed, even in the virtual environment.
python3 -m venv --without-pip .venv
. .venv/bin/activate

python -m satan_reborn --help
python -m unittest -v
```

Without a virtual environment, use `python3` wherever your system lacks `python`.
On Windows, use `py -3` and, if using a venv, `.venv\Scripts\Activate.ps1`.

## Run

```sh
python -m satan_reborn scan /path/to/local/project
python -m satan_reborn scan /path/to/local/project \
  --html reports/audit.html --json reports/audit.json

# Serves the last scan, not the project directory.
python -m satan_reborn serve
# Open http://127.0.0.1:1995, then Ctrl+C to stop.

python -m satan_reborn serve --port 8080 --report reports/audit.html
```

Every completed scan writes `reports/last-report.html`, relative to the current
working directory. `--html` writes an additional export; `--json` is optional.
Open the HTML directly in a browser for a fully offline experience. Run `serve`
from the same working directory as the scan, or supply `--report`.
The viewer binds **only to 127.0.0.1**, exposes only `/` and `/index.html`, disables
caching, and reloads the report on each request. There is no host/bind option.

### Exit codes / CI

| Code | Meaning |
| --- | --- |
| `0` | Completed; no CRYPT or HAUNT findings |
| `1` | Completed; at least one CRYPT or HAUNT finding |
| `2` | Invalid arguments, target, output, or server operation |

Warnings about skipped files or unavailable OSV checks remain in the report.
Exit `0` does **not** prove that the code is secure or that coverage is complete.
Reports are still written when the scan exits `1`.

```sh
# CI fails on critical/high signals; stores the report even when it fails.
python -m satan_reborn scan . --json reports/ci.json
```

## Summon the demo

```sh
python -m satan_reborn scan examples/haunted_app \
  --html reports/haunted.html --json reports/haunted.json
# Expected exit code: 1. This is a successful audit of an unsafe fixture.
python -m satan_reborn serve
```

**Do not run, build, deploy, or install the haunted app.** It is intentionally
unsafe text for the scanner to inspect. Its AWS-shaped key, GitHub-shaped token,
generic secret, and private-key header are clearly labeled **FAKE placeholders**.
They were not issued by a service and contain no usable credentials.
Its `.invalid` domains are reserved, nonfunctional examples.

### Screenshot

![Haunted app audit: retro terminal and ASCII skull, exorcism-required verdict,
Soul Integrity 0/100, 3 CRYPT, 13 HAUNT, 1 SPOOK, and 2 WHISPER findings,
with masked evidence and fix advice.](docs/screenshots/report.png)

This is a browser capture of the generated offline demo report, not a mockup.
To refresh it, run the demo command, open `reports/haunted.html`, use a desktop
viewport (1440 × 1200), and save a browser screenshot to
`docs/screenshots/report.png`. A browser is only needed to view or capture HTML,
not to run the scanner or tests.

## What gets checked

Each check is its own plugin in `satan_reborn/checks/`.

| Plugin | Signals | CWE |
| --- | --- | --- |
| `hardcoded_secrets.py` | AWS access-key IDs; classic/fine-grained GitHub tokens; private-key headers; high-entropy quoted credential assignments | CWE-798 |
| `insecure_config.py` | Docker stages with no explicit nonroot USER or a final root USER; Python DEBUG assignments (names, attributes, config keys) and debug=True calls; chmod 777; curl piped to a shell; HTTP URLs in configuration | CWE-250, 489, 732, 494, 319 |
| `risky_code.py` | Python eval/exec; subprocess shell=True; pickle.load/loads; yaml.load without SafeLoader/CSafeLoader; password-related MD5/SHA1 calls | CWE-95, 78, 502, 916 |
| `dependencies.py` | Unpinned entries in `requirements*.txt`; extracts exact PyPI/npm versions for opt-in OSV | CWE-1104, 1395 |

Every finding includes a file-relative location, a 1-based line, a rule ID,
standard and spooky severity, a CWE, and specific fix advice. Detected credential
values are replaced with `[REDACTED]`. **No source excerpt or matched credential
is retained in a finding**, printed in the terminal, or embedded in JSON/HTML.
Filenames and package metadata are not secrets and are reported as supplied;
do not put credentials in filenames or dependency names.

### Threat levels and Soul Integrity

| Spooky | Standard | Score deduction |
| --- | --- | --- |
| CRYPT | CRITICAL | 25 |
| HAUNT | HIGH | 12 |
| SPOOK | MEDIUM | 5 |
| WHISPER | LOW | 1 |

**Soul Integrity = max(0, 100 − sum of finding deductions).** This is a transparent
demo heuristic, not a calibrated risk model. An empty folder scores 100.
The report provides readable severity labels as well as colors, keyboard-native
fix disclosures, semantic tables, a skip link, high-contrast text, responsive
layout, and `prefers-reduced-motion` rules that disable all animations.
Decorative motion stops within four seconds even without reduced motion.
Severity cards jump to the first matching finding, scrollable tables accept
keyboard focus, and print styles reveal fix advice. Coverage warnings remain
visible even when the score is 100; no findings is not a clean bill of health.
It contains no JavaScript, external assets, fonts, analytics, or trackers.

## Optional OSV advisory lookups

```sh
python -m satan_reborn scan examples/haunted_app --osv --json reports/osv.json
```

**Only `--osv` enables network requests.** It sends pinned dependency
**ecosystem, package name, and version** to `https://api.osv.dev/v1/query`.
It does not send source, paths, snippets, or credentials.
Default scans do not create an OSV client or make network calls.

- PyPI: exact `==` pins, including extras and environment-marker lines, from
  `requirements*.txt`. Markers are not evaluated, so all exact pins are checked.
- npm: exact semver in `package.json`, plus resolved versions in
  `package-lock.json` (v1, v2, v3), including nested/scoped packages.
- Ranges, wildcard pins, direct URLs, and editable installs are not OSV-queryable.
  Requirement include/option lines are not followed outside the scanned tree.
- Requests use a 3-second timeout, a 1 MiB response limit, an in-memory cache,
  and a 100-unique-version budget. Environment proxies and redirects are disabled.
- On the first connectivity/API failure, remaining online queries are skipped,
  a coverage warning is recorded, and local findings/report generation continue.
- OSV `database_specific.severity` maps to spooky levels; missing or unsupported
  severity defaults conservatively to HAUNT. No CVSS-vector calculation is claimed.
  Withdrawn advisories are ignored.

Tests mock OSV responses and offline failures. The test suite needs no internet.

## Boundaries, privacy, and false positives

This is a compact static auditor, not an exhaustive SAST engine or penetration
test. Review every finding in context.

- Traversal skips symlinks, nonregular files, binary/non-UTF-8 files, files larger
  than 1 MiB, VCS folders, virtual environments, `node_modules`, build caches,
  `build`, `dist`, and directories named `reports`. Explicit report output paths,
  `last-report.html`, `*.satan.html`, and `*.satan.json` are excluded from rescans.
  Put other generated exports under `reports/` to avoid scanning previous reports.
- Python checks use the host interpreter's AST, resolve common import aliases,
  and ignore commented-out calls and string examples. Unsupported Python syntax
  generates a warning and skips AST checks, while text checks still run.
- No interprocedural/data-flow analysis, runtime alias tracking, JavaScript code
  analysis, or proof that an input is attacker-controlled is performed.
  Shadowed names, development debug flags, Docker base-image USER inheritance,
  local HTTP endpoints, and deliberate credential fixtures can yield false positives.
- Secret detection uses patterns and entropy heuristics. Encoded/split secrets,
  unknown formats, and short or low-entropy secrets may be missed.
- No `.gitignore` interpretation, baseline/suppression system, dependency
  installation, or execution of build configuration is implemented.
- JSON and HTML are local, atomically replaced outputs with private temporary-file
  permissions. Reports still contain filenames and security findings. Store and
  share them carefully. Treat the folder being scanned as a stable local tree;
  this is not an OS sandbox against concurrent malicious filesystem mutations.

## How Kiro was used

The checked-in `.kiro/` artifacts capture the project's **spec-driven Kiro
workflow**. They remain inspectable alongside the implementation:

1. `.kiro/specs/satan-reborn/requirements.md` defines EARS acceptance requirements
   tied to user stories.
2. `design.md` records the plugin contract, threat boundaries, report model,
   local serving, and offline/OSV behavior.
3. `tasks.md` maps checked implementation tasks to code, documentation, and tests.
4. `.kiro/steering/{product,tech,structure}.md` gives Kiro persistent project
   context: resurrection scope, stdlib-only constraints, privacy, and layout.
5. `.kiro/hooks/test-on-save.json` defines `python -m unittest -v` after a Python save.
   `rescan-example-on-save.json` defines local demo regeneration after relevant saves.
   Its command accepts the demo's expected exit `1`, but propagates operational
   failures. Neither hook runs the vulnerable app or enables OSV.

**Vibe coding, with guardrails:** natural-language requests describe the feel
("a haunted 1995 terminal, but readable and usable with a keyboard") and the
behavior. Specs turn that intent into acceptance criteria; steering constrains
the code; small implementation/test loops check the result. This finishing pass
reconciled the checklist against the code, fixed missed debug-attribute detection
and exact-pin parsing, and added report accessibility regressions rather than
treating generated code or checked boxes as proof.

Open this folder in Kiro and use the spec/checklist to guide changes. The
preserved hook files contain `v1` / `PostFileSave` command definitions. Tests
validate their checked-in structure, matchers, and offline-safe commands, not
their registration in a live Kiro installation. Check hook activation and schema
support in your Kiro version; the same commands can always be run manually from
the project root. Ensure `python` selects Python 3.10+. These artifacts are
evidence of workflow design, not a recorded Kiro chat or proof of automatic hook
execution. No such recording is bundled or claimed.

## Development

```text
satan_reborn/
  __main__.py          CLI, exit policy, report persistence
  models.py            finding, severity, score, report schema
  scanner.py           bounded read-only traversal and plugin registry execution
  checks/              four independent check plugins
  osv.py               optional, bounded advisory queries
  report.py            escaped standalone HTML / atomic JSON outputs
  server.py            loopback-only last-report viewer
examples/haunted_app/   fake, deliberately unsafe fixtures
tests/                 unittest checks, CLI, server, OSV, HTML, and privacy tests
.kiro/                 specs, steering, and two save-hook definitions
docs/                  demo script, Devpost draft, real report screenshot
```

To add a plugin, implement `analyze(source: Source) -> list[Finding]`, register it
in `checks/__init__.py`, and add positive/negative tests. Findings must never
include matched source or credentials. Run `python -m unittest -v` before
shipping. All tests in this new project are included in `tests/`.

## License

[MIT](LICENSE). Copyright © 2026 Minh Tuan Le. This is a new implementation
inspired by SATAN's browser-report idea, not a redistribution of the 1995 tool.
