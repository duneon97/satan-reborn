# SATAN Reborn requirements

## Product story

As a Kiroween participant, I want to resurrect SATAN's 1995 browser-report spirit
as a safe local-code auditor, so that a forgotten security tool gains a useful
new life without performing network attacks.

## R1. Local scanning and execution safety

**User story:** As a developer, I want an offline folder scan that does not run
my application.

- WHEN the user runs `python -m satan_reborn scan <path>`, THE SYSTEM SHALL inspect
  readable local UTF-8 files using Python 3.10+ standard-library code only.
- WHILE OSV is not enabled, THE SYSTEM SHALL make no network requests.
- WHEN inspecting source, THE SYSTEM SHALL NOT import or execute scanned code.
- WHEN a file is a symlink, nonregular, binary, non-UTF-8, null-byte-containing,
  or over 1 MiB, THE SYSTEM SHALL skip it and increment the skipped counter.
- WHEN a file's binary suffix matches `BINARY_SUFFIXES`, or its name ends with
  `.satan.html`, `.satan.json`, or is `last-report.html`, THE SYSTEM SHALL skip it.
- WHEN traversal encounters directories named `.git`, `.hg`, `.svn`, `.venv`,
  `venv`, `env`, `__pycache__`, `node_modules`, `.mypy_cache`, `.pytest_cache`,
  `.tox`, `dist`, `build`, or `reports`, THE SYSTEM SHALL omit them.
- WHEN a subdirectory entry is itself a symlink, THE SYSTEM SHALL not descend into it.
- WHEN explicit output paths are passed via `exclude_paths`, THE SYSTEM SHALL skip
  files whose resolved path matches any of them.
- WHEN Python syntax is unsupported for a file, THE SYSTEM SHALL record a coverage
  warning (including the filename) and continue text-only checks.
- WHEN a directory cannot be read during traversal, THE SYSTEM SHALL append a
  coverage warning and continue with accessible paths.

## R2. Secret detection and output privacy

**User story:** As a code owner, I want to find exposed credentials without
duplicating them in audit outputs.

- WHEN an AWS access-key ID pattern (`AKIA`/`ASIA` prefix, 20 chars) appears on a
  line, THE SYSTEM SHALL report CRYPT with rule `secret.aws`.
- WHEN a GitHub token pattern (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, or
  `github_pat_` prefix) appears on a line, THE SYSTEM SHALL report CRYPT with rule
  `secret.github`.
- WHEN a PEM private-key header appears (`-----BEGIN [type ]PRIVATE KEY-----`),
  THE SYSTEM SHALL report CRYPT with rule `secret.private-key`.
- WHEN a quoted credential-like assignment has a value of length ≥20 and Shannon
  entropy ≥3.5 bits/char, AND that line has no specific-pattern hit,
  THE SYSTEM SHALL report HAUNT with rule `secret.entropy`.
- WHEN any secret finding is emitted, THE SYSTEM SHALL set its `evidence` field
  to `"[REDACTED]"` and SHALL NOT retain the matched value or source excerpt
  anywhere in findings, JSON, HTML, or terminal output.
- WHEN HTML incorporates any target-controlled value, THE SYSTEM SHALL pass it
  through `html.escape()`. The CSP header SHALL disallow scripts and external
  resources.

## R3. Insecure configuration

**User story:** As a maintainer, I want dangerous configuration defaults surfaced.

- WHEN a Dockerfile or `*.dockerfile` stage has no explicit `USER`, or its final
  `USER` is `root`, `0`, `00`, or `000` (optionally with a group suffix),
  THE SYSTEM SHALL report HAUNT with rule `config.docker-root` at the `FROM` line.
- WHEN the check transitions to a new `FROM` stage, THE SYSTEM SHALL reset the
  per-stage USER tracking independently of prior stages.
- WHEN a `.py`/`.pyw` file assigns `DEBUG = True` (or `config["DEBUG"] = True`,
  `config.DEBUG = True`) or calls a function with `debug=True`, THE SYSTEM SHALL
  report HAUNT with rule `config.debug` at each occurrence's line.
- WHEN a file (not a comment or `//`/`;`-prefixed line) contains `chmod 777` (or
  `chmod -R 0777`), THE SYSTEM SHALL report HAUNT with rule `config.chmod`.
- WHEN a file contains a `curl ... | sh`-style pipe-to-shell pattern,
  THE SYSTEM SHALL report HAUNT with rule `config.curl-shell`.
- WHEN a config-format file (`.ini`, `.cfg`, `.conf`, `.toml`, `.yaml`, `.yml`,
  `.json`, `.xml`, `.properties`, `.env`, `.env.*`, `Dockerfile*`, `settings.py`,
  `config.py`) contains an HTTP URL on a non-comment line, THE SYSTEM SHALL
  report SPOOK with rule `config.http`.

## R4. Risky Python code

**User story:** As a reviewer, I want high-risk APIs located without executing them.

- WHEN a `.py`/`.pyw` file's AST contains a call to `eval` or `exec`
  (including builtins-qualified forms), THE SYSTEM SHALL report HAUNT with
  rule `code.dynamic-execution`.
- WHEN a `subprocess.*` call has `shell=True` as a keyword argument with a literal
  `True` value, THE SYSTEM SHALL report HAUNT with rule `code.shell`.
- WHEN a `pickle.load` or `pickle.loads` (or `_pickle` variants) call is present,
  THE SYSTEM SHALL report HAUNT with rule `code.pickle`.
- WHEN `yaml.load` is called without an explicit `SafeLoader` or `CSafeLoader`
  (as a positional or keyword `Loader` argument), THE SYSTEM SHALL report HAUNT
  with rule `code.yaml`.
- WHEN `hashlib.md5`, `hashlib.sha1`, or `hashlib.new("md5"/"sha1")` appears in
  a password-related statement or enclosing function (name or statement contains
  `password`, `passwd`, `pwd`, or `credential`, case-insensitive), THE SYSTEM
  SHALL report HAUNT with rule `code.password-hash`.
- WHEN imports use aliases (`import X as Y` or `from M import X as Y`),
  THE SYSTEM SHALL resolve those aliases before applying the above rules.
- WHEN a code-like string appears only as a comment or a string literal (not an
  AST `Call` node), THE SYSTEM SHALL NOT emit a finding for it.
- WHEN a file has Python syntax errors or is not `.py`/`.pyw`, THE SYSTEM SHALL
  return no AST-based findings for that file.

## R5. Dependencies and optional advisories

**User story:** As an offline-first user, I want manifest checks without mandatory
cloud access.

- WHEN a `requirements*.txt` file contains a line without an exact `==` pin and
  the line is not a comment, option flag, or backslash continuation,
  THE SYSTEM SHALL report WHISPER with rule `deps.unpinned` (CWE-1104).
- WHEN `pinned_dependencies()` extracts a PyPI pin, THE SYSTEM SHALL normalise the
  package name (consecutive `[-_.]` → `-`, lowercased) per PEP 503.
- WHEN `pinned_dependencies()` parses npm manifests, THE SYSTEM SHALL handle
  `package.json` (dependencies/devDependencies/optionalDependencies sections) and
  `package-lock.json` v1 (nested `dependencies` tree) and v2/v3 (`packages` map
  with `node_modules/` prefix) formats.
- IF `--osv` is supplied, WHEN exact PyPI/npm versions are found in manifests,
  THE SYSTEM SHALL query `api.osv.dev/v1/query` with only ecosystem, package name,
  and version — never paths, source, or credentials.
- WHEN identical (ecosystem, name, version) queries repeat within a scan,
  THE SYSTEM SHALL reuse cached results without making a second HTTP request.
- WHEN the first OSV request fails or returns invalid data, THE SYSTEM SHALL set
  the client offline, append a warning, and complete local checks and report
  generation normally.
- WHILE querying OSV, THE SYSTEM SHALL enforce a 3-second timeout, a 1 MiB
  response cap, and a 100 unique-version query budget per scan.
- WHEN an OSV advisory has no supported `database_specific.severity` value,
  THE SYSTEM SHALL default to HAUNT (CWE-1395).
- WHEN an OSV advisory ID fails validation (`[A-Za-z0-9._:-]{1,100}`), THE SYSTEM
  SHALL replace it with `"OSV-advisory"` in the finding title.
- WHEN an advisory has a `withdrawn` field, THE SYSTEM SHALL skip it.

## R6. Reports and CI

**User story:** As a developer, I want a portable, spooky report and CI exit codes.

- WHEN a scan completes, THE SYSTEM SHALL atomically write `reports/last-report.html`
  (relative to CWD) and any additional `--html`/`--json` paths requested, even
  when high-severity findings exist.
- WHEN `--html` and `--json` resolve to the same path, THE SYSTEM SHALL exit `2`
  before writing any file.
- WHEN a finding is recorded, THE SYSTEM SHALL include: `rule_id`, `severity`
  (spooky), `standard_severity`, `title`, `file` (relative POSIX path), `line`
  (1-based), `cwe`, `advice`, and `evidence` (`""` or `"[REDACTED]"`).
- WHEN calculating Soul Integrity, THE SYSTEM SHALL subtract 25/12/5/1 points for
  CRYPT/HAUNT/SPOOK/WHISPER respectively and clamp the result at zero.
- WHEN findings contain CRYPT or HAUNT, THE SYSTEM SHALL exit `1`.
- WHEN findings contain only SPOOK/WHISPER or none, THE SYSTEM SHALL exit `0`.
- WHEN arguments, target access, or output writes fail, THE SYSTEM SHALL exit `2`
  and print a sanitised diagnostic — no raw exception text.
- WHEN rendering HTML, THE SYSTEM SHALL produce one self-contained file with a
  black/red/green retro interface, ASCII skull, CRT scanlines, flicker animation,
  and blinking cursor, using inline CSS only (no `<script>`, no external resources).
- WHILE reduced motion is preferred (`prefers-reduced-motion: reduce`),
  THE SYSTEM SHALL disable all CSS animations and transitions.
- WHEN using keyboard navigation or narrow screens, THE SYSTEM SHALL provide a
  skip link, semantic table headers with `scope="col"`, native `<details>`/`<summary>`
  for fix advice disclosures, visible focus outlines, and responsive layout.
- WHEN writing atomic output, THE SYSTEM SHALL use `tempfile.mkstemp` in the
  destination directory, write content, then `os.replace`; on any failure,
  THE SYSTEM SHALL unlink the temporary file and not leave it behind.

## R7. Local report viewer

**User story:** As a demo presenter, I want to view the last report safely.

- WHEN `serve` runs, THE SYSTEM SHALL bind only to `127.0.0.1`; no bind-address
  option is exposed.
- WHEN `serve` is called and the report file does not exist, THE SYSTEM SHALL
  raise `ValueError` before binding to any port.
- WHEN a client sends GET or HEAD to `/` or `/index.html`, THE SYSTEM SHALL return
  the current report with headers: `Cache-Control: no-store`,
  `Content-Security-Policy` (including `frame-ancestors 'none'`), and
  `X-Content-Type-Options: nosniff`.
- WHEN a client requests `/favicon.ico`, THE SYSTEM SHALL return 204.
- WHEN a client requests any other path (including traversal attempts),
  THE SYSTEM SHALL return 404.
- THE SYSTEM SHALL re-read the report file on every request; it does not cache in
  memory.
- THE SYSTEM SHALL NOT log request strings (to prevent control-character injection).
- THE SYSTEM SHALL NOT expose the Python version in the `Server:` response header
  (`server_version = "SATAN-Reborn"`, `sys_version = ""`).

## R8. Reproducibility and Kiro integration

**User story:** As a hackathon judge, I want a reproducible demo and inspectable
spec-driven workflow.

- WHEN `python -m unittest -v` runs from the project root, THE SYSTEM SHALL
  discover and pass all tests without pip dependencies or external connectivity.
- WHEN a user scans `examples/haunted_app`, THE SYSTEM SHALL produce findings for
  every local rule ID:
  `secret.aws`, `secret.github`, `secret.private-key`, `secret.entropy`,
  `config.docker-root`, `config.chmod`, `config.curl-shell`, `config.debug`,
  `config.http`, `code.dynamic-execution`, `code.shell`, `code.pickle`,
  `code.yaml`, `code.password-hash`, `deps.unpinned`.
- WHEN a Python file is saved in Kiro, THE SYSTEM SHALL run `python -m unittest -v`
  via the `test-on-save.json` hook.
- WHEN a file under `satan_reborn/` or `examples/haunted_app/` is saved in Kiro,
  THE SYSTEM SHALL regenerate the haunted-app report without executing the fixture
  and without passing `--osv`, via the `rescan-example-on-save.json` hook.
- THE SYSTEM SHALL include setup, demo, CI, and privacy documentation, screenshot
  placeholders, and an MIT license; `.kiro` specs/steering/hooks SHALL be
  committed project artifacts.
