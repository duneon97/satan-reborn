# SATAN Reborn design

## Resurrection, not replication

The 1995 SATAN made security findings approachable through a browser.
This project keeps that presentation idea, not its network-scanning behavior.
The new target is a stable local source tree. Core auditing is offline and
read-only. User-requested reports are the only routine filesystem writes.

## Architecture

```text
CLI scan
  -> bounded filesystem traversal  (scanner.scan)
  -> Source(relative POSIX path, UTF-8 text)
  -> explicit PLUGINS registry  (checks/__init__.py PLUGINS tuple)
     -> hardcoded_secrets.analyze   (line-based regex + entropy)
     -> insecure_config.analyze     (Docker stage tracking + AST + text patterns)
     -> risky_code.analyze          (AST-only, .py/.pyw)
     -> dependencies.analyze        (text manifest parsing)
  -> optional: pinned_dependencies -> OSVClient -> advisory Finding objects
  -> deduplicate (set) + stable sort (severity rank, file, line, rule_id, title)
  -> Report -> escaped HTML -> atomic write to reports/last-report.html
            -> optional --html export (same atomic write)
            -> optional --json export (json.dumps, ensure_ascii=True)
  -> exit 1 for CRYPT/HAUNT, else 0

CLI serve
  -> validate report file exists
  -> ThreadingHTTPServer("127.0.0.1", port)
  -> serve only / and /index.html; re-read file per request
```

Each local plugin exports `analyze(Source) -> list[Finding]`. Registry entries
are explicit in `checks/__init__.py`, so scanning never loads plugins from the
target folder or imports user code.

## Data model

```
Severity  (str Enum)
  CRYPT / HAUNT / SPOOK / WHISPER
  .standard  -> "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
  .penalty   -> 25 / 12 / 5 / 1

Source  (frozen dataclass)
  path: str           relative POSIX path within the scanned tree
  text: str           UTF-8 content
  .lines -> list[str]

Finding  (frozen dataclass, hashable)
  rule_id: str        e.g. "secret.aws", "code.shell"
  severity: Severity
  title: str
  file: str           relative POSIX path
  line: int           1-based
  advice: str         fix guidance
  cwe: str            e.g. "CWE-798"
  evidence: str       "" or "[REDACTED]" — never a raw credential or source excerpt
  .to_dict()          adds "standard_severity" key

Dependency  (frozen dataclass, in checks/dependencies.py)
  ecosystem: str      "PyPI" or "npm"
  name: str
  version: str        exact pin only
  file: str           manifest path (not sent to OSV)
  line: int           (not sent to OSV)

Report  (mutable dataclass)
  target: str         root directory basename
  generated_at: str   UTC ISO-8601 timestamp (seconds precision)
  files_scanned: int
  files_skipped: int
  findings: list[Finding]
  warnings: list[str]
  osv_enabled: bool
  .counts             -> dict{severity.value: count}
  .soul_integrity     -> max(0, 100 - sum(penalties))
  .has_blockers       -> any CRYPT or HAUNT finding
  .to_dict()          schema_version=1; includes all above fields + findings as dicts
```

Score is `max(0, 100 - sum(penalties))`. It is explicitly a heuristic, not a
security guarantee. Incomplete coverage is visible independently of findings.

## Check implementation

### Secrets (`hardcoded_secrets.py`)

Line-based regular expressions match three specific token patterns:
- `(AKIA|ASIA)[A-Z0-9]{16}` → CRYPT / `secret.aws` / CWE-798
- `gh[pousr]_[A-Za-z0-9]{36,255}` or `github_pat_[A-Za-z0-9_]{22,255}` → CRYPT / `secret.github` / CWE-798
- `-----BEGIN [type ]PRIVATE KEY-----` → CRYPT / `secret.private-key` / CWE-798

When a specific pattern hits a line, the entropy check is suppressed for that
line to prevent duplicate findings. The entropy fallback uses a quoted
credential-like name regex (`ASSIGNMENT`) and Shannon entropy ≥ 3.5 → HAUNT /
`secret.entropy` / CWE-798. All `evidence` fields are `"[REDACTED]"`.

### Configuration (`insecure_config.py`)

**Docker**: iterate lines tracking `FROM` (start/reset stage, record `stage_line`)
and `USER` (record effective user). On each new `FROM` and at end-of-file, if
the final user for a stage is `None`, `root`, `0`, `00`, or `000` (with optional
`:group` suffix), emit HAUNT / `config.docker-root` / CWE-250. Matches files
named `Dockerfile*` or `*.dockerfile`. Base-image USER inheritance is not resolved.

**Debug mode**: `ast.parse` the `.py`/`.pyw` source. Walk for:
- `ast.Assign`/`ast.AnnAssign` where target is `DEBUG` (Name, Attribute, or subscript key) and
  value is `True` → HAUNT / `config.debug` / CWE-489
- `ast.Call` keyword with `arg == "debug"` and value `True` → HAUNT / `config.debug` / CWE-489

**Text patterns** (applied after skipping `#`, `//`, `;`-prefixed lines):
- `chmod\s+(-\w+\s+)*0?777` → HAUNT / `config.chmod` / CWE-732 (any file)
- `curl ...|[sudo/env ]sh` → HAUNT / `config.curl-shell` / CWE-494 (any file)
- `http://\S+` in a config-format file (`.ini`, `.cfg`, `.conf`, `.toml`, `.yaml`,
  `.yml`, `.json`, `.xml`, `.properties`, `.env`, `Dockerfile*`, `settings.py`,
  `config.py`) → SPOOK / `config.http` / CWE-319

### Risky code (`risky_code.py`)

`.py`/`.pyw` only. `ast.parse` → walk for `ast.Call` nodes. Import alias
resolution is a single `ast.walk` pass building `aliases: dict[local_name → full_name]`
for both `import X as Y` and `from M import X as Y` forms. The `qualified(node)`
helper reconstructs dotted names from `Name` and `Attribute` nodes.

Rules and their `qualified(node.func)` triggers:
- `eval`, `exec`, `builtins.eval`, `builtins.exec` → HAUNT / `code.dynamic-execution` / CWE-95
- `subprocess.*` with `shell=True` kwarg (literal `True`) → HAUNT / `code.shell` / CWE-78
- `pickle.loads`, `pickle.load`, `_pickle.loads`, `_pickle.load` → HAUNT / `code.pickle` / CWE-502
- `yaml.load` without `SafeLoader`/`CSafeLoader` as positional arg[1] or `Loader` kwarg → HAUNT / `code.yaml` / CWE-502
- `hashlib.md5`, `hashlib.sha1`, or `hashlib.new("md5"/"sha1")` inside a
  password context → HAUNT / `code.password-hash` / CWE-916

`password_context(node)` traverses the `parents` dict upward from the call to
find its containing statement and enclosing function name, then regex-searches for
`password|passwd|pwd|credential` (case-insensitive).

### Dependencies (`dependencies.py`)

`is_requirements(source)` → filename starts with `requirements` and ends with
`.txt`. `requirement_lines()` strips comments, skips blank/backslash-continuation
lines, and includes editable installs (treated as unpinned).

`PIN` regex matches exact `name==version` pins (with optional extras and environment
markers). PyPI names are normalised via `re.sub(r"[-_.]+", "-", name).lower()`.
Trailing extra constraints or arbitrary text are not accepted as an exact pin.
Whitespace followed by a marker, `--hash` option, continuation, or end of line
is permitted.

`NPM_VERSION` matches semver `X.Y.Z[-prerelease][+build]` only (no ranges, no `^`,
no `~`). `package.json` reads `dependencies`, `devDependencies`, and
`optionalDependencies` sections. `package-lock.json` handles:
- v2/v3: `packages` dict, entries with `node_modules/` in the key
- v1: recursive `dependencies` tree

`key_line(source, key)` scans lines for the JSON-encoded key to return a 1-based
source line. `analyze()` flags unpinned requirements lines as WHISPER / `deps.unpinned`.

## Optional network boundary

`OSVClient` is constructed only when `--osv` is passed; scanner.py imports but
never instantiates it by default. The fixed HTTPS endpoint receives POST requests
with `{"package": {"ecosystem": ..., "name": ...}, "version": ...}`. Source text,
manifest paths, and line numbers are never included.

Limits: 3-second timeout, 1 MiB response cap (`MAX_RESPONSE`), 100-query in-memory
dict cache keyed by `(ecosystem, name, version)`. Proxies and redirects are disabled
via `ProxyHandler({})` and `NoRedirect` (subclass of `HTTPRedirectHandler`).

First transport/API/JSON failure: `self.offline = True`, append a sanitised warning,
return `[]`; no subsequent queries are attempted. Error detail is never echoed.
Withdrawn advisories are skipped. Advisory IDs failing `re.fullmatch(r"[A-Za-z0-9._:-]{1,100}")` become `"OSV-advisory"`. Unknown severity → `Severity.HAUNT`.

## Filesystem and report safety

Traversal uses `O_NOFOLLOW | O_NONBLOCK` when opening files, then `fstat` rejects
non-regular inodes. `os.walk(followlinks=False)` and per-entry `is_symlink()` checks
prevent symlink escapes. Binary suffixes, null bytes, non-UTF-8 content, oversized
files, and output-path collisions are all skipped before any plugin sees content.
This mitigates common hazards but is not a kernel sandbox against concurrent tree
mutations.

HTML output escapes all target-controlled fields through `html.escape()`. The CSP
`default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'`
prevents resource loading and form submission. The server adds `frame-ancestors 'none'`
and `Cache-Control: no-store` / `X-Content-Type-Options: nosniff` headers. It never
serves directory listings, the scanned source tree, or any path outside the single
report file. Terminal output uses `ascii()` on filenames and warnings to prevent
control-character injection.

Atomic writes use `tempfile.mkstemp` in the destination directory, write via
`os.fdopen`, then `os.replace`. The temp file is always unlinked on failure,
preserving the previous report.

## Presentation and accessibility

Single-file HTML: `<!doctype html>`, `<html lang="en">`, `<meta charset="utf-8">`,
viewport and color-scheme meta. Inline `STYLE` constant contains all CSS — no
`<script>`, no external fonts, no images, no analytics. Structural elements:
terminal masthead, hero with ASCII skull and blinking cursor, scan-session panel,
dashboard (Soul Integrity meter + severity count cards), findings table, optional
warnings aside, about section, footer.

Findings table: `<table>` with `<caption>`, `<thead>` with `scope="col"` headers,
`<tbody>` rows. Fix advice uses native `<details>`/`<summary>` — no JavaScript.
Skip link (`<a class="skip" href="#findings">`) enables keyboard navigation;
the target section has `tabindex="-1"`. The table's named scroll region has
`tabindex="0"` and visible focus styling. Narrow layouts wrap navigation and
metadata without overflowing the page. Each summary includes screen-reader-only
finding title/location context. Severity cards link to the first matching row,
or the findings section for zero counts.

A triage aside prioritizes critical/high findings. A separate coverage banner
links to warning notes even when Soul Integrity is 100. Critical/high reports
use a red score treatment. The meter has low/high/optimum semantics; the score
remains explicitly a heuristic.

Cursor blink and skull flicker each stop within four seconds.
`prefers-reduced-motion: reduce` sets `animation: none !important` on all elements.
Print media query resets backgrounds, removes decorative elements, and forces
`<details>` content visible, including the `::details-content` content-visibility
used by current browsers. Forced-colors styling retains borders and focus.

## Demo and submission artifacts

The fixture retains all deliberate security signals, using only clearly labeled
FAKE credential-shaped values and reserved `.invalid` domains. `app.py` raises
`SystemExit` immediately after its docstring and safety comment, before imports.
This prevents accidental invocation from reaching the examples; scanner/tests
still parse it as text. Its local README maps files to all 15 rules and warns
against installation, deployment, import, and container builds.

`docs/screenshots/report.png` is a real desktop browser capture of the generated
demo report. `docs/DEMO_SCRIPT.md` contains a 0:00–3:00 shot list, narration,
preflight commands, and expected exit-code handling. `docs/DEVPOST.md` describes
only implemented behavior and separates future ideas.

The existing `.kiro/hooks/*.json` definitions are preserved. Tests validate their
file structure, matchers, offline-safe commands, and expected-exit handling.
They do not validate a live Kiro installation's schema, registration, or automatic
event handling. Documentation must not claim that the artifact files are a
recorded Kiro session or verified automatic execution.

## Error policy and testing

`main()` wraps the top-level `scan()` and `serve()` calls in `except (OSError,
ValueError)` and prints a generic sanitised message, then returns `2`. Reports are
always written before the exit code for blockers is determined; a failing write is
an exit-2 condition.

Test modules and their coverage:
- `test_secrets.py` — positive/negative for all four secret rules
- `test_checks.py` — positive/negative for all insecure_config and risky_code rules
- `test_dependencies.py` — PyPI/npm pinning, normalisation, lockfile formats, malformed JSON
- `test_scanner.py` — traversal boundaries, exclusions, FIFO handling, OSV opt-in,
  sort order, JSON redaction invariant; `ModelTests` for scoring and `to_dict()` shape
- `test_cli.py` — all exit codes via subprocess, report paths, terminal escaping,
  `--help`/`--version`
- `test_osv.py` — payload shape, caching, severity mapping, offline/budget/withdrawn,
  bad-response paths, `IncompleteRead`
- `test_report.py` — HTML escaping, no-script audit, atomic writes, failed-write cleanup,
  JSON roundtrip
- `test_server.py` — real loopback HTTP; 200/404/204 routing; security headers;
  bind address; report refresh
- `test_project.py` — AST parseability of all project `.py` files; hook schema
  (`version: v1`, two `PostFileSave` hooks, no `--osv`); demo covers every local rule_id
