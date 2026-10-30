---
inclusion: always
---

# Technology constraints

## Language and runtime

- Python **>=3.10**, **standard library only**. No pip, no npm, no build system,
  no CDN dependency — not even in development.
- Entry point: `python -m satan_reborn`. Version string: `__version__` in
  `satan_reborn/__init__.py` (currently `1.0.0`).
- Test suite: `python -m unittest -v` from the project root; no extra packages.
  Tests use `unittest`, `tempfile`, `subprocess`, and `unittest.mock`.

## Plugin contract

- Each check plugin lives in `satan_reborn/checks/` and exports exactly
  `analyze(source: Source) -> list[Finding]`.
- Plugins are explicitly registered in `checks/__init__.py` as the `PLUGINS` tuple
  (order: `hardcoded_secrets`, `insecure_config`, `risky_code`, `dependencies`).
- `scanner.py` calls each plugin per file; plugins never import or execute scanned code.
- Adding a plugin requires: `analyze()` implementation, positive/negative tests,
  a CWE, fix advice, and a consistent `Severity` value.

## Data model invariants

- `Finding` is a frozen dataclass. It MUST NOT hold a raw source excerpt or a
  matched credential value. The `evidence` field is either `""` (default) or
  `"[REDACTED]"`.
- `Source` is a frozen dataclass: relative POSIX path + UTF-8 text only.
- `Report.to_dict()` serialises at schema version `1`. The shape must not change
  without bumping the version. The dict includes: `schema_version`, `tool`,
  `target`, `generated_at`, `files_scanned`, `files_skipped`, `osv_enabled`,
  `soul_integrity`, `counts`, `has_blockers`, `warnings`, `findings`.
- `Dependency` (in `checks/dependencies.py`) is a frozen dataclass carrying
  ecosystem, name, exact version, manifest file path, and line number.
  Paths/lines are never sent to OSV.

## Traversal safety

- Skip: symlinks, FIFOs/nonregular files (`fstat` after `O_NOFOLLOW`), binary
  suffixes (`BINARY_SUFFIXES` set in `scanner.py`), null bytes, non-UTF-8 content
  (decoded via `utf-8-sig` to handle BOMs), files >1 MiB (`MAX_FILE_BYTES`),
  `*.satan.html`, `*.satan.json`, `last-report.html`.
- Excluded directories: `.git`, `.hg`, `.svn`, `.venv`, `venv`, `env`,
  `__pycache__`, `node_modules`, `.mypy_cache`, `.pytest_cache`, `.tox`,
  `dist`, `build`, `reports`.
- Symlinked subdirectories are also pruned during `os.walk` by checking
  `Path(directory / d).is_symlink()` before adding to `dirs`.
- Explicit report output paths are passed as `exclude_paths` to `scan()`.
- `os.walk(followlinks=False)` with a top-down directory filter keeps traversal
  within the declared boundary.

## AST usage

- `risky_code.py` and `insecure_config.py` call `ast.parse()` on `.py`/`.pyw`
  files only. A `SyntaxError`/`ValueError`/`RecursionError` is caught, a
  coverage warning is appended (for `scanner.py`'s pre-check), and text-only
  checks still run.
- Import alias resolution is done via a single `ast.walk` pass — no
  interprocedural or data-flow analysis is claimed or performed.
- Comments and string literals are never treated as callable AST nodes.
- `risky_code.py` uses a `parents` dict (built during `ast.walk`) for
  `password_context()` to inspect the enclosing statement and function name.

## HTML report

- Single self-contained file; all CSS is inline (`STYLE` constant in `report.py`).
  No `<script>`, no external fonts, no images, no analytics.
- Every target-controlled value (filename, finding title, advice, target name,
  warnings) goes through `html.escape()` before insertion.
- CSP header: `default-src 'none'; style-src 'unsafe-inline'; base-uri 'none';
  form-action 'none'` (the `CSP` constant is shared between `report.py` and
  `server.py`).
- Terminal filenames in stdout are passed through `ascii()` to prevent control
  character injection. Warnings on stderr also use `ascii()`.
- Accessibility: skip link (`<a class="skip" href="#findings">`), semantic
  `<table>` with `<caption>` and `scope="col"` on headers, native
  `<details>`/`<summary>` disclosures, focus outlines, high-contrast text,
  responsive layout, `prefers-reduced-motion` disables all animations and
  transitions.
- Print media query resets background/colours and shows hidden `details` content.
- The report also exposes `<html lang="en">`, viewport meta, and
  `<meta name="color-scheme" content="dark">`.

## Atomic writes

- `write_text_atomic()` in `report.py`: `tempfile.mkstemp(prefix=".satan-",
  suffix=".tmp")` in the same directory as the destination, write with
  `os.fdopen`, then `os.replace`. The temp file is unlinked on any failure.
- `reports/` is created via `mkdir(parents=True, exist_ok=True)` on first write.
- Default last-report path: `reports/last-report.html` relative to CWD
  (`DEFAULT_REPORT` in `server.py`).
- `write_json()` calls `write_text_atomic()` with `json.dumps(..., indent=2,
  ensure_ascii=True) + "\n"`.

## Local report server

- `ThreadingHTTPServer` bound to `("127.0.0.1", port)`. Default port: `1995`.
- `make_handler(report_path)` returns a `ReportHandler` class (closure over the
  resolved path).
- `ReportHandler.server_version = "SATAN-Reborn"`, `sys_version = ""` to avoid
  leaking Python version in `Server:` header.
- Serves **only** `/` and `/index.html` (returns the HTML report on every GET/HEAD).
- Returns 404 for all other paths. Returns 204 (no content) for `/favicon.ico`.
- Path parsed via `urlsplit(self.path).path` to strip query strings.
- Response headers: `Cache-Control: no-store`, `Content-Security-Policy` (with
  `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`.
- Request strings are never logged (`log_message` is a no-op).
- No directory listing, no source exposure, no bind-address option.
- `serve()` raises `ValueError` if the report file does not exist before binding.

## OSV client

- Constructed only when `--osv` is passed; default scans never create it.
- Fixed endpoint: `https://api.osv.dev/v1/query` (POST, JSON body).
- Request body: `{"package": {"ecosystem": ..., "name": ...}, "version": ...}`.
  Source paths, filenames, and text are never included.
- `User-Agent: SATAN-Reborn/1.0` set on every request.
- Limits per scan: 3 s timeout (`timeout` parameter, default `3.0`), 1 MiB
  response (`MAX_RESPONSE = 1024 * 1024`), 100 unique (ecosystem, name, version)
  queries (`max_queries` parameter, default `100`) — in-memory dict cache.
- Proxies and redirects are disabled via `ProxyHandler({})` and a `NoRedirect`
  handler (subclass of `HTTPRedirectHandler` that returns `None`).
- First transport/API/JSON failure: set `self.offline = True`, append a warning,
  return `[]`; remaining queries are skipped. Local findings and report are
  always produced.
- Exception types caught: `OSError`, `URLError`, `HTTPException`, `ValueError`,
  `TypeError`, `AttributeError`, `RecursionError` (and `IncompleteRead` via
  `HTTPException`). Error detail is never echoed.
- Withdrawn advisories (`vuln.get("withdrawn")`) are skipped.
- Unknown/unsupported severity defaults to `Severity.HAUNT`.
- Advisory ID is validated with `re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", advisory)`;
  invalid IDs are replaced with `"OSV-advisory"`.
- OSV is fully mocked in tests; the test suite requires no internet access.

## Exit codes

| Code | Condition |
|---|---|
| `0` | Scan completed; no CRYPT or HAUNT findings |
| `1` | Scan completed; at least one CRYPT or HAUNT finding |
| `2` | Argument error, missing/file target, duplicate output paths, or server failure |

Exit `2` is produced by catching `(OSError, ValueError)` in `main()` and printing
a sanitised message — no raw exception text. Reports are written before `exit(1)`
is determined.

## Testing conventions

- Each check plugin has both positive (unsafe) and negative (safe) subtests.
- `test_scanner.py` uses `tempfile.TemporaryDirectory` and real file I/O.
  Includes `ModelTests` for scoring and `to_dict()` shape.
- `test_cli.py` runs the module via `subprocess` to verify real exit codes and
  terminal escaping.
- `test_osv.py` mocks `urllib.request`; never hits the network. Verifies payload
  shape, caching, severity mapping, offline/budget/withdrawn/bad-response paths.
- `test_project.py` verifies AST parseability of all `.py` files, hook schema
  (`version: v1`, two hooks, `PostFileSave`, no `--osv`), and demo coverage of
  every `rule_id`.
- `test_report.py` and `test_server.py` verify escaping, atomic writes, and
  loopback behaviour.
- Run the full suite and the haunted example scan after any meaningful change.
