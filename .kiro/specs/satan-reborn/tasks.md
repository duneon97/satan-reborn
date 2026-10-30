# Implementation tasks

All tasks are complete. The implementation is fully shipped and tested.

## Core infrastructure

- [x] **R1/R6** Create `satan_reborn` package with `__version__ = "1.0.0"`;
  implement `python -m satan_reborn` CLI via `__main__.py` with `scan` and
  `serve` subcommands, `port_number` validator, and `(OSError, ValueError)`
  exit-2 handler that never echoes exception text.
- [x] **R1** Implement bounded UTF-8 traversal in `scanner.scan()`:
  `O_NOFOLLOW | O_NONBLOCK` open + `fstat` for nonregular-file rejection;
  `os.walk(followlinks=False)` with top-down `EXCLUDED_DIRS` pruning and
  per-entry symlink check; binary-suffix, null-byte, oversized-file, and
  output-path exclusion; `utf-8-sig` decode to handle BOMs; coverage warnings
  on syntax errors and unreadable directories.
- [x] **R6** Implement findings deduplication (`set`) and stable sort by
  severity rank, file, line, `rule_id`, and title.

## Check plugins

- [x] **R2** Implement `hardcoded_secrets.analyze()`: `TOKEN_PATTERNS` for AWS
  `AKIA`/`ASIA`, GitHub `gh[pousr]_`/`github_pat_`, and PEM private-key headers
  (all CRYPT / CWE-798); `ASSIGNMENT` regex + `entropy()` ≥ 3.5 fallback (HAUNT /
  CWE-798); specific-pattern hit suppresses entropy match on same line;
  `evidence = "[REDACTED]"` on all findings.
- [x] **R3** Implement `insecure_config.analyze()`: per-stage Docker FROM/USER
  tracking with reset on new stage (HAUNT / `config.docker-root` / CWE-250);
  AST detection of `DEBUG = True`, `config["DEBUG"] = True`, and `debug=True`
  keyword calls (HAUNT / `config.debug` / CWE-489); text patterns for
  `chmod 777` (HAUNT / CWE-732), `curl|shell` (HAUNT / CWE-494), and HTTP URLs
  in config-format files (SPOOK / CWE-319).
- [x] **R4** Implement `risky_code.analyze()`: `.py`/`.pyw` only; `ast.parse` +
  single-pass alias resolution for `Import` and `ImportFrom`; `qualified()`
  helper; rules for `eval`/`exec` (CWE-95), `subprocess shell=True` (CWE-78),
  `pickle.load/loads` (CWE-502), `yaml.load` without SafeLoader (CWE-502),
  MD5/SHA1 in `password_context()` (CWE-916); comments/string-literals not treated
  as calls.
- [x] **R5** Implement `dependencies.analyze()` and `pinned_dependencies()`:
  `PIN` regex for exact PyPI `==` pins with PEP 503 name normalisation;
  `NPM_VERSION` regex for exact semver; `package.json` (three dependency sections)
  and `package-lock.json` v1/v2/v3 handling; `key_line()` for JSON source
  location; unpinned lines flagged as WHISPER / `deps.unpinned` / CWE-1104.

## OSV integration

- [x] **R5** Implement `OSVClient` in `osv.py`: POST to `api.osv.dev/v1/query`
  with only ecosystem/name/version; `ProxyHandler({})` and `NoRedirect` disable
  environment proxies and redirects; 3-second timeout, 1 MiB response cap,
  100-query in-memory cache; offline-fallback on first transport/API/JSON error
  without echoing error detail; withdrawn-advisory skip; advisory-ID validation;
  unknown severity → HAUNT / CWE-1395.
- [x] **R5** Wire OSV into `scanner.scan()`: `OSVClient` constructed only when
  `--osv` is passed; `pinned_dependencies()` called per-file to collect manifests;
  `client.findings()` called per dependency after traversal; client warnings
  appended to `Report.warnings`.

## Report and output

- [x] **R6** Implement `render_html()` in `report.py`: all target-controlled
  fields through `html.escape()`; inline `STYLE` constant (no `<script>`, no
  external resources); shared `CSP` constant; `SKULL` ASCII art; severity count
  cards; findings table with `<details>`/`<summary>` disclosures; Soul Integrity
  `<meter>`; warnings `<aside>`; responsive layout; `prefers-reduced-motion` and
  print media rules; accessibility: skip link, `<html lang="en">`, `scope="col"`,
  viewport and color-scheme meta, focus outlines.
- [x] **R6** Implement `write_text_atomic()`: `tempfile.mkstemp` in destination
  directory, write via `os.fdopen`, `os.replace`; unlink temp on any failure.
  Implement `write_json()`: `json.dumps(indent=2, ensure_ascii=True) + "\n"`.
- [x] **R6** Wire exit codes in `__main__.main()`: write reports before checking
  `has_blockers`; exit `1` for CRYPT/HAUNT, `0` otherwise; exit `2` on
  `(OSError, ValueError)` without raw exception text; duplicate HTML/JSON path
  detected and rejected before any write.

## Local server

- [x] **R7** Implement `server.py`: `make_handler(report_path)` closure returning
  `ReportHandler`; GET/HEAD on `/` and `/index.html` → 200 with re-read report;
  `/favicon.ico` → 204; all other paths → 404; `Cache-Control: no-store`,
  `CSP + frame-ancestors 'none'`, `X-Content-Type-Options: nosniff` headers;
  `log_message` no-op; `server_version = "SATAN-Reborn"`, `sys_version = ""`.
  `serve()` validates report exists before binding `ThreadingHTTPServer` to
  `("127.0.0.1", port)`; exits cleanly on `KeyboardInterrupt`.

## Demo fixture and documentation

- [x] **R8** Create `examples/haunted_app/` with intentionally unsafe text
  fixtures using only clearly labeled FAKE placeholder credentials and
  `.invalid` reserved domains: `app.py`, `requirements.txt`, `package.json`,
  `settings.env`, `Dockerfile`. The fixture exercises all 15 local rule IDs.
- [x] **R8** Add README with setup, run, demo, CI, OSV, privacy/boundaries, and
  Kiro usage sections; screenshot placeholders; MIT license (`LICENSE`).
- [x] **R8** Add `.gitignore` covering `reports/` and `.venv/`.

## Tests

- [x] **R1–R8** Add `tests/test_secrets.py`: all four secret rule IDs, masking,
  entropy threshold, specific-token/entropy deduplication, safe negatives.
- [x] **R1–R8** Add `tests/test_checks.py`: all `insecure_config` and `risky_code`
  rules, alias resolution, multiline calls, safe/comment negatives.
- [x] **R1–R8** Add `tests/test_dependencies.py`: PyPI/npm pinning, name
  normalisation, editable installs, lockfile v1/v2/v3, malformed JSON.
- [x] **R1–R8** Add `tests/test_scanner.py`: traversal exclusions, binary/symlink/
  FIFO/oversized handling, OSV opt-in mock, findings sort order, JSON redaction
  invariant; `ModelTests` for `soul_integrity`, `has_blockers`, `to_dict()` shape.
- [x] **R1–R8** Add `tests/test_cli.py`: all exit codes via subprocess, both
  report exports, duplicate-path rejection, terminal control-character escaping,
  `--help`/`--version`.
- [x] **R1–R8** Add `tests/test_osv.py`: payload shape/caching, severity mapping,
  offline/budget/withdrawn/bad-response/IncompleteRead paths; no network access.
- [x] **R1–R8** Add `tests/test_report.py`: HTML escaping/no-script audit, atomic
  write, failed-write cleanup (no leftover temp file), JSON roundtrip.
- [x] **R1–R8** Add `tests/test_server.py`: real loopback HTTP; 200/404/204
  routing; security headers; loopback bind assertion; report refresh.
- [x] **R1–R8** Add `tests/test_project.py`: AST parseability of all `.py` files;
  hook schema validation (v1, two PostFileSave hooks, no `--osv`, matcher coverage
  across OS path separators); demo covers every local rule_id; all findings have
  advice, valid CWE, and line ≥ 1.

## Kiro hooks and steering

- [x] **R8** Add `.kiro/hooks/test-on-save.json`: PostFileSave on `\.py$` →
  `python -m unittest -v`.
- [x] **R8** Add `.kiro/hooks/rescan-example-on-save.json`: PostFileSave on
  `satan_reborn/` or `examples/haunted_app/` → rescan demo; accepts exit 0 or 1;
  never passes `--osv`.
- [x] **R8** Add `.kiro/steering/product.md`, `tech.md`, `structure.md` with
  `inclusion: always` and complete project context.
- [x] **R8** Add `.kiro/specs/satan-reborn/requirements.md`, `design.md`,
  `tasks.md` as the spec-driven workflow artifacts.
