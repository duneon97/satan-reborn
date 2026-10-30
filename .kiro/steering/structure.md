---
inclusion: always
---

# Repository map

```text
satan_reborn/
  __init__.py          Package marker; exposes __version__ = "1.0.0".
  __main__.py          argparse CLI (scan / serve subcommands), port_number validator,
                       exit policy (0/1/2), atomic report persistence, terminal output
                       with ascii() escaping on filenames and warnings.
  models.py            Severity enum (CRYPT/HAUNT/SPOOK/WHISPER) with .standard and
                       .penalty properties; Source (frozen, .lines); Finding (frozen,
                       .to_dict() with standard_severity); Report dataclass with
                       .counts, .soul_integrity, .has_blockers, .to_dict()
                       (schema_version=1).
  scanner.py           Bounded UTF-8 traversal: O_NOFOLLOW + O_NONBLOCK + fstat,
                       followlinks=False; EXCLUDED_DIRS set; per-file plugin dispatch;
                       AST syntax pre-check with coverage warning; optional OSV pass
                       on manifests; findings dedup (set) + stable severity/file/line
                       sort; MAX_FILE_BYTES = 1 MiB.
  checks/
    __init__.py        Explicit PLUGINS tuple:
                       (hardcoded_secrets, insecure_config, risky_code, dependencies).
    hardcoded_secrets.py  TOKEN_PATTERNS (AWS AKIA/ASIA, GitHub gh[pousr]_/github_pat_,
                          private-key BEGIN headers); ASSIGNMENT regex for quoted
                          credential-like names ≥20 chars; Shannon entropy ≥3.5 check;
                          specific-pattern hits suppress entropy match on same line;
                          evidence always "[REDACTED]".
    insecure_config.py    Per-stage Docker FROM/USER tracking (root/0/UID-zero = HAUNT);
                          AST detection of DEBUG=True assignments, config-dict DEBUG,
                          and debug=True keyword calls; text patterns for chmod 777,
                          curl|shell, HTTP URLs in CONFIG_SUFFIXES/.env/Dockerfile files.
    risky_code.py         .py/.pyw only; ast.parse with alias resolution (Import +
                          ImportFrom); qualified() helper; rules: eval/exec, subprocess
                          shell=True, pickle.load/loads, yaml.load without
                          SafeLoader/CSafeLoader, MD5/SHA1 in password context;
                          password_context() inspects enclosing statement + function name.
    dependencies.py       is_requirements(), requirement_lines(), PIN regex for exact
                          PyPI ==pins, NPM_VERSION regex for exact semver; key_line()
                          for JSON source location; pinned_dependencies() extracts
                          Dependency objects; analyze() flags unpinned requirements.txt
                          lines as WHISPER (CWE-1104). Dependency frozen dataclass holds
                          ecosystem/name/version/file/line.
  osv.py               OSVClient: constructed only when --osv passed; NoRedirect handler;
                       ProxyHandler({}) disables env proxies; fixed HTTPS endpoint;
                       3 s timeout, 1 MiB response cap, 100-query cache budget;
                       offline-fallback on first transport/API/JSON error (never echoes
                       error detail); withdrawn advisories skipped; unknown severity →
                       HAUNT; findings() returns list[Finding] with CWE-1395.
  report.py            render_html(): all target-controlled fields through html.escape();
                       inline CSS only (STYLE constant), no <script>, no external
                       resources; CSP constant reused by server; SKULL ASCII art;
                       severity cards, findings table with native <details>/<summary>,
                       warnings aside, Soul Integrity meter, reduced-motion and print
                       media rules.
                       write_text_atomic(): mkstemp in same dir, fdopen, os.replace,
                       cleanup on failure.
                       write_json(): json.dumps with ensure_ascii=True + newline.
  server.py            DEFAULT_REPORT = Path("reports/last-report.html").
                       make_handler(report_path): ReportHandler serves only / and
                       /index.html (200), /favicon.ico (204), all else 404; reads
                       report file on every request; security headers: Cache-Control
                       no-store, CSP + frame-ancestors 'none', X-Content-Type-Options
                       nosniff; request strings never logged.
                       serve(): validates report file exists; ThreadingHTTPServer bound
                       to ("127.0.0.1", port); KeyboardInterrupt exits cleanly.

examples/haunted_app/  Deliberately unsafe text fixtures — DO NOT run, build, or import.
  app.py               FAKE eval, exec, subprocess shell=True, pickle.loads, yaml.load
                       with Loader, hashlib.md5/sha1 in password funcs, DEBUG=True,
                       app.run(debug=True), and clearly labeled FAKE credential-shaped
                       strings (AWS, GitHub, private-key header, high-entropy assignment).
  requirements.txt     Unpinned Flask + requests; exact-pinned demo package for OSV.
  package.json         Exact npm versions for OSV demo.
  settings.env         FAKE AWS and GitHub credential-shaped placeholders; HTTP URL.
  Dockerfile           Root-user stage; curl|sh; chmod 777; no USER instruction.

tests/
  __init__.py          Marks tests as a package; re-exports nothing.
  test_checks.py       Positive/negative subtests for insecure_config and risky_code.
  test_secrets.py      Positive/negative subtests for hardcoded_secrets.
  test_dependencies.py Positive/negative subtests for dependencies plugin.
  test_scanner.py      Traversal boundary, skipping, exclusions, OSV opt-in, ordering,
                       no-secret-value-in-JSON invariant; ModelTests for scoring.
  test_cli.py          subprocess runs verifying all exit codes, report paths, escaping,
                       help/version flags.
  test_osv.py          urllib.request mocked; online/offline/cache/budget/withdrawn/
                       bad-response/IncompleteRead paths; payload shape verified.
  test_report.py       html.escape invariants, self-contained HTML audit, atomic-write
                       behaviour, failed-write cleanup, JSON roundtrip.
  test_server.py       Real loopback HTTP requests; 200/404/204 routing; header
                       verification; loopback bind assertion; report refresh.
  test_project.py      AST parseability of all .py files; hook schema and matcher checks;
                       demo covers every local rule_id; findings have advice/CWE/line.

.kiro/
  steering/            product.md, tech.md, structure.md — inclusion: always.
  specs/
    satan-reborn/      Project-wide spec (requirements.md, design.md, tasks.md).
  hooks/
    test-on-save.json            PostFileSave on *.py → python -m unittest -v.
    rescan-example-on-save.json  PostFileSave on satan_reborn/ or haunted_app/ files →
                                 python -c "...main(['scan', 'examples/haunted_app', ...])";
                                 accepts exit 0 or 1; never passes --osv.

reports/               Runtime output directory (git-ignored).
  last-report.html     Always written by scan; replaced atomically.
```

## Navigation rules

- Check rules belong in their owning plugin. Do not add new detection logic to
  `scanner.py`, `report.py`, or `models.py`.
- New plugins: implement `analyze(Source) -> list[Finding]`, register in
  `checks/__init__.py`, add positive/negative tests, a CWE, and fix advice.
- Data model changes that alter `to_dict()` shape must bump `schema_version`.
- Do not add raw source snippets, matched credential values, or `evidence` fields
  containing anything other than `""` or `"[REDACTED]"` to any Finding.
- Update specs when behaviour intentionally changes.
