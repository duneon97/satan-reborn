# SATAN Reborn design

## Resurrection, not replication

The 1995 SATAN made security findings approachable through a browser.
This project keeps that presentation idea, not its network-scanning behavior.
The new target is a stable local source tree. Core auditing is offline and
read-only. User-requested reports are the only routine filesystem writes.

## Architecture

```text
CLI scan
  -> bounded filesystem traversal
  -> Source(relative POSIX path, UTF-8 text)
  -> explicit PLUGINS registry
     -> hardcoded_secrets.analyze
     -> insecure_config.analyze
     -> risky_code.analyze
     -> dependencies.analyze
  -> optional dependency metadata -> OSVClient -> advisory findings
  -> deduplicate / stable severity-file-line sort
  -> Report -> escaped HTML + optional JSON -> atomic persistence
  -> exit 1 for CRYPT/HAUNT, else 0

CLI serve -> ThreadingHTTPServer(127.0.0.1) -> last HTML only
```

Each local plugin exports `analyze(Source) -> list[Finding]`. Registry entries
are explicit, so scanning does not load code or plugins from the target folder.
No subprocess, application import, package installation, or manifest execution
is used in scanning.

## Data model

- `Severity`: CRYPT/HAUNT/SPOOK/WHISPER map to CRITICAL/HIGH/MEDIUM/LOW and deduct
  25/12/5/1 points from Soul Integrity.
- `Finding`: frozen/hashable rule ID, severity, title, relative file, 1-based
  line, fix advice, CWE, and optional redacted evidence. No raw source field.
- `Report`: target basename, UTC timestamp, file counters, findings, coverage
  warnings, and whether OSV was requested. JSON schema version is `1`.
- `Dependency`: ecosystem, package, exact version, and local manifest location.
  Paths and line numbers do not enter the OSV request.

Score is `max(0, 100 - sum(penalties))`. It is explicitly a heuristic, not a
security guarantee. Incomplete coverage is visible independently of findings.

## Check implementation

### Secrets

Bounded, line-based regular expressions match AWS access-key IDs, GitHub tokens,
and private-key headers. Quoted credential-like assignments of length >=20
are checked for Shannon entropy >=3.5 bits/character. Specific token patterns
avoid duplicate generic findings on the same line. Output only `[REDACTED]`.

### Configuration

Docker instructions track the final USER separately for each FROM stage; a
stage with no explicit USER or UID zero is flagged. Base-image USER inheritance
is intentionally not resolved. AST checks detect DEBUG assignments/config
items and debug keyword arguments. Text patterns detect chmod 777, curl|shell,
and HTTP URLs in common configuration formats.

### Risky code

Python AST traversal resolves ordinary imports and from-import aliases.
Rules cover eval/exec, subprocess shell=True, pickle deserialization, explicit
unsafe/missing YAML loaders, and weak hashes in password-related statements
or functions. Comments/string literals do not become calls. There is no
data-flow, control-flow, or runtime-name-resolution claim.

### Dependencies

Requirements are inspected as text, not executed. Exact pins are eligible for
OSV. npm manifests and lockfiles are parsed as JSON; exact semver is extracted,
including scoped and nested packages. Ranges are never guessed/resolved.

## Optional network boundary

OSV is disabled by default, including client construction. When enabled, the
fixed HTTPS endpoint receives only package ecosystem/name/version. Queries are
cached per scan. Timeout: 3 seconds. Response limit: 1 MiB. Budget: 100 unique
versions. Proxies and redirects are disabled. A first transport/API failure
switches off remaining online work and records a warning, without discarding
local findings. Withdrawn advisories are ignored; unknown severity is HAUNT.

## Filesystem and report safety

Traversal omits symlinks, VCS/environment/dependency/cache/build/report
directories, binary/non-UTF-8 files, and files >1 MiB. Opening uses O_NOFOLLOW
and O_NONBLOCK where available, then fstat rejects nonregular files. This avoids
common symlink/FIFO hazards but is not a sandbox against concurrent tree changes.
Report destinations are excluded from the same scan.

HTML escapes all target-controlled fields and contains no script or external
resource. A CSP disallows resource loading and form actions. The server adds
frame restrictions and no-store/nosniff headers. It serves no directory listings
and no target files. Terminal filenames are escaped to prevent control injection.
Atomic same-directory temporary writes preserve old output on write failures.

## Presentation and accessibility

Single-file HTML uses a terminal masthead, skull, CRT scanlines, subtle flicker,
red/green headings, visible severity labels, a Soul Integrity meter, and a
semantic file:line findings table. Native details/summary elements disclose fix
advice without JavaScript. High-contrast text, focus outlines, a skip link,
responsive layout, and reduced-motion rules support accessible use.

## Error policy and testing

Operational errors yield exit 2 and sanitized diagnostics. High findings yield
exit 1 after reports are persisted. Offline OSV is a warning, not an operational
error. Unit and integration tests use unittest, temporary directories, mocked
OSV, subprocess CLI runs, and loopback HTTP requests. They verify redaction,
escaping, unsafe/safe patterns, manifests, bounded traversal, exit codes, atomic
writes, and report-only serving without importing the haunted fixture.
