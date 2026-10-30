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
- WHEN a file is a symlink, nonregular, binary, non-UTF-8, or over 1 MiB,
  THE SYSTEM SHALL skip it without blocking on input.
- WHEN traversal encounters excluded VCS, environment, dependency, cache, build,
  or report directories, THE SYSTEM SHALL omit those directories.
- WHEN Python syntax is unsupported or a readable subtree is unavailable,
  THE SYSTEM SHALL record a coverage warning and continue other checks.

## R2. Secret detection and output privacy

**User story:** As a code owner, I want to find exposed credentials without
duplicating them in audit outputs.

- WHEN AWS/GitHub token patterns or private-key headers occur in a text file,
  THE SYSTEM SHALL report a CRYPT finding with its file and line.
- WHEN a quoted credential-like assignment has length of at least 20 and Shannon
  entropy of at least 3.5 bits per character, THE SYSTEM SHALL report HAUNT.
- WHEN any secret finding is emitted, THE SYSTEM SHALL replace its evidence
  with `[REDACTED]` and SHALL NOT retain the matched value or source excerpt.
- WHEN HTML incorporates untrusted filenames or text, THE SYSTEM SHALL escape
  them and SHALL disallow active scripts and external resources.

## R3. Insecure configuration

**User story:** As a maintainer, I want dangerous configuration defaults surfaced.

- WHEN a Docker stage has no explicit USER or its final USER is root/UID zero,
  THE SYSTEM SHALL report HAUNT and advise an unprivileged USER.
- WHEN Python assigns DEBUG/debug True, sets a DEBUG config item True, or passes
  `debug=True`, THE SYSTEM SHALL report HAUNT.
- WHEN text contains chmod 777 or curl piped into a shell, THE SYSTEM SHALL
  report HAUNT with least-privilege or verified-download advice.
- WHEN a configuration file contains an HTTP URL, THE SYSTEM SHALL report SPOOK
  and advise HTTPS for nonlocal services.

## R4. Risky Python code

**User story:** As a reviewer, I want high-risk APIs located without executing them.

- WHEN a Python AST calls eval/exec, subprocess with `shell=True`, or pickle
  deserialization, THE SYSTEM SHALL report HAUNT at the call's starting line.
- WHEN `yaml.load` lacks an explicit SafeLoader/CSafeLoader, THE SYSTEM SHALL
  report HAUNT and recommend `safe_load`.
- WHEN a password-related statement or function uses MD5/SHA1, THE SYSTEM SHALL
  report HAUNT and recommend a salted slow password KDF.
- WHEN imports use ordinary aliases, THE SYSTEM SHALL resolve those aliases.
- WHEN code-like text is only a comment or string, THE SYSTEM SHALL NOT treat it
  as an executable AST call.

## R5. Dependencies and optional advisories

**User story:** As an offline-first user, I want manifest checks without mandatory
cloud access.

- WHEN a requirement entry lacks an exact `==` pin without a wildcard,
  THE SYSTEM SHALL report WHISPER with reproducible-install advice.
- IF `--osv` is supplied, WHEN exact PyPI/npm versions are found, THE SYSTEM SHALL
  query `api.osv.dev` with only ecosystem, package name, and version.
- WHEN identical package/version queries repeat, THE SYSTEM SHALL reuse results.
- WHEN the first request fails or returns invalid data, THE SYSTEM SHALL warn,
  skip remaining online work, and finish local checks and report generation.
- WHILE querying OSV, THE SYSTEM SHALL enforce a timeout, response-size limit,
  and unique-query budget.
- WHEN an advisory has no supported severity, THE SYSTEM SHALL default to HAUNT.

## R6. Reports and CI

**User story:** As a developer, I want a portable, spooky report and CI exit codes.

- WHEN a scan completes, THE SYSTEM SHALL write a last-report HTML file and any
  requested HTML/JSON export, even when high-severity findings exist.
- WHEN a finding is reported, THE SYSTEM SHALL include a spooky and standard
  severity, rule ID, title, file:line, CWE ID, and fix advice.
- WHEN calculating Soul Integrity, THE SYSTEM SHALL subtract 25/12/5/1 points
  for CRYPT/HAUNT/SPOOK/WHISPER respectively and clamp the result at zero.
- WHEN CRYPT or HAUNT findings exist, THE SYSTEM SHALL exit `1`.
- WHEN only SPOOK/WHISPER or no findings exist, THE SYSTEM SHALL exit `0`.
- WHEN arguments or file/server operations fail, THE SYSTEM SHALL exit `2`
  without exposing raw exception contents.
- WHEN rendering HTML, THE SYSTEM SHALL produce one self-contained file with a
  black/red/green retro interface, ASCII skull, flicker, and blinking cursor.
- WHILE reduced motion is preferred, THE SYSTEM SHALL disable all animations.
- WHEN using keyboard or narrow screens, THE SYSTEM SHALL provide readable
  labels, semantic tables, focus cues, disclosures, and scrollable findings.

## R7. Local report viewer

**User story:** As a demo presenter, I want to view the last report safely.

- WHEN `serve` runs, THE SYSTEM SHALL bind only to `127.0.0.1`.
- WHEN a client requests `/` or `/index.html`, THE SYSTEM SHALL return the latest
  persisted report with no-store and restrictive security headers.
- WHEN a client requests project files, directories, or traversal paths,
  THE SYSTEM SHALL return 404 rather than expose scanned source.

## R8. Reproducibility and Kiro integration

**User story:** As a hackathon judge, I want a reproducible demo and inspectable
spec-driven workflow.

- WHEN `python -m unittest -v` runs from the root, THE SYSTEM SHALL discover and
  pass tests without pip dependencies or external connectivity.
- WHEN a user scans `examples/haunted_app`, THE SYSTEM SHALL demonstrate all four
  spooky severities using clearly labeled fake, nonfunctional secrets only.
- WHEN a matching Python file is saved in Kiro, THE SYSTEM SHALL provide a hook
  to run the tests.
- WHEN a relevant scanner/example file is saved in Kiro, THE SYSTEM SHALL provide
  a hook to regenerate the example report without executing the fixture.
- THE SYSTEM SHALL include setup/demo/privacy documentation, screenshot
  placeholders, an MIT license, and tracked `.kiro` specs/steering/hooks.
