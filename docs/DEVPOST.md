# SATAN Reborn

## Tagline

Old-school paranoia. New-world code. An offline-first security auditor with a
haunted browser report.

## Inspiration

The 1995 Security Administrator Tool for Analyzing Networks made security
findings approachable through a browser. For Kiroween 2026's **Resurrection**
theme, we brought back that presentation spirit, not the network scanner.
Today's haunted house is often a source tree: exposed credentials, dangerous
defaults, and risky APIs hiding in familiar files.

SATAN Reborn is a new Python implementation. It does not contain the original
SATAN code or perform network attacks.

## What it does

Point it at a local folder. It reads bounded UTF-8 files without importing or
executing scanned code, installing dependencies, or contacting external services
by default. Four plugins implement **15 local rule IDs**:

- Credential patterns and high-entropy credential-like assignments.
- Insecure Docker/configuration choices, debug mode, permissive permissions,
  download-to-shell patterns, and plaintext configuration URLs.
- Risky Python calls, including dynamic execution, shell subprocesses, unsafe
  deserialization, and weak password hashing.
- Unpinned Python requirements.

The result is a portable, self-contained HTML report: ASCII skull, CRT
scanlines, four spooky severity levels with standard labels, visible coverage
warnings, and contextual fix disclosures. “Soul Integrity” is a transparent
heuristic, not a security guarantee. Credentials are redacted; findings contain
locations and advice, not source excerpts.

JSON exports and meaningful exit codes support CI. An optional viewer binds
only to loopback and exposes only the report. Exact PyPI/npm versions can be
checked against OSV **only with explicit `--osv` network opt-in**, sending package
metadata, never source. This feature is not required for the offline demo.
There is no bundled vulnerability database or default npm code analysis.

## How we built it

The runtime is Python 3.10+ standard library only: `pathlib`/`os` for traversal,
`ast` for Python checks, `re` and entropy heuristics for secrets, dataclasses for
findings, `html.escape` for output safety, and `unittest` for regression tests.
Reports use inline CSS, semantic HTML, and native disclosure controls, without
JavaScript, frameworks, fonts, analytics, or external assets.

**Kiro's role is represented by the preserved `.kiro/` workflow artifacts:**

- **Specs:** requirements tie user stories to acceptance criteria; design records
  architecture and safety boundaries; tasks map implementation to tests.
- **Steering:** product, technology, and structure files keep the Resurrection
  scope, privacy rules, stdlib-only constraint, and module responsibilities
  visible during changes.
- **Hooks:** checked-in command definitions describe test-on-save and offline
  haunted-demo rescans. They accept the demo's expected findings exit code
  without masking operational failures.
- **Vibe coding:** natural-language iteration translates “haunted retro terminal,
  but accessible” into small report changes, then checks the generated HTML
  and scanner behavior against specs and regression tests.

The finishing pass compared the checklist with actual code, fixed a missing
debug-attribute case and overly permissive exact-pin parsing, bounded decorative
motion, and captured a real report screenshot. We do not treat a checked box or
generated implementation as proof.

These files document the intended Kiro workflow, not a bundled chat recording or
verified live hook execution. Tests validate the supplied hook structure and
commands; activation/schema support must be checked in the user's Kiro version.
The project and tests work without Kiro or internet access.

## Challenges

- Making a security auditor safe to point at an untrusted local tree: skip
  symlinks, nonregular files, binaries, oversized files, and generated reports.
- Finding credential signals without copying their values into audit artifacts.
- Avoiding Python comment/string false positives while staying dependency-free.
- Keeping a theatrical report readable with keyboard navigation, reduced motion,
  narrow screens, and print output.
- Separating local findings from optional live advisory coverage, and completing
  reports gracefully when opt-in advisory requests fail.

This is bounded static analysis, not a sandbox against concurrent filesystem
mutation, exhaustive SAST, exploit verification, or proof that code is secure.

## Accomplishments

- A useful offline scan and report with no pip dependencies or build step.
- An intentionally vulnerable, fake-only fixture covering every local rule and
  every severity, guarded against accidental execution.
- Escaped, script-free HTML, redacted evidence, atomic exports, and CI exit codes.
- A standard-library test suite covering plugins, traversal, CLI, reports, the
  loopback viewer, and mocked advisory behavior.
- A real browser screenshot at `docs/screenshots/report.png` and a reproducible
  three-minute demo script at `docs/DEMO_SCRIPT.md`.

## What we learned

The strongest constraint was not the horror theme; it was earning trust.
An impressive score needs an honest explanation. Redaction should begin in the
finding model, not be added as a display patch. Offline defaults simplify the
demo and make data boundaries understandable. Specs are useful only when their
claims are reconciled against code and tested behavior.

Accessibility also improved the theme: readable labels and deliberate focus
states make the “terminal” feel more intentional, not less haunted.

## What's next

These are future ideas, **not implemented features**:

- More precise scope-aware Python analysis and broader configuration coverage.
- Reviewed suppressions/baselines and clearer coverage accounting.
- Additional lockfile formats and better dependency location mapping.
- An explicitly managed offline advisory snapshot, with provenance and age shown.
- Broader assistive-technology and browser testing.

We would keep the default experience local, inspectable, dependency-free, and
explicit about uncertainty.

## Built with tags

Python, Python Standard Library, unittest, AST, HTML5, CSS3, Kiro,
Static Analysis, Security, Offline First, Accessibility, Open Source

**License:** MIT. New implementation; not affiliated with the original SATAN.
