---
inclusion: always
---

# Technology constraints

- Python >=3.10, standard library only. No pip, npm, build-system, or CDN dependency.
- Entry point: `python -m satan_reborn`. Tests: `python -m unittest -v`.
- Local plugins: `analyze(Source) -> list[Finding]`, explicitly registered.
- Python risk checks use AST and must not import target code.
- Source/credential values must not appear in Finding objects or reports.
- Escape all target-controlled HTML fields. Keep reports single-file and scriptless.
- Keep reduced-motion rules, semantic tables, focus outlines, readable contrast,
  and keyboard-native details/summary disclosures.
- Serve only a report, only on 127.0.0.1. Do not expose source or add a bind option.
- Default scans are offline. Mock OSV in tests; enforce timeout, size, query
  limits and graceful offline handling.
- Exit 1 for CRYPT/HAUNT after report generation, 0 otherwise, 2 for operations.
- Run the test suite and the example scan after meaningful code changes.
- Reports and __pycache__ are ignored. `.kiro` remains tracked.
