---
inclusion: always
---

# Repository map

- `satan_reborn/__main__.py`: argparse commands, persistence, CI exits.
- `satan_reborn/models.py`: Source, Finding, Report, Severity, score, schema.
- `satan_reborn/scanner.py`: safe traversal and plugin orchestration.
- `satan_reborn/checks/`: secret/config/risky-code/dependency plugins plus registry.
- `satan_reborn/osv.py`: explicitly enabled, bounded advisory client.
- `satan_reborn/report.py`: escaped standalone report renderer and atomic writes.
- `satan_reborn/server.py`: last-report-only loopback HTTP viewer.
- `examples/haunted_app/`: deliberately unsafe, fake-credential demo fixtures.
- `tests/`: discoverable unittest modules; no external services needed.
- `.kiro/specs/satan-reborn/`: EARS requirements, design, checked task list.
- `.kiro/steering/`: persistent product, tech, and repository context.
- `.kiro/hooks/`: exactly two JSON save hooks for tests and demo regeneration.
- `reports/`: ignored runtime output; default `last-report.html` lives here.

Keep check rules in their owning plugin. New rules require safe/unsafe tests,
a CWE, fix advice, and consistent spooky severity. Do not add raw snippets to
the shared report model. Update specs when behavior intentionally changes.
