---
inclusion: always
---

# Product

SATAN Reborn is a Kiroween 2026 Resurrection project: the spirit of the 1995
Security Administrator Tool for Analyzing Networks, rebuilt as a modern
offline-first security auditor for a **local code folder**. It does not scan
networks, execute code, install dependencies, or make network requests unless
`--osv` is explicitly passed.

## Purpose and audience

- Developers and code owners who want quick, dependency-free static security
  checks against a local source tree.
- CI pipelines that need an exit code signalling critical/high findings.
- Hackathon/demo audiences who want a polished, retro 1995-inspired browser
  report with no JavaScript, no external assets, and no trackers.

## Core value propositions

1. **Zero setup** — Python 3.10+ standard library only; no pip, npm, or build step.
2. **Offline by default** — no network requests unless the user opts in with `--osv`.
3. **Read-only audit** — scanned code is never imported, executed, or modified.
4. **Privacy** — credential values are replaced with `[REDACTED]`; no source
   excerpts or matched secrets appear in any Finding, report, or terminal output.
5. **Retro presentation** — black terminal, red/green CRT aesthetic, ASCII skull,
   blinking cursor, subtle flicker — all done with pure CSS; no JS.

## What the tool checks

Four independent plugins, each in `satan_reborn/checks/`:

| Plugin | Focus | CWEs |
|---|---|---|
| `hardcoded_secrets` | AWS key IDs (AKIA/ASIA), GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_), private-key BEGIN headers, high-entropy quoted credential assignments | CWE-798 |
| `insecure_config` | Docker root USER (per-stage), Flask/Django `debug=True` (AST), chmod 777, curl\|shell, HTTP URLs in config files | CWE-250, 489, 732, 494, 319 |
| `risky_code` | Python eval/exec, subprocess shell=True, pickle.load/loads, unsafe yaml.load (no SafeLoader/CSafeLoader), weak password hashes (MD5/SHA1) | CWE-95, 78, 502, 916 |
| `dependencies` | Unpinned requirements.txt entries; exact PyPI/npm versions extracted for optional OSV queries | CWE-1104, 1395 |

## Severity and Soul Integrity

| Spooky | Standard | Score deduction |
|---|---|---|
| CRYPT | CRITICAL | 25 |
| HAUNT | HIGH | 12 |
| SPOOK | MEDIUM | 5 |
| WHISPER | LOW | 1 |

Soul Integrity = `max(0, 100 − Σ penalties)`. It is a transparent demo heuristic,
not a calibrated risk model. Communicate this clearly wherever it appears.

## Boundaries and honesty

- This is a compact static auditor, not a full SAST engine or pen-test.
- No interprocedural analysis, data-flow tracking, or JS analysis is performed.
- False positives are expected for fixtures, shadow names, local HTTP, and
  Docker base-image USER inheritance.
- Every finding includes fix advice, a CWE, and a severity; context is required.

## Content rules

- Never execute scanned application code or install its dependencies.
- Never use real credentials in fixtures; label all placeholder values as FAKE.
- Never expose credential values in outputs, reports, or terminal lines.
- Never add external fonts, analytics, trackers, or JavaScript to reports.
- OSV `--osv` sends only ecosystem/name/version — never source, paths, or secrets.
- The haunted demo app is intentionally insecure text for scanner input only;
  do not run, deploy, repair, or build it.
- Preserve privacy warnings, redaction behaviour, and FAKE labels.
