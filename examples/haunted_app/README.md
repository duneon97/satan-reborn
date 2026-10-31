# Haunted app: intentionally vulnerable, text-only fixture

**Do not run, import, build, deploy, or install this example.**
It is scanner input, not a working application. `app.py` stops immediately if
accidentally invoked, before any third-party imports or unsafe calls.
The requirements and npm manifest are data to inspect, not project setup steps.

All credential-shaped strings in `app.py` are **FAKE**, nonfunctional
placeholders, not values issued by a service. The private-key example is only
a header with fake text, not key material. All example service/download URLs
use reserved `.invalid` domains.

From the repository root:

```sh
python3 -m satan_reborn scan examples/haunted_app \
  --html reports/haunted.html --json reports/haunted.json
```

Expected exit code: **1**, meaning the scan succeeded and found critical/high
signals. Open `reports/haunted.html` directly in a browser. No internet is needed.

## What to look for

| Fixture | Local rules demonstrated |
| --- | --- |
| `app.py` | `secret.aws`, `secret.github`, `secret.private-key`, `secret.entropy`, `config.debug`, `code.dynamic-execution`, `code.shell`, `code.pickle`, `code.yaml`, `code.password-hash` |
| `Dockerfile` | `config.docker-root`, `config.chmod`, `config.curl-shell` |
| `settings.env` | `config.http` |
| `requirements.txt` | `deps.unpinned` |
| `package.json` | Exact npm metadata for optional OSV extraction, not a local advisory database |

The fixture covers all **15 local rule IDs** and all four severity levels.
Default scans flag unpinned Python requirements, but do **not** label pinned
Python/npm versions as vulnerable without advisory data. OSV is optional and
requires an explicit network opt-in; it is not part of this offline demo.
Findings show locations, CWEs, and remediation, but never matched source or
credential values. Deliberate vulnerabilities should stay here for regression
tests, not be copied into a real project.
