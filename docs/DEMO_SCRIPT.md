# SATAN Reborn: 3-minute demo

**Runtime:** 3:00. **Theme:** Kiroween 2026, Resurrection.
Read at a relaxed pace; use the remaining seconds in each shot for clicks and
legible pauses. All shots are local. No credentials, accounts, external services,
or OSV requests are needed.

## Before recording

- Use a clean terminal in the repository root, Python 3.10+, and a browser.
  Close unrelated tabs and hide notifications and personal filesystem paths.
- Run `python3 -m unittest -v`; keep the real passing summary ready.
- Run the scan below. Exit **1 is expected**; do not chain it to the next
  command with `&&`. A shell configured to stop on nonzero exit needs the
  demonstrated explicit exit-code handling.

```sh
python3 -m satan_reborn scan examples/haunted_app \
  --html reports/haunted.html --json reports/haunted.json
code=$?
printf 'Scan exit: %s\n' "$code"
test "$code" -eq 1
```

- Open `reports/haunted.html` directly, without a server. Set browser zoom to
  100%, use a desktop viewport, and enable reduced motion if preferred.
- Keep the fixture README, `app.py`, JSON report, and `.kiro/` tree open in an
  editor. Inspect text only. Never run the haunted app or install its packages.
- The current demo has 19 findings across all 15 local rules, all four
  severities, and Soul Integrity 0/100. If fixtures change, use actual output,
  not these numbers or an edited terminal transcript.
- `docs/screenshots/report.png` is a fallback still, not footage of interaction.
  Capture any Kiro IDE/hook behavior live only if it really works in the
  installed version. Do not fabricate a chat, save event, or hook notification.

## Timed narration and shot list

| Time | Shot / action | Narration |
| --- | --- | --- |
| **0:00–0:20** | Start on the report hero, skull, and Resurrection subtitle. | “In 1995, SATAN brought security findings into a browser. For Kiroween Resurrection, SATAN Reborn brings that idea back for local source code. Old-school paranoia, new-world code. This is a new implementation, not the original tool, and it does not scan networks.” |
| **0:20–0:40** | Show the short quickstart and fixture README. Briefly highlight the FAKE labels and fail-closed guard in `app.py`. | “It runs on Python 3.10 or newer, using only the standard library. No pip install, account, or internet is needed. Our haunted app is deliberately unsafe text, with clearly fake credentials and reserved example domains. We inspect it, never run it.” |
| **0:40–1:00** | Run the prepared scan command in the terminal. Show exit 1, redacted evidence, and report paths. | “One command scans the folder and writes HTML and JSON. The scanner never imports the app or installs its dependencies. Exit one means the scan completed and found critical or high signals. The reports are still written. Credential evidence is redacted.” |
| **1:00–1:25** | Return to the HTML. Show verdict, score disclaimer, severity counters, and click CRYPT. | “The report is a single offline file, with no JavaScript or external assets. Soul Integrity is a transparent scoring heuristic, not a security guarantee. CRYPT, HAUNT, SPOOK, and WHISPER also carry standard severity labels. These counters jump straight to the matching findings.” |
| **1:25–1:50** | Open the first finding's fix disclosure with the keyboard. Show CWE and file:line, then a shell or pickle finding and its advice. | “Every finding gives a location, a rule, a CWE, and practical fix advice. Secret values and source excerpts never appear in the report. The checks cover credential patterns, risky configuration, dangerous Python APIs, and unpinned Python requirements. Static analysis has blind spots, so context still matters.” |
| **1:50–2:10** | Narrow the browser, Tab into the table, then show reduced-motion behavior and a short JSON excerpt. | “The retro aesthetic still needs to be usable: visible keyboard focus, native disclosures, readable contrast, and a scrollable table on narrow screens. Decorative motion ends quickly and respects reduced motion. JSON makes the same findings useful in CI. Advisory lookups exist, but only behind explicit OSV opt-in.” |
| **2:10–2:40** | In the editor, show `.kiro/specs/satan-reborn/`, steering files, and both hook definitions. Show the task corrections, not a simulated Kiro session. | “The Kiro workflow is inspectable in the repository. Requirements define acceptance, design explains boundaries, and tasks track implementation. Steering preserves the offline, standard-library-only constraints. Hook definitions describe tests and demo rescans after saves. Vibe coding supplies the haunted look; specs and tests constrain the result. These are workflow artifacts, not a bundled recording of Kiro or proof that hooks fired.” |
| **2:40–3:00** | Show the real unittest summary, then return to the report and end on the project name and MIT license. | “The standard-library test suite checks the scanner, redaction, CLI, reports, optional advisory failure handling, and loopback viewer. All fifteen local rules have demo coverage. SATAN Reborn resurrects the browser-report spirit without resurrecting network attacks. Local, inspectable, and MIT licensed. The dead code tells tales. Listen carefully.” |

## Optional live viewer shot

Direct file viewing is sufficient. If showing the viewer instead, run this in
a second terminal and stop it with Ctrl+C after the take:

```sh
python3 -m satan_reborn serve --report reports/haunted.html
```

Open the displayed loopback address. It serves only the report, not the source
folder. Do not claim this is a public deployment. Do not enable `--osv` during
the offline recording, or claim a pinned package has been checked against live
advisories when it has not.
