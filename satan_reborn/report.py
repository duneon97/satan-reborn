"""Self-contained, escaped, offline HTML and machine-readable JSON reports."""

import json
import os
import tempfile
from html import escape
from pathlib import Path

from . import __version__
from .models import Report, Severity

SKULL = r'''
       .-""""-.
      /        \
     /_        _\
    // \      / \\
    |\__\    /__/|
     \    ||    /
      \        /
       |VVVVVV|
       |______|
       MEMENTO
        SECURI
'''

STYLE = """
:root{color-scheme:dark;--bg:#080c0a;--panel:#0e1511;--green:#8bffad;--muted:#a3b4a8;
--red:#ff7b83;--line:#344b3b;--white:#edf6ee;--amber:#ffd18a;--purple:#d4bcff}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);
color:var(--white);font:14px/1.65 "Courier New",Courier,monospace}
body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:5;opacity:.12;
background:repeating-linear-gradient(0deg,transparent 0 3px,#000 3px 4px)}
::selection{background:var(--green);color:#080c0a}a{color:var(--green);text-underline-offset:4px}
a:focus-visible,summary:focus-visible{outline:3px solid var(--amber);outline-offset:5px}
.skip{position:absolute;left:12px;top:-80px;background:var(--green);color:#000;padding:8px;z-index:9}
.skip:focus{top:8px}.wrap{max-width:1240px;margin:auto;padding:0 36px}
.masthead{border-bottom:1px solid var(--line);background:#0c110e}
.masthead .wrap{min-height:62px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.brand{font-weight:bold;letter-spacing:3px;color:var(--green)}.brand b{color:var(--red)}
nav{display:flex;gap:24px;font-size:12px}nav a{text-decoration:none;color:var(--muted)}
.status{color:var(--green);font-size:11px;letter-spacing:1px}.dot{display:inline-block;
width:7px;height:7px;background:var(--green);margin-right:7px;box-shadow:0 0 9px #8bffad66}
.hero{display:grid;grid-template-columns:1fr 245px;align-items:center;gap:32px;padding:48px 0 36px}
.eyebrow{font-size:11px;letter-spacing:2px;color:var(--red);margin:0 0 14px;text-transform:uppercase}
h1{font-size:clamp(48px,8vw,98px);line-height:.95;letter-spacing:-6px;margin:0;font-weight:900}
h1 span{display:block;color:var(--green);font-size:.49em;letter-spacing:12px;margin-top:14px}
.cursor{color:var(--red);animation:blink 1.2s steps(1,end) infinite}
.lede{max-width:640px;color:var(--muted);font-size:13px;margin-top:25px}
.tag{display:inline-block;border:1px solid var(--line);font-size:10px;padding:3px 8px;
color:var(--green);letter-spacing:1px;margin:3px 4px 0 0}
.skull{margin:0;text-align:center;color:var(--green);font-size:15px;line-height:1.2;
text-shadow:0 0 18px #8bffad35;animation:flicker 9s linear infinite}
.session{border:1px solid var(--line);background:var(--panel);margin-bottom:24px}
.bar{padding:8px 15px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;
gap:12px;font-size:11px;color:var(--muted);background:#131d16;letter-spacing:1px}
.lights{color:var(--red);letter-spacing:5px}.session-body{padding:18px 22px;display:grid;
grid-template-columns:1fr 1fr;gap:8px 30px;font-size:12px}.label{color:var(--muted)}
.value{overflow-wrap:anywhere}.prompt{color:var(--green)}
.dashboard{display:grid;grid-template-columns:1.25fr 2fr;gap:22px;margin:0 0 38px}
.integrity{border:1px solid var(--line);padding:22px;background:var(--panel)}
.section-kicker{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;margin:0}
.score{font-size:58px;line-height:1.1;font-weight:bold;color:var(--green);margin:10px 0}
.score small{font-size:16px;font-weight:normal;color:var(--muted)}
meter{width:100%;height:12px;accent-color:var(--green)}
meter::-webkit-meter-bar{background:#243429;border:0;border-radius:0}
meter::-webkit-meter-optimum-value{background:var(--green)}
.score-note{font-size:11px;color:var(--muted);margin:10px 0 0}
.counts{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--line);background:var(--panel)}
.count{padding:23px 16px;border-right:1px solid var(--line);text-decoration:none;color:inherit}
.count:last-child{border:0}.count strong{display:block;font-size:42px;line-height:1.4}
.count .standard{display:block;font-size:10px;color:var(--muted);margin-top:10px}
.crypt{color:var(--red)}.haunt{color:var(--amber)}.spook{color:var(--purple)}.whisper{color:var(--green)}
.section-head{display:flex;justify-content:space-between;align-items:center;gap:15px;margin:0 0 16px}
h2{font-size:19px;letter-spacing:1px;margin:0}h2 .index{color:var(--red);font-size:12px;margin-right:10px}
.small{font-size:11px;color:var(--muted)}.table-wrap{overflow:auto;border:1px solid var(--line)}
table{width:100%;border-collapse:collapse;text-align:left;min-width:760px}
caption{text-align:left;padding:12px 16px;background:var(--panel);font-size:11px;color:var(--muted)}
th{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--muted);
background:#131d16;padding:12px 16px;border-bottom:1px solid var(--line)}
td{padding:18px 16px;vertical-align:top;border-bottom:1px solid #25382b;font-size:12px}
tr:last-child td{border:0}tbody tr:hover{background:#101c14}.badge{display:inline-block;
border:1px solid currentColor;padding:2px 7px;font-size:10px;font-weight:bold;letter-spacing:1px}
.finding-title{font-size:13px;font-weight:bold}.rule{font-size:10px;color:var(--muted);
display:block;margin-top:5px}code{font:inherit;color:var(--green);overflow-wrap:anywhere}
.location{min-width:180px;max-width:290px;overflow-wrap:anywhere}.location a{color:var(--muted)}
details{margin-top:10px}summary{color:var(--green);cursor:pointer;width:fit-content}
.advice{color:var(--muted);max-width:550px;margin:8px 0 0}
.masked{display:block;color:var(--amber);font-size:10px;margin-top:7px}
.clear{padding:34px;color:var(--green);text-align:center;border:1px solid var(--line)}
.notes{margin:32px 0;border:1px solid var(--line);padding:20px 24px;background:var(--panel)}
.notes h2{font-size:14px;color:var(--amber)}.notes ul{font-size:12px;color:var(--muted);padding-left:20px}
.about{display:grid;grid-template-columns:1fr 1fr;gap:36px;margin:40px 0}
.about h3{font-size:12px;color:var(--green);letter-spacing:1px}.about p{font-size:12px;color:var(--muted)}
footer{border-top:1px solid var(--line);padding:22px 0 30px;font-size:10px;color:var(--muted)}
footer .wrap{display:flex;justify-content:space-between;gap:20px}.red{color:var(--red)}
@keyframes blink{50%{opacity:0}}@keyframes flicker{0%,97%,100%{opacity:1}98%{opacity:.7}99%{opacity:.95}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;
transition:none!important;scroll-behavior:auto!important}}
@media(max-width:800px){.wrap{padding:0 18px}.hero{grid-template-columns:1fr 140px;gap:14px}
.skull{font-size:11px}h1{letter-spacing:-3px}h1 span{letter-spacing:6px}.dashboard{grid-template-columns:1fr}
.masthead .status{display:none}.count{padding:16px}.session-body{grid-template-columns:1fr}
.about{grid-template-columns:1fr;gap:10px}footer .wrap{flex-direction:column;gap:5px}}
@media(max-width:480px){.hero{grid-template-columns:1fr}.skull{display:none}.hero{padding-top:35px}
nav{gap:14px}.brand{font-size:12px;letter-spacing:1px}.count{padding:12px 8px}
.count strong{font-size:30px}.count .badge{font-size:9px;padding:2px 4px}.bar{font-size:9px}}
@media print{body{background:#fff;color:#000}body:before,.skull,.cursor,nav{display:none}
*{animation:none!important;text-shadow:none!important;color:#000!important}
.wrap{max-width:none;padding:0}.hero{padding:15px 0}.dashboard{margin-bottom:15px}
details>p{display:block!important}table{min-width:0}td,th{padding:8px}a{text-decoration:none}}
"""

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


def render_html(report: Report) -> str:
    e = escape
    counts = report.counts
    cards = "".join(
        f'<a class="count {s.value.lower()}" href="#findings" '
        f'aria-label="{counts[s.value]} {s.value}, {s.standard} findings">'
        f'<span class="badge">{s.value}</span><strong>{counts[s.value]:02d}</strong>'
        f'<span class="standard">{s.standard}</span></a>'
        for s in Severity
    )
    rows = []
    for number, finding in enumerate(report.findings, 1):
        location = f"{finding.file}:{finding.line}"
        masked = f'<span class="masked">{e(finding.evidence)}</span>' if finding.evidence else ""
        rows.append(
            f'<tr id="finding-{number}"><td><span class="badge {finding.severity.value.lower()}">'
            f'{finding.severity.value}</span><span class="rule">{finding.severity.standard}</span></td>'
            f'<td><span class="finding-title">{e(finding.title)}</span>{masked}'
            f'<span class="rule">{e(finding.rule_id)} / {e(finding.cwe)}</span>'
            f'<details><summary>Exorcism / fix advice</summary>'
            f'<p class="advice">{e(finding.advice)}</p></details></td>'
            f'<td class="location"><a href="#finding-{number}" '
            f'aria-label="{e(location, quote=True)}">{e(location)}</a></td></tr>'
        )
    findings_html = (
        '<div class="table-wrap" role="region" aria-label="Security findings" tabindex="0">'
        '<table><caption>Sorted by severity, then file and line. Open a finding for fix advice.</caption>'
        '<thead><tr><th scope="col">Threat level</th><th scope="col">Finding / remediation</th>'
        '<th scope="col">File:line</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>"
        if rows else '<div class="clear">[ OK ] No apparitions detected by enabled checks.</div>'
    )
    warning_html = ""
    if report.warnings:
        warning_html = (
            '<aside class="notes" aria-labelledby="warning-heading">'
            '<h2 id="warning-heading">Scanner field notes / coverage warnings</h2><ul>'
            + "".join(f"<li>{e(w)}</li>" for w in report.warnings) + "</ul></aside>"
        )
    verdict = "EXORCISM REQUIRED" if report.has_blockers else "NO HIGH-SEVERITY SIGNALS"
    network = "OSV OPT-IN" if report.osv_enabled else "OFFLINE / NO NETWORK"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{e(CSP, quote=True)}">
<meta name="color-scheme" content="dark">
<title>SATAN Reborn | {e(report.target)} security report</title>
<style>{STYLE}</style>
</head>
<body>
<a class="skip" href="#findings">Skip to findings</a>
<header class="masthead"><div class="wrap">
  <div class="brand">SATAN<b>://</b>REBORN</div>
  <nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#findings">Findings</a><a href="#about">Readme</a></nav>
  <span class="status"><span class="dot" aria-hidden="true"></span>LOCAL SYSTEM ONLINE</span>
</div></header>
<main class="wrap" id="overview">
  <section class="hero" aria-labelledby="report-title">
    <div><p class="eyebrow">Est. 1995 / Resurrected 2026 / Kiroween</p>
      <h1 id="report-title">SATAN<span>REBORN<i class="cursor" aria-hidden="true">_</i></span></h1>
      <p class="lede">Old-school paranoia. New-world code.<br>
      A local security audit, summoned from the grave.</p>
      <span class="tag">READ-ONLY AUDIT</span><span class="tag">STDLIB ONLY</span><span class="tag">{network}</span>
    </div><pre class="skull" aria-hidden="true">{e(SKULL)}</pre>
  </section>
  <section class="session" aria-label="Scan session">
    <div class="bar"><span><span class="lights" aria-hidden="true">● ● ●</span> SATAN_REBORN.EXE / AUDIT LOG</span><span>v{__version__}</span></div>
    <div class="session-body">
      <div><span class="prompt">$ target </span><span class="value">{e(report.target)}</span></div>
      <div><span class="label">UTC timestamp </span><span class="value">{e(report.generated_at)}</span></div>
      <div><span class="label">Files examined </span>{report.files_scanned} <span class="label">/ files skipped </span>{report.files_skipped}</div>
      <div><span class="label">Verdict </span><strong class="{'red' if report.has_blockers else 'prompt'}">{verdict}</strong></div>
    </div>
  </section>
  <section class="dashboard" aria-label="Audit summary">
    <div class="integrity"><p class="section-kicker">Soul Integrity</p>
      <p class="score">{report.soul_integrity}<small> / 100</small></p>
      <meter min="0" max="100" value="{report.soul_integrity}" aria-label="Soul Integrity">{report.soul_integrity} out of 100</meter>
      <p class="score-note">A heuristic, not a security guarantee.</p>
    </div><div class="counts">{cards}</div>
  </section>
  <section id="findings" aria-labelledby="findings-heading">
    <div class="section-head"><h2 id="findings-heading"><span class="index">01 /</span>The haunting</h2>
    <span class="small">{len(report.findings)} findings recovered</span></div>
    {findings_html}
  </section>
  {warning_html}
  <section class="about" id="about" aria-label="About this audit">
    <div><h3>02 / FROM NETWORKS TO NECROMANCY</h3>
    <p>In 1995, SATAN helped administrators uncover network weaknesses.
    Reborn preserves the browser-report spirit, but inspects a local code folder instead.
    No port scans. No code execution. No source uploads.</p></div>
    <div><h3>03 / KNOW YOUR DEMONS</h3>
    <p>CRYPT = critical, HAUNT = high, SPOOK = medium, WHISPER = low.
    Soul Integrity starts at 100 and loses 25 / 12 / 5 / 1 points per finding.
    Review context before fixing. Ignored files and static-analysis blind spots still exist.
    Credential values are redacted; source excerpts are never included.</p></div>
  </section>
</main>
<footer><div class="wrap"><span>SATAN REBORN © 2026 Minh Tuan Le / MIT</span>
<span>THE DEAD CODE TELLS TALES. LISTEN CAREFULLY.</span></div></footer>
</body></html>
"""


def write_text_atomic(path, content: str) -> None:
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".satan-", suffix=".tmp", dir=destination.parent)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary)


def write_json(report: Report, path) -> None:
    write_text_atomic(path, json.dumps(report.to_dict(), indent=2, ensure_ascii=True) + "\n")
