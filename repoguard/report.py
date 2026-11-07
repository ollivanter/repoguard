"""Terminal, JSON, Markdown and HTML output."""
from __future__ import annotations

import html
import json
import os
import sys
from urllib.parse import quote

from .models import Finding, ScanResult, Severity

ICONS = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡", Severity.LOW: "🔵", Severity.INFO: "⚪"}
CATEGORY_NAMES = {"secrets": "Secrets", "dependencies": "Dependencies", "workflows": "Workflows"}
MARKER = "<!-- repoguard-report -->"
MAX_MARKDOWN = 60000


def link(result: ScanResult, f: Finding) -> str | None:
    if not (result.repo and f.file):
        return None
    base = f"{result.server_url.rstrip('/')}/{result.repo}"
    if f.commit:
        return f"{base}/commit/{f.commit}"
    if not result.commit:
        return None
    url = f"{base}/blob/{result.commit}/{quote(f.file)}"
    return url + (f"#L{f.line}" if f.line else "")


# ----------------------------------------------------------------- terminal
def terminal(result: ScanResult, stream=None) -> str:
    stream = stream or sys.stdout
    color = stream.isatty() and not os.environ.get("NO_COLOR")
    codes = {Severity.CRITICAL: "1;31", Severity.HIGH: "31", Severity.MEDIUM: "33", Severity.LOW: "36", Severity.INFO: "37"}

    def c(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    grade_code = {"A": "1;32", "B": "32", "C": "33", "D": "33", "F": "1;31"}[result.grade]
    out = [c("RepoGuard", "1") + f"  {result.repo or result.target}" + (f" @ {result.commit[:7]}" if result.commit else ""),
           f"Score {c(f'{result.score}/100', grade_code)}  Grade {c(result.grade, grade_code)}  "
           + "  ".join(f"{k}: {v}" for k, v in result.counts().items() if k != "info"), ""]
    for f in result.sorted_findings():
        out.append(f"{c(f'[{f.severity.label.upper():8}]', codes[f.severity])} {f.title}")
        if f.location:
            out.append(f"           {f.location}" + (f"  (commit {f.commit[:7]})" if f.commit else ""))
    if not result.findings:
        out.append(c("No findings. Nice.", "32"))
    for n in result.notes:
        out.append(c(f"note: {n}", "2"))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------- json
def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


# ----------------------------------------------------------------- markdown
def _md(text: str) -> str:
    return html.escape(text, quote=False)


def markdown(result: ScanResult) -> str:
    counts = result.counts()
    head = [MARKER,
            f"## 🛡️ RepoGuard · {result.score}/100 · Grade {result.grade}", "",
            f"**{_md(result.repo or result.target)}**" + (f" · `{result.commit[:7]}`" if result.commit else "")
            + f" · {len(result.findings)} finding{'s' if len(result.findings) != 1 else ''}", "",
            "| 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low |", "|:-:|:-:|:-:|:-:|",
            f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |", ""]
    for n in result.notes:
        head.append(f"> ℹ️ {_md(n)}")
    if result.notes:
        head.append("")
    if not result.findings:
        head.append("✅ No issues found.")
    body: list[str] = []
    size = sum(len(x) + 1 for x in head)
    shown = 0
    findings = result.sorted_findings()
    for sev in sorted(Severity, reverse=True):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        section = [f"<details{' open' if sev >= Severity.HIGH else ''}><summary><b>{ICONS[sev]} "
                   f"{sev.label.capitalize()} ({len(group)})</b></summary>", ""]
        for f in group:
            url = link(result, f)
            loc = _md(f.location) + (f" (commit {f.commit[:7]})" if f.commit else "")
            block = [f"#### {_md(f.title)}",
                     f"📍 {f'[{loc}]({url})' if url else loc} · `{f.rule}`", "", _md(f.description), ""]
            if f.evidence:
                block += [f"<pre>{html.escape(f.evidence)}</pre>", ""]
            block += [f"**Fix:** {_md(f.fix)}", ""]
            if f.references:
                block += [" · ".join(f"[{_md(r.rsplit('/', 1)[-1])}]({r})" for r in f.references[:6]), ""]
            chunk = "\n".join(block)
            if size + len(chunk) > MAX_MARKDOWN:
                break
            section.append(chunk)
            size += len(chunk)
            shown += 1
        section.append("</details>\n")
        body.extend(section)
    if shown < len(findings):
        body.append(f"…and {len(findings) - shown} more. Download the full HTML report from this run's artifacts.")
    body.append("<sub>Scanned by RepoGuard: secrets, dependencies (OSV.dev) and GitHub Actions workflows.</sub>")
    return "\n".join(head + [""] + body) + "\n"


# --------------------------------------------------------------------- html
GRADE_COLOR = {"A": "var(--ok)", "B": "var(--good)", "C": "var(--warn)", "D": "var(--orange)", "F": "var(--bad)"}
SEV_VAR = {Severity.CRITICAL: "--critical", Severity.HIGH: "--high", Severity.MEDIUM: "--medium",
           Severity.LOW: "--low", Severity.INFO: "--info"}


def _e(text) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def _inline_code(text: str) -> str:
    """Escape, then turn `code` spans into <code>."""
    parts = _e(text).split("`")
    return "".join(f"<code>{p}</code>" if i % 2 else p for i, p in enumerate(parts))


def _finding_html(result: ScanResult, f: Finding) -> str:
    url = link(result, f)
    loc = _e(f.location) + (f" · commit {_e(f.commit[:7])}" if f.commit else "")
    loc_html = f'<a href="{_e(url)}" target="_blank" rel="noopener">{loc}</a>' if url else loc
    desc_lines = f.description.split("\n")
    desc = "<p>" + _inline_code(desc_lines[0]) + "</p>"
    rest = [l[2:] for l in desc_lines[1:] if l.startswith("- ")]
    if rest:
        desc += "<ul>" + "".join(f"<li>{_inline_code(r)}</li>" for r in rest) + "</ul>"
    refs = "".join(f'<a href="{_e(r)}" target="_blank" rel="noopener">{_e(r.rsplit("/", 1)[-1])}</a>' for r in f.references[:8])
    return f"""
<article class="finding" data-sev="{f.severity.label}" data-cat="{f.category}" style="--sev: var({SEV_VAR[f.severity]})">
  <header>
    <span class="pill">{f.severity.label}</span>
    <span class="cat">{CATEGORY_NAMES[f.category]}</span>
    <h3>{_inline_code(f.title)}</h3>
  </header>
  <div class="meta">{loc_html}<span class="rule">{_e(f.rule)}</span></div>
  {desc}
  {f'<pre class="evidence">{_e(f.evidence)}</pre>' if f.evidence else ''}
  <div class="fix"><span>Fix</span><p>{_inline_code(f.fix)}</p></div>
  {f'<div class="refs">{refs}</div>' if refs else ''}
</article>"""


def html_report(result: ScanResult) -> str:
    counts = result.counts()
    circumference = 2 * 3.14159 * 54
    dash = circumference * result.score / 100
    by_cat = {c: sum(1 for f in result.findings if f.category == c) for c in CATEGORY_NAMES}
    stats = result.stats
    stat_items = [("Files scanned", stats.get("files_scanned")), ("Commits in history", stats.get("commits_scanned")),
                  ("Packages checked", stats.get("packages_checked")), ("Workflows", stats.get("workflows_scanned"))]
    stat_html = "".join(f"<div><b>{_e(v)}</b><span>{_e(k)}</span></div>" for k, v in stat_items if v is not None)
    sev_tiles = "".join(
        f'<button class="tile" data-filter-sev="{s.label}" style="--sev: var({SEV_VAR[s]})">'
        f"<b>{counts[s.label]}</b><span>{s.label}</span></button>"
        for s in sorted(Severity, reverse=True) if s != Severity.INFO)
    cat_chips = '<button class="chip active" data-filter-cat="all">All <i>{}</i></button>'.format(len(result.findings)) + "".join(
        f'<button class="chip" data-filter-cat="{c}">{name} <i>{by_cat[c]}</i></button>' for c, name in CATEGORY_NAMES.items())
    notes = "".join(f'<div class="note">{_inline_code(n)}</div>' for n in result.notes)
    findings = "".join(_finding_html(result, f) for f in result.sorted_findings())
    empty = '<div class="empty"><b>No findings.</b><span>Nothing leaked, nothing vulnerable, workflows look tight.</span></div>'
    title = result.repo or result.target
    commit = f'<code>{_e(result.commit[:7])}</code>' if result.commit else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RepoGuard · {_e(title)}</title>
<style>
:root {{
  --bg: #07090d; --panel: #0d1117; --panel2: #111823; --line: #1c2633; --text: #d7e0ea; --muted: #7d8b9c;
  --accent: #36f1cd; --ok: #36f1cd; --good: #9be564; --warn: #ffd166; --orange: #ff9f43; --bad: #ff4d6d;
  --critical: #ff4d6d; --high: #ff9f43; --medium: #ffd166; --low: #5aa9ff; --info: #7d8b9c;
  --mono: ui-monospace, "JetBrains Mono", "SFMono-Regular", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; background: var(--bg); color: var(--text); font: 15px/1.55 var(--sans); }}
body {{ background-image: radial-gradient(circle at 20% -10%, #36f1cd14, transparent 40%),
  linear-gradient(var(--line) 1px, transparent 1px), linear-gradient(90deg, var(--line) 1px, transparent 1px);
  background-size: auto, 48px 48px, 48px 48px; background-attachment: fixed; }}
.wrap {{ max-width: 1040px; margin: 0 auto; padding: 32px 16px 64px; }}
a {{ color: var(--accent); text-decoration: none; }} a:hover {{ text-decoration: underline; }}
code {{ font: 0.9em var(--mono); background: #ffffff0d; border: 1px solid var(--line); padding: 1px 5px; border-radius: 4px; word-break: break-word; }}
.top {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; color: var(--muted); font: 13px var(--mono); }}
.logo {{ color: var(--accent); font-weight: 700; letter-spacing: .2em; }}
.logo::before {{ content: "◆ "; }}
h1 {{ font: 700 clamp(22px, 4vw, 32px)/1.2 var(--mono); margin: 8px 0 24px; word-break: break-word; }}
.hero {{ display: grid; grid-template-columns: auto 1fr; gap: 24px; background: var(--panel); border: 1px solid var(--line);
  border-radius: 14px; padding: 24px; box-shadow: 0 0 0 1px #36f1cd0a, 0 20px 60px -30px #36f1cd33; }}
.dial {{ position: relative; width: 140px; height: 140px; }}
.dial svg {{ transform: rotate(-90deg); }}
.dial .track {{ stroke: var(--line); }}
.dial .bar {{ stroke: var(--grade); filter: drop-shadow(0 0 6px var(--grade)); stroke-linecap: round; }}
.dial .val {{ position: absolute; inset: 0; display: grid; place-content: center; text-align: center; }}
.dial .val b {{ font: 700 40px/1 var(--mono); color: var(--grade); }}
.dial .val span {{ font: 12px var(--mono); color: var(--muted); }}
.grade {{ font: 700 13px var(--mono); color: var(--grade); border: 1px solid var(--grade); border-radius: 999px; padding: 2px 10px; }}
.tiles {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; }}
.tile {{ all: unset; cursor: pointer; background: var(--panel2); border: 1px solid var(--line); border-top: 2px solid var(--sev);
  border-radius: 10px; padding: 10px 12px; display: flex; flex-direction: column; }}
.tile b {{ font: 700 24px var(--mono); color: var(--sev); }}
.tile span {{ font: 12px var(--mono); color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }}
.tile:hover, .tile.active {{ background: #ffffff08; box-shadow: inset 0 0 0 1px var(--sev); }}
.tile:focus-visible, .chip:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
.stats {{ display: flex; flex-wrap: wrap; gap: 18px; }}
.stats div {{ display: flex; flex-direction: column; }}
.stats b {{ font: 600 16px var(--mono); }} .stats span {{ font-size: 12px; color: var(--muted); }}
.note {{ margin-top: 16px; padding: 10px 14px; border: 1px dashed var(--warn); border-radius: 10px; color: var(--warn); font-size: 14px; }}
.bar-row {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 28px 0 14px; align-items: center; }}
.chip {{ all: unset; cursor: pointer; font: 13px var(--mono); padding: 6px 12px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); }}
.chip i {{ font-style: normal; opacity: .7; margin-left: 4px; }}
.chip.active {{ color: var(--bg); background: var(--accent); border-color: var(--accent); }}
.finding {{ background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--sev); border-radius: 12px;
  padding: 16px 18px; margin-bottom: 12px; }}
.finding header {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }}
.finding h3 {{ flex-basis: 100%; margin: 6px 0 0; font: 600 16px/1.4 var(--sans); }}
.pill {{ font: 700 11px var(--mono); text-transform: uppercase; letter-spacing: .08em; color: var(--sev);
  border: 1px solid var(--sev); border-radius: 999px; padding: 1px 8px; }}
.cat {{ font: 12px var(--mono); color: var(--muted); }}
.meta {{ display: flex; flex-wrap: wrap; gap: 12px; font: 13px var(--mono); margin: 6px 0 4px; word-break: break-all; }}
.rule {{ color: var(--muted); }}
.finding p {{ margin: 8px 0; }} .finding ul {{ margin: 6px 0; padding-left: 20px; }}
.evidence {{ font: 13px/1.5 var(--mono); background: #000; border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px;
  overflow-x: auto; color: #9fb3c8; margin: 10px 0; white-space: pre-wrap; word-break: break-all; }}
.fix {{ display: flex; gap: 10px; background: #36f1cd0d; border: 1px solid #36f1cd33; border-radius: 8px; padding: 10px 12px; margin-top: 10px; }}
.fix span {{ font: 700 11px var(--mono); color: var(--accent); text-transform: uppercase; letter-spacing: .1em; padding-top: 3px; }}
.fix p {{ margin: 0; }}
.refs {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; font: 12px var(--mono); }}
.empty {{ text-align: center; padding: 48px 16px; border: 1px dashed var(--ok); border-radius: 14px; color: var(--ok); }}
.empty b {{ display: block; font: 700 22px var(--mono); }} .empty span {{ color: var(--muted); }}
.hidden {{ display: none; }}
footer {{ margin-top: 40px; color: var(--muted); font: 12px var(--mono); text-align: center; }}
@media (max-width: 640px) {{
  .hero {{ grid-template-columns: 1fr; justify-items: center; text-align: center; }}
  .tiles {{ grid-template-columns: repeat(2, 1fr); width: 100%; }} .stats {{ justify-content: center; }}
}}
@media (prefers-reduced-motion: no-preference) {{ .dial .bar {{ transition: stroke-dasharray 1s ease-out; }} }}
</style>
</head>
<body>
<div class="wrap">
  <div class="top"><span class="logo">REPOGUARD</span><span>{_e(result.scanned_at)}</span>{commit}</div>
  <h1>{_e(title)}</h1>
  <section class="hero" style="--grade: {GRADE_COLOR[result.grade]}">
    <div class="dial" role="img" aria-label="Security score {result.score} out of 100, grade {result.grade}">
      <svg width="140" height="140" viewBox="0 0 140 140" aria-hidden="true">
        <circle class="track" cx="70" cy="70" r="54" fill="none" stroke-width="10"/>
        <circle class="bar" cx="70" cy="70" r="54" fill="none" stroke-width="10"
          stroke-dasharray="{dash:.1f} {circumference:.1f}"/>
      </svg>
      <div class="val"><b>{result.score}</b><span>/ 100</span></div>
    </div>
    <div>
      <div style="margin-bottom:12px"><span class="grade">GRADE {result.grade}</span></div>
      <div class="tiles">{sev_tiles}</div>
      <div class="stats">{stat_html}</div>
    </div>
  </section>
  {notes}
  <div class="bar-row" role="group" aria-label="Filter by category">{cat_chips}</div>
  <main id="findings">{findings if result.findings else empty}</main>
  <footer>Generated by RepoGuard · secrets · dependencies via OSV.dev · GitHub Actions workflows</footer>
</div>
<script>
(function () {{
  var cat = "all", sev = null;
  function apply() {{
    document.querySelectorAll(".finding").forEach(function (el) {{
      var ok = (cat === "all" || el.dataset.cat === cat) && (!sev || el.dataset.sev === sev);
      el.classList.toggle("hidden", !ok);
    }});
  }}
  document.querySelectorAll("[data-filter-cat]").forEach(function (b) {{
    b.addEventListener("click", function () {{
      cat = b.dataset.filterCat;
      document.querySelectorAll("[data-filter-cat]").forEach(function (x) {{ x.classList.toggle("active", x === b); }});
      apply();
    }});
  }});
  document.querySelectorAll("[data-filter-sev]").forEach(function (b) {{
    b.addEventListener("click", function () {{
      sev = sev === b.dataset.filterSev ? null : b.dataset.filterSev;
      document.querySelectorAll("[data-filter-sev]").forEach(function (x) {{ x.classList.toggle("active", x.dataset.filterSev === sev); }});
      apply();
    }});
  }});
}})();
</script>
</body>
</html>
"""
