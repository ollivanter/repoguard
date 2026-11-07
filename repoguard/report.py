"""Terminal, JSON, Markdown and HTML output."""
from __future__ import annotations

import html
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

from .models import Finding, ScanResult, Severity

ICONS = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡", Severity.LOW: "🔵", Severity.INFO: "⚪"}
CATEGORY_NAMES = {"secrets": "Secrets", "dependencies": "Dependencies", "workflows": "Workflows", "containers": "Containers"}
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
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x9b]")


def _clean(text) -> str:
    """Strip control characters: a file named with ANSI escapes must not rewrite the user's terminal."""
    return CONTROL.sub("?", str(text))


def terminal(result: ScanResult, stream=None) -> str:
    stream = stream or sys.stdout
    color = stream.isatty() and not os.environ.get("NO_COLOR")
    codes = {Severity.CRITICAL: "1;31", Severity.HIGH: "31", Severity.MEDIUM: "33", Severity.LOW: "36", Severity.INFO: "37"}

    def c(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    grade_code = {"A": "1;32", "B": "32", "C": "33", "D": "33", "F": "1;31"}[result.grade]
    out = [c("RepoGuard", "1") + f"  {_clean(result.repo or result.target)}" + (f" @ {_clean(result.commit[:7])}" if result.commit else ""),
           f"Score {c(f'{result.score}/100', grade_code)}  Grade {c(result.grade, grade_code)}  "
           + "  ".join(f"{k}: {v}" for k, v in result.counts().items() if k != "info"), ""]
    for f in result.sorted_findings():
        out.append(f"{c(f'[{f.severity.label.upper():8}]', codes[f.severity])} {_clean(f.title)}")
        if f.location:
            out.append(f"           {_clean(f.location)}" + (f"  (commit {_clean(f.commit[:7])})" if f.commit else ""))
    if not result.findings:
        out.append(c("No findings. Nice.", "32"))
    for n in result.notes:
        out.append(c(f"note: {_clean(n)}", "2"))
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
            loc = _md(f.location).replace("[", "\\[").replace("]", "\\]") + (f" (commit {f.commit[:7]})" if f.commit else "")
            block = [f"#### {_md(f.title)}",
                     f"📍 {f'[{loc}]({url})' if url else loc} · `{f.rule}`", "", _md(f.description), ""]
            if f.patch and (f.patch.get("before") or f.patch.get("after")):
                diff = [f"- {l}" for l in f.patch.get("before", [])] + [f"+ {l}" for l in f.patch.get("after", [])]
                body_text = html.escape("\n".join(diff))
                block += [f"<details><summary>Suggested change</summary>\n\n<pre>{body_text}</pre>\n</details>", ""]
            elif f.evidence:
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
STATIC = Path(__file__).parent / "web" / "static"


def embed_json(data: dict) -> str:
    """JSON that can't break out of a <script> element, whatever the repository contains."""
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return (text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def html_report(result: ScanResult) -> str:
    """Self-contained, offline HTML report: the web UI's stylesheet and renderer with the data inlined."""
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    title = html.escape(result.repo or result.target)
    csp = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; "
           "base-uri 'none'; form-action 'none'")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="color-scheme" content="dark">
<title>RepoGuard report · {title}</title>
<style>{css}</style>
</head>
<body class="report-only">
<a class="skip-link" href="#main">Skip to content</a>
<div class="texture" aria-hidden="true"></div>
<header class="topbar"><span class="brand"><span class="brand-mark" aria-hidden="true"></span>repoguard</span></header>
<main id="main"><section class="report" id="report" aria-labelledby="report-title" hidden></section></main>
<footer class="footer"><span>Generated by repoguard · {html.escape(result.scanned_at)}</span><span>Offline report: no network requests</span></footer>
<script type="application/json" id="repoguard-data">{embed_json(result.to_dict())}</script>
<script>{js}</script>
</body>
</html>
"""
