"""Command line: repoguard scan [TARGET] ..."""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from . import __version__, report
from .models import Severity
from .scanner import TargetError, resolve_target, scan_path

FAIL_CHOICES = ["never", "low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="repoguard",
                                description="Security audit for a repo: leaked secrets (including git history), "
                                            "vulnerable dependencies and risky GitHub Actions workflows.")
    p.add_argument("--version", action="version", version=f"repoguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan a folder or GitHub repo")
    s.add_argument("target", nargs="?", default=".", help="folder, owner/repo or GitHub URL (default: current folder)")
    s.add_argument("--format", choices=["terminal", "json", "markdown", "html"], default="terminal",
                   help="what to print to stdout (default: terminal)")
    s.add_argument("--json", metavar="FILE", help="also write a JSON report")
    s.add_argument("--markdown", metavar="FILE", help="also write a Markdown report (for PR comments)")
    s.add_argument("--html", metavar="FILE", help="also write the HTML dashboard")
    s.add_argument("--fail-on", choices=FAIL_CHOICES, default="never",
                   help="exit with code 1 if a finding is at least this severe (default: never)")
    s.add_argument("--only", choices=["secrets", "dependencies", "workflows"], action="append",
                   help="run only these scanners (repeatable)")
    s.add_argument("--no-history", action="store_true", help="don't scan git history for secrets")
    s.add_argument("--max-commits", type=int, default=1000, help="history depth to scan (default: 1000)")
    s.add_argument("--offline", action="store_true", help="skip the OSV.dev vulnerability lookup")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root, slug, tmp = resolve_target(args.target)
    except TargetError as exc:
        print(f"repoguard: {exc}", file=sys.stderr)
        return 2
    try:
        result = scan_path(root, label=slug or root.name, slug=slug, history=not args.no_history,
                           max_commits=max(1, args.max_commits), offline=args.offline,
                           categories=tuple(args.only) if args.only else ("secrets", "dependencies", "workflows"))
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    writers = {"json": report.to_json, "markdown": report.markdown, "html": report.html_report}
    for fmt, fn in writers.items():
        dest = getattr(args, fmt)
        if dest:
            Path(dest).write_text(fn(result), encoding="utf-8")
    sys.stdout.write(report.terminal(result) if args.format == "terminal" else writers[args.format](result))

    if args.fail_on != "never":
        worst = result.worst()
        if worst is not None and worst >= Severity.parse(args.fail_on):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
