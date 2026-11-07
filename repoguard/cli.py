"""Command line: repoguard scan [TARGET] … and repoguard serve."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, report
from .github import GitHubError, InvalidRepoRef, check_token, parse_repo_ref
from .models import CATEGORIES, Severity
from .pipeline import STEP_IDS, Cancelled, Context, Options, Progress, scan_github
from .scanner import scan_path

FAIL_CHOICES = ["never", "low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="repoguard",
                                description="Security audit for a repo: leaked secrets (including git history), "
                                            "vulnerable dependencies, risky GitHub Actions workflows and Dockerfiles.")
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
    s.add_argument("--only", choices=list(CATEGORIES), action="append", help="run only these scanners (repeatable)")
    s.add_argument("--no-history", action="store_true", help="don't scan git history for secrets")
    s.add_argument("--max-commits", type=int, default=1000, help="history depth to scan (default: 1000)")
    s.add_argument("--offline", action="store_true", help="skip the OSV.dev vulnerability lookup")
    s.add_argument("--resolve-pins", action="store_true",
                   help="look up the commit SHA behind each unpinned action (uses git ls-remote)")
    s.add_argument("--token", help="GitHub token for private repos (default: $GITHUB_TOKEN)")
    s.add_argument("--quiet", action="store_true", help="no progress output on stderr")

    w = sub.add_parser("serve", help="run the web UI")
    w.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1, local only)")
    w.add_argument("--port", type=int, default=8000)
    w.add_argument("--allowed-host", action="append", default=[],
                   help="extra Host header value to accept when deployed behind a domain (repeatable)")
    return p


ICONS = {"done": "✓", "skipped": "–", "failed": "✗", "cancelled": "■"}


def stderr_progress(quiet: bool):
    tty = sys.stderr.isatty() and not os.environ.get("NO_COLOR")

    def emit(event: dict) -> None:
        if quiet:
            return
        if event["type"] == "step":
            state = event["state"]
            if state == "running":
                if tty:
                    sys.stderr.write(f"\r\033[2K  … {event['label']}")
                    sys.stderr.flush()
                return
            if state == "skipped" and event.get("detail") in ("local folder", "not selected"):
                if tty:
                    sys.stderr.write("\r\033[2K")
                return
            ms = f" {event['ms'] / 1000:.1f}s" if event.get("ms") else ""
            line = f"  {ICONS.get(state, '?')} {event['label']}" + (f"  {event['detail']}" if event.get("detail") else "") + ms
            sys.stderr.write(("\r\033[2K" if tty else "") + line + "\n")
        elif event["type"] == "log" and event.get("level") in ("warn", "error"):
            sys.stderr.write(f"  ! {event['text']}\n")
    return emit


def run_scan(args) -> int:
    progress = Progress(STEP_IDS, stderr_progress(args.quiet))
    categories = tuple(args.only) if args.only else CATEGORIES
    path = Path(args.target).expanduser()
    if path.exists():
        if not path.is_dir():
            print(f"repoguard: {args.target} is not a directory", file=sys.stderr)
            return 2
        result = scan_path(path.resolve(), label=path.resolve().name, history=not args.no_history,
                           max_commits=max(1, args.max_commits), offline=args.offline, categories=categories,
                           resolve_pins=args.resolve_pins, progress=progress)
    else:
        try:
            ref = parse_repo_ref(args.target)
            token = check_token(args.token or os.environ.get("GITHUB_TOKEN"))
        except InvalidRepoRef as exc:
            print(f"repoguard: {args.target} is neither a folder nor a GitHub repo ({exc})", file=sys.stderr)
            return 2
        except GitHubError as exc:
            print(f"repoguard: {exc.message}", file=sys.stderr)
            return 2
        opts = Options(history=not args.no_history, max_commits=max(1, args.max_commits), osv=not args.offline,
                       categories=categories, resolve_pins=args.resolve_pins, max_repo_kb=10**12, clone_timeout=1800)
        try:
            result = scan_github(ref, opts, Context(progress=progress), token=token)
        except GitHubError as exc:
            print(f"repoguard: {exc.message}" + (f"\n  {exc.hint}" if exc.hint else ""), file=sys.stderr)
            return 2
        except (Cancelled, KeyboardInterrupt):
            print("repoguard: cancelled", file=sys.stderr)
            return 130

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


def run_serve(args) -> int:
    try:
        import uvicorn

        from .web.app import create_app
    except ImportError:
        print("repoguard: the web UI needs extra packages: pip install 'repoguard[web]'", file=sys.stderr)
        return 2
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("repoguard: warning: serving beyond localhost. Anyone who can reach this port can run scans; "
              "put it behind authentication.", file=sys.stderr)
    hosts = ["127.0.0.1", "localhost", "[::1]", *args.allowed_host]
    if args.host not in ("0.0.0.0", "::"):
        hosts.append(args.host)
    app = create_app(allowed_hosts=hosts)
    print(f"RepoGuard UI on http://{'localhost' if args.host in ('127.0.0.1', '::1') else args.host}:{args.port}",
          file=sys.stderr)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", server_header=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        return run_serve(args)
    return run_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
