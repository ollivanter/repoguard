"""Run every scanner over a directory or a GitHub repository."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .files import is_git_repo
from .models import ScanResult

GITHUB_URL = re.compile(r"^(?:https?://github\.com/|git@github\.com:)?([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def github_slug(remote: str) -> str | None:
    m = GITHUB_URL.match(remote.strip())
    return f"{m.group(1)}/{m.group(2)}" if m else None


def _git(root: Path, *args: str) -> str:
    try:
        out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=60)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _pr_head_sha(event_path: str | None) -> str | None:
    try:
        with open(event_path or "", encoding="utf-8") as fh:
            event = json.load(fh)
        return ((event.get("pull_request") or {}).get("head") or {}).get("sha")
    except (OSError, ValueError, AttributeError):
        return None


class TargetError(RuntimeError):
    pass


def resolve_target(target: str) -> tuple[Path, str | None, Path | None]:
    """Return (local path, owner/repo if known, temp dir to delete afterwards)."""
    path = Path(target).expanduser()
    if path.exists():
        if not path.is_dir():
            raise TargetError(f"{target} is not a directory")
        return path.resolve(), None, None
    slug = github_slug(target)
    if not slug:
        raise TargetError(f"{target} is neither a folder nor a GitHub repo (owner/name or URL)")
    tmp = Path(tempfile.mkdtemp(prefix="repoguard-"))
    clone = subprocess.run(["git", "clone", "--quiet", "--no-tags", f"https://github.com/{slug}.git", str(tmp / "repo")],
                           capture_output=True, text=True, timeout=900)
    if clone.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise TargetError(f"couldn't clone {slug}: {clone.stderr.strip().splitlines()[-1] if clone.stderr.strip() else 'unknown error'}")
    return tmp / "repo", slug, tmp


def repo_identity(root: Path, result: ScanResult, slug: str | None = None) -> None:
    """Fill in repo/commit for links. GitHub Actions tells us exactly which repo/commit we're in."""
    git = is_git_repo(root)
    if os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REPOSITORY"):
        result.repo = os.environ["GITHUB_REPOSITORY"]
        result.commit = os.environ.get("GITHUB_SHA")
        result.server_url = os.environ.get("GITHUB_SERVER_URL", result.server_url)
        # On pull requests GITHUB_SHA is a temporary merge commit; link to the PR's head instead.
        head = _pr_head_sha(os.environ.get("GITHUB_EVENT_PATH"))
        if head:
            result.commit = head
    elif git:
        result.repo = slug or github_slug(_git(root, "remote", "get-url", "origin"))
        result.commit = _git(root, "rev-parse", "HEAD") or None
    if git and _git(root, "rev-parse", "--is-shallow-repository") == "true":
        result.notes.append("This is a shallow clone, so only part of the git history was checked for secrets. "
                            "Use `fetch-depth: 0` with actions/checkout for a full history scan.")


def scan_path(root: Path, *, label: str | None = None, slug: str | None = None, history: bool = True,
              max_commits: int = 1000, offline: bool = False, osv_client=None,
              categories: tuple[str, ...] = ("secrets", "dependencies", "workflows", "containers"),
              resolve_pins: bool = False, progress=None, pin_resolver=None) -> ScanResult:
    from .pipeline import STEP_IDS, Context, Options, Progress, scan_local
    opts = Options(history=history, max_commits=max_commits, osv=not offline, categories=categories,
                   resolve_pins=resolve_pins)
    ctx = Context(progress=progress or Progress(STEP_IDS), osv_client=osv_client, pin_resolver=pin_resolver)
    result = scan_local(root, opts, ctx, label=label, slug=slug)
    if offline and result.stats.get("packages_found"):
        result.notes.append("Dependency vulnerabilities weren't checked (offline mode).")
    if history and result.stats.get("commits_scanned", 0) >= max_commits:
        result.notes.append(f"Only the newest {max_commits} commits were checked for secrets "
                            "(raise it with --max-commits).")
    return result
