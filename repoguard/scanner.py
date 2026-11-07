"""Run every scanner over a directory or a GitHub repository."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import deps, secrets, workflows
from .files import is_git_repo, list_files
from .models import ScanResult
from .scoring import score

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


def scan_path(root: Path, *, label: str | None = None, slug: str | None = None, history: bool = True,
              max_commits: int = 1000, offline: bool = False, osv_client=None,
              categories: tuple[str, ...] = ("secrets", "dependencies", "workflows")) -> ScanResult:
    git = is_git_repo(root)
    result = ScanResult(target=label or str(root),
                        scanned_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    # GitHub Actions tells us exactly which repo/commit we're in.
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
    if git and _git(root, "rev-parse", "--is-shallow-repository") == "true" and history and "secrets" in categories:
        result.notes.append("This is a shallow clone, so only part of the git history was checked for secrets. "
                            "Use `fetch-depth: 0` with actions/checkout for a full history scan.")

    files = list_files(root)
    if "secrets" in categories:
        f, s = secrets.scan(root, history=history, max_commits=max_commits, is_git=git)
        result.findings += f
        result.stats.update(s)
        if history and git and s.get("commits_scanned", 0) >= max_commits:
            result.notes.append(f"Only the newest {max_commits} commits were checked for secrets "
                                "(raise it with --max-commits).")
    else:
        result.stats["files_scanned"] = len(files)
    if "dependencies" in categories:
        f, s, n = deps.scan(root, files, offline=offline, client=osv_client)
        result.findings += f
        result.stats.update(s)
        result.notes += n
    if "workflows" in categories:
        f, s, n = workflows.scan(root, files)
        result.findings += f
        result.stats.update(s)
        result.notes += n

    seen, unique = set(), []
    for finding in result.findings:
        if finding.fingerprint not in seen:
            seen.add(finding.fingerprint)
            unique.append(finding)
    result.findings = unique
    result.score, result.grade = score(result.findings)
    return result
