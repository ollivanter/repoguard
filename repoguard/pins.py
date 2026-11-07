"""Resolve `owner/repo@tag` action references to immutable commit SHAs (git ls-remote, no API quota)."""
from __future__ import annotations

import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .models import Finding

REPO = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def git_env() -> dict:
    env = dict(os.environ)
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_ASKPASS="")
    return env


def ls_remote(repo: str, ref: str, timeout: int = 20, runner=subprocess.run) -> str | None:
    """Commit SHA for a tag or branch, peeling annotated tags. None if it can't be resolved."""
    if not REPO.match(repo) or not REF.match(ref) or ".." in ref:
        return None
    refs = [f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}"]
    try:
        out = runner(["git", "ls-remote", "--", f"https://github.com/{repo}.git", *refs],
                     capture_output=True, text=True, timeout=timeout, env=git_env())
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    found = {}
    for line in out.stdout.splitlines():
        sha, _, name = line.partition("\t")
        if SHA.match(sha):
            found[name] = sha
    return found.get(f"refs/tags/{ref}^{{}}") or found.get(f"refs/tags/{ref}") or found.get(f"refs/heads/{ref}")


def pin_line(line_text: str, ref: str, sha: str) -> str:
    code, hash_, comment = line_text.partition(" #")
    code = re.sub(r"@" + re.escape(ref) + r"(\s*)$", "@" + sha + r"\1", code.rstrip()) if ref else code.rstrip() + "@" + sha
    return f"{code} # {ref or 'pinned'}" + (f" ({comment.strip()})" if comment.strip() else "")


def apply(findings: list[Finding], resolver=ls_remote, workers: int = 6, should_stop=None) -> dict:
    """Fill in exact SHAs and a ready-to-paste patch for unpinned-action findings."""
    wanted = {(f.details.get("repo"), f.details.get("ref")) for f in findings
              if f.rule == "workflow/unpinned-action" and f.details.get("repo") and f.details.get("ref")}
    if should_stop:
        should_stop()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        resolved = dict(zip(wanted, pool.map(lambda k: resolver(*k), wanted)))
    hit = 0
    for f in findings:
        if f.rule != "workflow/unpinned-action":
            continue
        sha = resolved.get((f.details.get("repo"), f.details.get("ref")))
        if not sha:
            continue
        hit += 1
        f.details["resolved_sha"] = sha
        line = f.details.get("line_text", "")
        f.patch = {"start": f.line, "before": [line], "after": [pin_line(line, f.details["ref"], sha)]}
        f.fix = (f"Pin it to `{sha}` (what `{f.details['ref']}` points to right now) and keep the version as a "
                 "comment. Dependabot (package-ecosystem: github-actions) keeps pinned SHAs up to date.")
    return {"actions_resolved": hit, "actions_unresolved": len([k for k, v in resolved.items() if not v])}
