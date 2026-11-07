"""Post or update one RepoGuard comment on the current pull request.

Usage (inside GitHub Actions): python -m repoguard.ghcomment report.md
Needs GITHUB_TOKEN with `pull-requests: write`.
"""
from __future__ import annotations

import json
import os
import sys

from .report import MARKER


def pr_number(event_path: str | None) -> int | None:
    if not event_path or not os.path.exists(event_path):
        return None
    with open(event_path, encoding="utf-8") as fh:
        event = json.load(fh)
    pr = event.get("pull_request") or {}
    return pr.get("number") or (event.get("number") if "pull_request" in event else None)


def upsert(session, api: str, repo: str, number: int, body: str) -> str:
    url = f"{api}/repos/{repo}/issues/{number}/comments"
    page = 1
    while True:
        r = session.get(url, params={"per_page": 100, "page": page}, timeout=30)
        r.raise_for_status()
        comments = r.json()
        for c in comments:
            if MARKER in (c.get("body") or ""):
                session.patch(f"{api}/repos/{repo}/issues/comments/{c['id']}", json={"body": body},
                              timeout=30).raise_for_status()
                return "updated"
        if len(comments) < 100:
            break
        page += 1
    session.post(url, json={"body": body}, timeout=30).raise_for_status()
    return "created"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m repoguard.ghcomment REPORT.md", file=sys.stderr)
        return 2
    number = pr_number(os.environ.get("GITHUB_EVENT_PATH"))
    if not number:
        print("Not a pull request event; skipping the comment.")
        return 0
    token, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        print("GITHUB_TOKEN or GITHUB_REPOSITORY missing; skipping the comment.")
        return 0
    with open(argv[0], encoding="utf-8") as fh:
        body = fh.read()
    import requests
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                      "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "repoguard"})
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    try:
        print(f"PR comment {upsert(s, api, repo, number, body)}.")
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "?"
        print(f"::warning::RepoGuard couldn't comment on the PR (HTTP {code}). Give the workflow "
              "`permissions: pull-requests: write`; PRs from forks get a read-only token.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
