"""The scan as an explicit sequence of steps with a validated state machine.

Both the CLI and the web UI drive the same pipeline; they only differ in what they do
with progress events (print to stderr, or stream to the browser).
"""
from __future__ import annotations

import datetime as dt
import enum
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import deps, docker, pins, secrets, workflows
from .files import is_git_repo, list_files, load_ignore_patterns
from .github import GitHubClient, GitHubError, RepoRef, clone
from .models import CATEGORIES, ScanResult
from .scoring import score

STEPS: list[tuple[str, str]] = [
    ("validate", "Validating repository reference"),
    ("metadata", "Fetching repository metadata"),
    ("clone", "Cloning repository shallowly"),
    ("secrets", "Scanning files for hardcoded secrets"),
    ("history", "Replaying git history for leaked secrets"),
    ("dependencies", "Analyzing dependency tree"),
    ("osv", "Querying OSV.dev for known vulnerabilities"),
    ("workflows", "Auditing GitHub Actions workflows"),
    ("containers", "Inspecting Dockerfiles"),
    ("pins", "Resolving action tags to commit SHAs"),
    ("score", "Generating CVSS score breakdown"),
]
LABELS = dict(STEPS)


class StepState(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"
    CANCELLED = "cancelled"


TRANSITIONS = {
    StepState.PENDING: {StepState.RUNNING, StepState.SKIPPED, StepState.CANCELLED},
    StepState.RUNNING: {StepState.DONE, StepState.SKIPPED, StepState.FAILED, StepState.CANCELLED},
}


class InvalidTransition(RuntimeError):
    pass


class Cancelled(Exception):
    pass


@dataclass
class Step:
    id: str
    label: str
    state: StepState = StepState.PENDING
    detail: str = ""
    started: float | None = None
    finished: float | None = None

    def to_dict(self) -> dict:
        ms = int((self.finished - self.started) * 1000) if self.started and self.finished else None
        return {"id": self.id, "label": self.label, "state": self.state.value, "detail": self.detail, "ms": ms}


class Progress:
    """Tracks steps and emits events: {"type": "step"|"log"|"meta", ...}."""

    def __init__(self, step_ids: list[str], emit: Callable[[dict], None] | None = None):
        self.steps = {sid: Step(sid, LABELS[sid]) for sid in step_ids}
        self.emit = emit or (lambda event: None)
        self.t0 = time.monotonic()
        self.current: str | None = None

    def _move(self, sid: str, new: StepState, detail: str | None) -> None:
        step = self.steps[sid]
        if new not in TRANSITIONS.get(step.state, set()):
            raise InvalidTransition(f"{sid}: {step.state.value} -> {new.value}")
        now = time.monotonic()
        if new == StepState.RUNNING:
            step.started = now
            self.current = sid
        else:
            step.finished = now
            if step.started is None:
                step.started = now
            if self.current == sid:
                self.current = None
        step.state = new
        if detail is not None:
            step.detail = detail
        self.emit({"type": "step", "elapsed_ms": int((now - self.t0) * 1000), **step.to_dict()})

    def start(self, sid: str, detail: str = "") -> None:
        self._move(sid, StepState.RUNNING, detail)

    def done(self, sid: str, detail: str | None = None) -> None:
        self._move(sid, StepState.DONE, detail)

    def skip(self, sid: str, reason: str) -> None:
        self._move(sid, StepState.SKIPPED, reason)

    def fail(self, sid: str, detail: str) -> None:
        self._move(sid, StepState.FAILED, detail)

    def cancel_rest(self) -> None:
        for step in self.steps.values():
            if step.state in (StepState.PENDING, StepState.RUNNING):
                self._move(step.id, StepState.CANCELLED, "cancelled")

    def log(self, text: str, level: str = "info") -> None:
        self.emit({"type": "log", "level": level, "text": text,
                   "elapsed_ms": int((time.monotonic() - self.t0) * 1000)})

    def snapshot(self) -> list[dict]:
        return [s.to_dict() for s in self.steps.values()]


@dataclass
class Options:
    history: bool = True
    max_commits: int = 1000
    history_time_budget: float | None = None
    osv: bool = True
    resolve_pins: bool = False
    categories: tuple[str, ...] = CATEGORIES
    max_repo_kb: int = 512_000
    clone_timeout: float = 180


@dataclass
class Context:
    progress: Progress
    cancel: threading.Event = field(default_factory=threading.Event)
    osv_client: object | None = None
    pin_resolver: Callable | None = None

    def check(self) -> None:
        if self.cancel.is_set():
            raise Cancelled()


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def analyze(root: Path, result: ScanResult, opts: Options, ctx: Context) -> ScanResult:
    """Run the analysis steps over a local checkout and fill in `result`."""
    p, check = ctx.progress, ctx.check
    cats = set(opts.categories)
    git = is_git_repo(root)
    extra = load_ignore_patterns(root)
    files = list_files(root, extra)
    result.stats["files_scanned"] = len(files)

    # secrets: working tree
    current: dict = {}
    if "secrets" in cats:
        p.start("secrets", f"{_plural(len(files), 'file')}")
        current = secrets.scan_files(root, files, should_stop=check)
        p.done("secrets", f"{_plural(len(current), 'secret')} in {_plural(len(files), 'file')}")
    else:
        p.skip("secrets", "not selected")

    # secrets: history
    first_seen: dict = {}
    if "secrets" in cats and opts.history and git:
        p.start("history", f"up to {_plural(opts.max_commits, 'commit')}")
        old, first_seen, h = secrets.history_findings(root, current, extra, max_commits=opts.max_commits,
                                                       should_stop=check, time_budget=opts.history_time_budget)
        result.findings += old
        result.stats["commits_scanned"] = h["commits_scanned"]
        if h["truncated"]:
            result.notes.append(f"The history scan stopped after {h['commits_scanned']} commits to stay within its time budget.")
        p.done("history", f"{_plural(h['commits_scanned'], 'commit')} replayed, {_plural(len(old), 'removed secret')} found")
    else:
        p.skip("history", "not a git repository" if not git else "turned off")
    result.findings += [secrets._finding(hit, rel, first_seen=first_seen.get(fp)) for fp, (hit, rel) in current.items()]

    # dependencies
    packages: list = []
    if "dependencies" in cats:
        p.start("dependencies")
        manifests = deps.find_manifests(root, list_files(root, extra, include_lockfiles=True))
        packages, unpinned, notes = deps.collect(root, manifests)
        result.notes += notes
        result.findings += deps.unpinned_findings(unpinned)
        result.stats.update(manifests=len(manifests), packages_found=len(packages), packages_checked=0)
        if manifests:
            eco = sorted({pk.ecosystem for pk in packages})
            p.done("dependencies", f"{_plural(len(packages), 'pinned package')} in {_plural(len(manifests), 'manifest')}"
                   + (f" ({', '.join(eco)})" if eco else ""))
        else:
            p.done("dependencies", "no dependency manifests found")
        check()
    else:
        p.skip("dependencies", "not selected")

    if "dependencies" in cats and packages and opts.osv:
        p.start("osv", f"{_plural(len(packages), 'package')}")
        try:
            found = deps.vuln_findings(packages, ctx.osv_client or deps.OSVClient(), root, should_stop=check)
            result.findings += found
            result.stats["packages_checked"] = len(packages)
            n_vulns = sum(len(f.details.get("vulns", [])) for f in found)
            p.done("osv", f"{n_vulns} {'advisory' if n_vulns == 1 else 'advisories'} across "
                          f"{_plural(len(found), 'vulnerable package')}")
        except deps.OSVError as exc:
            result.notes.append(f"Dependency vulnerabilities weren't checked: {exc}.")
            p.fail("osv", str(exc))
    else:
        p.skip("osv", "turned off" if packages and not opts.osv else "no pinned packages to check")

    # workflows
    if "workflows" in cats:
        p.start("workflows")
        f, s, n = workflows.scan(root, files)
        result.findings += f
        result.stats.update(s)
        result.notes += n
        p.done("workflows", f"{_plural(s['workflows_scanned'], 'workflow')}, {_plural(len(f), 'issue')}"
               if s["workflows_scanned"] else "no workflows found")
        check()
    else:
        p.skip("workflows", "not selected")

    # containers
    if "containers" in cats:
        p.start("containers")
        f, s, n = docker.scan(root, files)
        result.findings += f
        result.stats.update(s)
        result.notes += n
        p.done("containers", f"{_plural(s['dockerfiles_scanned'], 'Dockerfile')}, {_plural(len(f), 'issue')}"
               if s["dockerfiles_scanned"] else "no Dockerfiles found")
        check()
    else:
        p.skip("containers", "not selected")

    # pins
    unpinned_actions = [f for f in result.findings if f.rule == "workflow/unpinned-action"]
    if opts.resolve_pins and unpinned_actions:
        p.start("pins", f"{_plural(len({(f.details.get('repo'), f.details.get('ref')) for f in unpinned_actions}), 'action')}")
        s = pins.apply(result.findings, resolver=ctx.pin_resolver or pins.ls_remote, should_stop=check)
        p.done("pins", f"{s['actions_resolved']} resolved" + (f", {s['actions_unresolved']} unknown" if s["actions_unresolved"] else ""))
    else:
        p.skip("pins", "no unpinned actions" if not unpinned_actions else "turned off")

    # score
    p.start("score")
    seen, unique = set(), []
    for finding in result.findings:
        if finding.fingerprint not in seen:
            seen.add(finding.fingerprint)
            unique.append(finding)
    result.findings = unique
    result.score, result.grade = score(result.findings)
    result.categories = tuple(c for c in CATEGORIES if c in cats)
    worst = max((f.severity.label for f in unique), key=lambda l: ["info", "low", "medium", "high", "critical"].index(l), default=None)
    p.done("score", f"{result.score}/100, grade {result.grade}" + (f" (worst: {worst})" if worst else ""))
    return result


def new_result(label: str) -> ScanResult:
    return ScanResult(target=label, scanned_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))


def scan_local(root: Path, opts: Options, ctx: Context, *, label: str | None = None, slug: str | None = None) -> ScanResult:
    """Scan a folder that's already on disk."""
    from .scanner import repo_identity
    p = ctx.progress
    for sid, reason in (("validate", "local folder"), ("metadata", "local folder"), ("clone", "local folder")):
        if sid in p.steps:
            p.skip(sid, reason)
    result = new_result(label or root.name)
    repo_identity(root, result, slug)
    return analyze(root, result, opts, ctx)


def scan_github(ref: RepoRef, opts: Options, ctx: Context, *, token: str | None = None,
                client: GitHubClient | None = None, cloner=clone) -> ScanResult:
    """Fetch metadata through the API, clone shallowly into a temp folder, analyze, clean up."""
    p = ctx.progress
    p.start("validate", ref.slug)
    p.done("validate", ref.slug)
    client = client or GitHubClient(token=token)
    p.start("metadata", f"GET /repos/{ref.slug}")
    try:
        info = client.repo(ref)
    except GitHubError as exc:
        p.fail("metadata", exc.message)
        raise
    finally:
        if client.rate:
            p.emit({"type": "rate", **client.rate})
    p.emit({"type": "meta", "repo": info.to_dict()})
    size_mb = info.size_kb / 1024
    size = f"{info.size_kb:,} KB" if info.size_kb < 1024 else f"{size_mb:,.1f} MB"
    p.done("metadata", f"{info.visibility}, {size}, default branch {info.default_branch}")
    ctx.check()
    if info.size_kb > opts.max_repo_kb:
        exc = GitHubError("too_large", f"{info.full_name} is {size_mb:,.0f} MB, above this server's "
                          f"{opts.max_repo_kb / 1024:,.0f} MB limit for live scans.",
                          hint="Run the CLI locally instead: repoguard scan " + info.full_name)
        p.start("clone", "checking size")
        p.fail("clone", exc.message)
        raise exc
    depth = opts.max_commits if opts.history else 1
    tmp = Path(tempfile.mkdtemp(prefix="repoguard-"))
    try:
        p.start("clone", f"depth {depth}, branch {info.default_branch}")
        try:
            cloner(ref, tmp / "repo", token=token, depth=depth, branch=info.default_branch,
                   timeout=opts.clone_timeout, should_stop=ctx.check)
        except GitHubError as exc:
            if exc.code == "clone_failed" and info.size_kb == 0:
                exc = GitHubError("empty_repo", f"{info.full_name} has no commits yet, so there's nothing to scan.",
                                  hint="Push some code first, or check you picked the right repository.")
            p.fail("clone", exc.message)
            raise exc
        p.done("clone", f"{info.full_name}@{info.default_branch}")
        result = new_result(info.full_name)
        result.repo = info.full_name
        result.meta = info.to_dict()
        from .scanner import _git
        result.commit = _git(tmp / "repo", "rev-parse", "HEAD") or None
        result = analyze(tmp / "repo", result, opts, ctx)
        if opts.history and result.stats.get("commits_scanned", 0) >= depth:
            result.notes.append(f"History was limited to the latest {depth} commits (shallow clone).")
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


STEP_IDS = [sid for sid, _ in STEPS]
