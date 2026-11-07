"""Leaked secret detection in the working tree and in git history."""
from __future__ import annotations

import hashlib
import math
import re
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .files import is_excluded, list_files, load_ignore_patterns, read_text
from .models import Finding, Severity

IGNORE_MARKER = re.compile(r"repoguard\s*:\s*ignore", re.I)
MAX_LINE = 5000
GENERIC_MAX_LINE = 1000


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    revoke: str = ""
    group: int = 0               # capture group holding the secret
    min_entropy: float = 0.0
    generic: bool = False        # low-confidence rule: stricter placeholder checks


def _r(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


RULES: list[Rule] = [
    Rule("private-key", "Private key", _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
         Severity.CRITICAL, "Generate a new key pair and remove the old public key everywhere it's trusted (servers, deploy keys, certificates)."),
    Rule("aws-access-key", "AWS access key ID", _r(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
         Severity.CRITICAL, "Deactivate and delete the key in AWS IAM → Users → Security credentials, then check CloudTrail for misuse."),
    Rule("github-token", "GitHub token", _r(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
         Severity.CRITICAL, "Revoke it at https://github.com/settings/tokens (or the app/OAuth settings that issued it)."),
    Rule("github-fine-grained-token", "GitHub fine-grained token", _r(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
         Severity.CRITICAL, "Revoke it at https://github.com/settings/personal-access-tokens."),
    Rule("anthropic-key", "Anthropic API key", _r(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}"),
         Severity.CRITICAL, "Delete the key at https://console.anthropic.com/settings/keys."),
    Rule("openai-key", "OpenAI API key", _r(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}"),
         Severity.CRITICAL, "Delete the key at https://platform.openai.com/api-keys."),
    Rule("stripe-live-key", "Stripe live secret key", _r(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b"),
         Severity.CRITICAL, "Roll the key in the Stripe Dashboard → Developers → API keys."),
    Rule("slack-token", "Slack token", _r(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
         Severity.HIGH, "Revoke it in your Slack app's settings (OAuth & Permissions)."),
    Rule("slack-webhook", "Slack webhook URL", _r(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
         Severity.HIGH, "Delete the webhook in the Slack app's Incoming Webhooks settings and create a new one."),
    Rule("google-api-key", "Google API key", _r(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
         Severity.HIGH, "Delete or regenerate it in Google Cloud Console → APIs & Services → Credentials, and add API restrictions."),
    Rule("telegram-bot-token", "Telegram bot token", _r(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
         Severity.HIGH, "Send /revoke to @BotFather in Telegram to get a new token."),
    Rule("notion-token", "Notion integration token", _r(r"\b(?:ntn_[A-Za-z0-9]{46}|secret_[A-Za-z0-9]{43})\b"),
         Severity.HIGH, "Refresh the secret at https://www.notion.so/my-integrations."),
    Rule("database-url-password", "Database URL with password",
         _r(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^\s:/@'\"]+:([^\s@/'\"]{4,})@"),
         Severity.HIGH, "Change the database user's password and update every service that uses it.", group=1, generic=True),
    Rule("jwt", "JSON Web Token", _r(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
         Severity.MEDIUM, "If this token grants access to a real system, revoke the session and rotate the signing key."),
    Rule("generic-secret", "Hard-coded secret",
         _r(r"""(?i)\b[a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret)[a-z0-9_.-]*["']?\s*(?:=|:|:=|=>)\s*["']([^"'\s]{8,200})["']"""),
         Severity.MEDIUM, "Rotate the credential with whoever issued it.", group=1, min_entropy=3.0, generic=True),
    Rule("env-secret", "Secret in environment-style assignment",
         _r(r"""^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\s*=\s*([^\s#'"$(){}]{8,200})\s*$"""),
         Severity.MEDIUM, "Rotate the credential with whoever issued it.", group=1, min_entropy=3.0, generic=True),
]

PLACEHOLDER_WORDS = ("example", "xxxx", "your", "dummy", "placeholder", "changeme", "change_me",
                     "redacted", "sample", "fake", "****", "...", "…", "<", ">", "{{", "${", "%s", "todo")
GENERIC_EXTRA_WORDS = ("test", "secret", "password", "token", "foobar", "localhost", "123456",
                       "abcdef", "qwerty", "process.env", "os.environ", "getenv", "config.", "settings.")


def entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def is_placeholder(secret: str, generic: bool) -> bool:
    low = secret.lower()
    if any(w in low for w in PLACEHOLDER_WORDS):
        return True
    if len(set(secret)) <= 3:
        return True
    if generic:
        if any(w in low for w in GENERIC_EXTRA_WORDS):
            return True
        # identifiers and paths, not secrets: "access_token", "API_KEY_NAME", "camelCaseName", "/etc/key"
        if re.fullmatch(r"[a-z_.\-]+|[A-Z_.\-]+|[a-z]+(?:[A-Z][a-z]+)+|[A-Z][a-z]+(?:[A-Z][a-z]+)*", secret):
            return True
        if "/" in secret or "\\" in secret or secret.startswith(("$", "%", "@")):
            return True
    return False


def mask(secret: str) -> str:
    keep = 4 if len(secret) >= 20 else 2
    return secret[:keep] + "*" * max(4, min(len(secret) - keep, 12))


def fingerprint(rule: Rule, secret: str) -> str:
    return hashlib.sha256(f"{rule.id}:{secret}".encode()).hexdigest()[:16]


@dataclass
class Hit:
    rule: Rule
    secret: str
    line_no: int
    line: str

    @property
    def fp(self) -> str:
        return fingerprint(self.rule, self.secret)

    def evidence(self) -> str:
        text = self.line.strip()
        text = text.replace(self.secret, mask(self.secret))
        return text if len(text) <= 160 else text[:157] + "…"


def scan_line(line: str, line_no: int) -> list[Hit]:
    if IGNORE_MARKER.search(line):
        return []
    line = line[:MAX_LINE]
    hits: list[Hit] = []
    taken: list[tuple[int, int]] = []
    long_line = len(line) > GENERIC_MAX_LINE
    for rule in RULES:
        if rule.generic and long_line:      # keeps the broad patterns linear-time on minified blobs
            continue
        for m in rule.pattern.finditer(line):
            start, end = m.span()
            if any(start < e and end > s for s, e in taken):
                continue
            secret = m.group(rule.group)
            if is_placeholder(secret, rule.generic):
                continue
            if rule.min_entropy and entropy(secret) < rule.min_entropy:
                continue
            taken.append((start, end))
            hits.append(Hit(rule, secret, line_no, line))
    return hits


def scan_text(text: str) -> list[Hit]:
    hits: list[Hit] = []
    for i, line in enumerate(text.splitlines(), 1):
        hits.extend(scan_line(line, i))
    return hits


HISTORY_NOTE = ("Deleting it in a later commit isn't enough: it stays in git history, and anyone who "
                "cloned or forked the repo still has it. Revoke it first. Rewriting history "
                "(git filter-repo, BFG) is optional cleanup, not a fix.")

DEFAULT_ENV_NAMES = {
    "aws-access-key": "AWS_ACCESS_KEY_ID", "github-token": "GITHUB_TOKEN", "github-fine-grained-token": "GITHUB_TOKEN",
    "anthropic-key": "ANTHROPIC_API_KEY", "openai-key": "OPENAI_API_KEY", "stripe-live-key": "STRIPE_SECRET_KEY",
    "slack-token": "SLACK_TOKEN", "slack-webhook": "SLACK_WEBHOOK_URL", "google-api-key": "GOOGLE_API_KEY",
    "telegram-bot-token": "TELEGRAM_BOT_TOKEN", "notion-token": "NOTION_TOKEN", "database-url-password": "DATABASE_URL",
}
KEY_ON_LINE = re.compile(r"""^\s*(?:export\s+|const\s+|let\s+|var\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*(?::=|=>|=|:)""")


def env_name(hit: "Hit") -> str:
    m = KEY_ON_LINE.match(hit.line)
    if m and hit.rule.id != "database-url-password":
        return re.sub(r"[^A-Za-z0-9]+", "_", m.group(1)).strip("_").upper() or "SECRET"
    return DEFAULT_ENV_NAMES.get(hit.rule.id, "SECRET")


def secret_patch(hit: "Hit", file: str) -> dict | None:
    """Suggested replacement for the line, built only from the masked text."""
    if hit.rule.id in ("private-key", "jwt"):
        return None
    masked_value = mask(hit.secret)
    line = hit.line.rstrip("\n").replace(hit.secret, masked_value)
    name = env_name(hit)
    lower = file.lower()
    ext = Path(lower).suffix
    indent = line[: len(line) - len(line.lstrip())]
    quoted = re.search(r"""(["'])[^"'\n]*?""" + re.escape(masked_value) + r"""[^"'\n]*?\1""", line)
    if hit.rule.id == "database-url-password":
        if not quoted and ext not in (".env", ".sh", ".bash", ".zsh", ""):
            return None
        target = quoted.group(0) if quoted else line.split("=", 1)[-1].strip()
    else:
        target = quoted.group(0) if quoted else masked_value
    if ext == ".py":
        after = line.replace(target, f'os.environ["{name}"]', 1)
    elif ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        after = line.replace(target, f"process.env.{name}", 1)
    elif ext in (".rb",):
        after = line.replace(target, f'ENV.fetch("{name}")', 1)
    elif ext in (".go",):
        after = line.replace(target, f'os.Getenv("{name}")', 1)
    elif lower.startswith(".github/workflows/") and ext in (".yml", ".yaml"):
        after = line.replace(target, "${{ secrets." + name + " }}", 1)
    elif ext in (".sh", ".bash", ".zsh") or lower.rsplit("/", 1)[-1] in ("dockerfile", "containerfile"):
        after = line.replace(target, '"${' + name + ':?' + name + ' is not set}"', 1)
    elif ext == ".env" or lower.rsplit("/", 1)[-1].startswith(".env"):
        after = f"{indent}# {name} comes from the environment or your secret manager; don't commit .env files"
    else:
        return None
    if after == line:
        return None
    return {"start": hit.line_no, "before": [line], "after": [after]}


def _finding(hit: Hit, file: str, *, commit: str | None = None, date: str | None = None,
             commits: int = 1, first_seen: tuple[str, str] | None = None) -> Finding:
    rule = hit.rule
    if commit:
        sev = rule.severity.downgraded() if rule.severity > Severity.MEDIUM else rule.severity
        title = f"{rule.name} in git history"
        desc = (f"This {rule.name} was committed in {commit[:7]}"
                + (f" ({date})" if date else "")
                + (f" and appears in {commits} commits" if commits > 1 else "")
                + f". It's no longer in the current files. {HISTORY_NOTE}")
    else:
        sev = rule.severity
        title = f"{rule.name} committed to the repo"
        desc = f"This {rule.name} is in the current code."
        if first_seen:
            desc += f" It was first committed in {first_seen[0][:7]} ({first_seen[1]}), so it's also in git history."
    fix = (f"{rule.revoke} " if rule.revoke else "") + (
        "Then load it from an environment variable or a secret store (e.g. GitHub Actions secrets) "
        "instead of the code. If it's a false positive, add `# repoguard:ignore` to the line "
        "or the path to `.repoguardignore`.")
    details = {"rule": rule.id, "secret_type": rule.name, "masked": mask(hit.secret)}
    if commit:
        details.update(commit=commit, date=date, commits=commits)
    elif first_seen:
        details.update(first_commit=first_seen[0], first_date=first_seen[1])
    return Finding(rule=f"secret/{rule.id}", title=title, severity=sev, category="secrets",
                   file=file, line=hit.line_no, description=desc, fix=fix.strip(),
                   evidence=hit.evidence(), commit=commit, details=details,
                   patch=None if commit else secret_patch(hit, file),
                   fingerprint=hit.fp + ("-h" if commit else ""))


class Stop(Exception):
    """Raised by a should_stop callback to abort a long scan."""


def scan_history(root: Path, extra_ignores: list[str], max_commits: int = 1000,
                 should_stop=None, deadline: float | None = None, state: dict | None = None):
    """Yield (hit, file, commit, date) for secrets in lines added anywhere in history, newest first.
    Stops early (setting state["truncated"]) when the deadline passes."""
    cmd = ["git", "-C", str(root), "log", "--all", "-p", "--no-color", "--no-ext-diff", "--no-renames",
           "--no-textconv", "--unified=0", "--format=@@@REPOGUARD %H %ad", "--date=short", f"-n{max_commits}"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    commit = date = file = None
    new_line = 0
    count = 0
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if line.startswith("@@@REPOGUARD "):
                _, commit, date = (line.split(" ") + ["", ""])[:3]
                file = None
                count += 1
                if should_stop:
                    should_stop()
                if deadline is not None and time.monotonic() > deadline:
                    if state is not None:
                        state["truncated"] = True
                    break
            elif line.startswith("diff --git "):
                file = None
            elif line.startswith("+++ "):
                path = line[4:]
                file = path[2:] if path.startswith("b/") else None
                if file and is_excluded(file, extra_ignores):
                    file = None
            elif line.startswith("@@ "):
                m = re.match(r"@@ -\S+ \+(\d+)", line)
                new_line = int(m.group(1)) if m else 0
            elif line.startswith("+") and file and commit:
                for hit in scan_line(line[1:], new_line):
                    yield hit, file, commit, date
                new_line += 1
    finally:
        if state is not None:
            state["commits"] = count
        proc.kill() if proc.poll() is None else None
        proc.stdout.close()
        proc.wait()


def scan_files(root: Path, files: list[str], should_stop=None) -> dict[str, tuple[Hit, str]]:
    current: dict[str, tuple[Hit, str]] = {}
    for i, rel in enumerate(files):
        if should_stop and i % 200 == 0:
            should_stop()
        text = read_text(root / rel, root)
        if text is None:
            continue
        for hit in scan_text(text):
            current.setdefault(hit.fp, (hit, rel))
    return current


def history_findings(root: Path, current: dict[str, tuple[Hit, str]], extra: list[str], *,
                     max_commits: int = 1000, should_stop=None, time_budget: float | None = None
                     ) -> tuple[list[Finding], dict[str, tuple[str, str]], dict]:
    first_seen: dict[str, tuple[str, str]] = {}
    old: dict[str, dict] = {}
    state: dict = {}
    deadline = time.monotonic() + time_budget if time_budget else None
    for hit, file, commit, date in scan_history(root, extra, max_commits, should_stop, deadline, state):
        fp = hit.fp
        if fp in current:
            first_seen[fp] = (commit, date)          # keeps overwriting → earliest
            continue
        entry = old.setdefault(fp, {"commits": set()})
        entry.update(hit=hit, file=file, commit=commit, date=date)   # earliest wins
        entry["commits"].add(commit)
    findings = [_finding(e["hit"], e["file"], commit=e["commit"], date=e["date"], commits=len(e["commits"]))
                for e in old.values()]
    return findings, first_seen, {"commits_scanned": state.get("commits", 0), "truncated": state.get("truncated", False)}


def scan(root: Path, *, history: bool = True, max_commits: int = 1000,
         extra_ignores: list[str] | None = None, is_git: bool = False) -> tuple[list[Finding], dict]:
    """Working tree + history in one call (used by tests and simple callers)."""
    extra = list(extra_ignores or []) + load_ignore_patterns(root)
    files = list_files(root, extra)
    current = scan_files(root, files)
    stats = {"files_scanned": len(files)}
    first_seen: dict = {}
    old_findings: list[Finding] = []
    if history and is_git:
        old_findings, first_seen, hstats = history_findings(root, current, extra, max_commits=max_commits)
        stats["commits_scanned"] = hstats["commits_scanned"]
    findings = [_finding(hit, rel, first_seen=first_seen.get(fp)) for fp, (hit, rel) in current.items()]
    return findings + old_findings, stats
