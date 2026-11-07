"""GitHub access: repository references, the REST API (with rate-limit handling) and safe cloning."""
from __future__ import annotations

import base64
import datetime as dt
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

API = "https://api.github.com"
OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}"
NAME = r"[A-Za-z0-9._-]{1,100}"
FORMS = [
    re.compile(rf"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>{OWNER})/(?P<name>{NAME}?)(?:\.git)?(?:/.*)?$", re.I),
    re.compile(rf"^git@github\.com:(?P<owner>{OWNER})/(?P<name>{NAME}?)(?:\.git)?/?$", re.I),
    re.compile(rf"^(?P<owner>{OWNER})/(?P<name>{NAME}?)(?:\.git)?/?$"),
]
OTHER_HOSTS = re.compile(r"^(?:https?://)?(?:www\.)?(gitlab\.com|bitbucket\.org|codeberg\.org|dev\.azure\.com|[\w.-]+\.\w{2,})/", re.I)
TOKEN_SHAPE = re.compile(r"^(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|[0-9a-f]{40})$")


class InvalidRepoRef(ValueError):
    pass


@dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"


def parse_repo_ref(text: str) -> RepoRef:
    """Accepts owner/name, https://github.com/owner/name[/tree/...], or git@github.com:owner/name.git."""
    value = (text or "").strip()
    if not value:
        raise InvalidRepoRef("Enter a repository, like owner/name or a github.com link.")
    if len(value) > 300 or any(c.isspace() for c in value):
        raise InvalidRepoRef("That doesn't look like a GitHub repository link.")
    value = value.split("?", 1)[0].split("#", 1)[0]
    for form in FORMS:
        m = form.match(value)
        if m:
            name = m.group("name")
            if name.lower().endswith(".git"):
                name = name[:-4]
            if not name or name in (".", "..") or name.startswith("-"):
                break
            return RepoRef(m.group("owner"), name)
    other = OTHER_HOSTS.match(value)
    if other and "github.com" not in other.group(1).lower():
        raise InvalidRepoRef(f"Only github.com repositories are supported, not {other.group(1)}.")
    raise InvalidRepoRef("That doesn't look like a GitHub repository. Use owner/name or a github.com link.")


def check_token(token: str | None) -> str | None:
    if token is None:
        return None
    token = token.strip()
    if not token:
        return None
    if not TOKEN_SHAPE.match(token):
        raise GitHubError("bad_token_format", "That doesn't look like a GitHub token. Personal access tokens start "
                          "with `github_pat_` (fine-grained) or `ghp_` (classic).", status=400)
    return token


class GitHubError(Exception):
    """A failure the user can act on. `message` is safe to show; it never contains the token."""

    def __init__(self, code: str, message: str, *, status: int | None = None, hint: str | None = None,
                 retry_at: float | None = None):
        super().__init__(message)
        self.code, self.message, self.status, self.hint, self.retry_at = code, message, status, hint, retry_at

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "hint": self.hint, "status": self.status,
                "retry_at": int(self.retry_at) if self.retry_at else None}


@dataclass
class RepoInfo:
    owner: str
    name: str
    full_name: str
    private: bool
    visibility: str
    default_branch: str
    size_kb: int
    archived: bool
    fork: bool
    html_url: str
    description: str | None
    pushed_at: str | None
    language: str | None
    stars: int

    def to_dict(self) -> dict:
        return asdict(self)


def _clock(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch).astimezone().strftime("%H:%M")


class GitHubClient:
    def __init__(self, token: str | None = None, session=None, api: str = API,
                 timeout: tuple[float, float] = (5, 20), max_retries: int = 2, sleep=time.sleep):
        if session is None:
            import requests
            session = requests.Session()
        self.http, self.api, self.timeout = session, api.rstrip("/"), timeout
        self.token, self.max_retries, self.sleep = token, max_retries, sleep
        self.rate: dict = {}

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "repoguard"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _remember_rate(self, headers) -> None:
        try:
            if "x-ratelimit-limit" in headers:
                self.rate = {"limit": int(headers["x-ratelimit-limit"]),
                             "remaining": int(headers.get("x-ratelimit-remaining", 0)),
                             "reset": int(headers.get("x-ratelimit-reset", 0)),
                             "authenticated": bool(self.token)}
        except (TypeError, ValueError):
            pass

    def _message(self, resp) -> str:
        try:
            msg = str((resp.json() or {}).get("message", ""))
        except ValueError:
            msg = ""
        msg = re.sub(r"\s+", " ", msg)[:200]
        return msg.replace(self.token, "[token]") if self.token else msg

    def get(self, path: str) -> dict:
        import requests
        url = f"{self.api}/{path.lstrip('/')}"
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.http.get(url, headers=self._headers(), timeout=self.timeout)
            except requests.Timeout:
                if attempt < self.max_retries:
                    self.sleep(1 + attempt)
                    continue
                raise GitHubError("timeout", "GitHub didn't answer in time.", hint="Try again in a minute.") from None
            except requests.RequestException:
                if attempt < self.max_retries:
                    self.sleep(1 + attempt)
                    continue
                raise GitHubError("network", "Couldn't reach GitHub.", hint="Check your internet connection.") from None
            headers = {k.lower(): v for k, v in resp.headers.items()}
            self._remember_rate(headers)
            status = resp.status_code
            if status == 200:
                return resp.json()
            if status in (403, 429):
                if headers.get("x-ratelimit-remaining") == "0":
                    reset = float(headers.get("x-ratelimit-reset", time.time() + 3600))
                    if self.token:
                        raise GitHubError("rate_limited", f"Your token has used up its GitHub API quota. It resets at {_clock(reset)}.",
                                          status=status, retry_at=reset)
                    raise GitHubError("rate_limited", f"GitHub's limit of 60 requests an hour without a token is used up. "
                                      f"It resets at {_clock(reset)}.", status=status, retry_at=reset,
                                      hint="Add a personal access token to get 5,000 requests an hour.")
                retry_after = headers.get("retry-after")
                if retry_after is not None or "secondary rate limit" in self._message(resp).lower():
                    wait = float(retry_after or 60)
                    if wait <= 10 and attempt < self.max_retries:
                        self.sleep(wait)
                        continue
                    raise GitHubError("rate_limited", "GitHub asked us to slow down (secondary rate limit).",
                                      status=status, retry_at=time.time() + wait, hint="Wait a minute and try again.")
                if headers.get("x-github-sso"):
                    raise GitHubError("sso_required", "This organization requires single sign-on for your token.",
                                      status=status, hint="Open github.com/settings/tokens, click Configure SSO next to "
                                      "the token and authorize the organization.")
                raise GitHubError("forbidden", "GitHub refused access" + (f": {self._message(resp)}" if self._message(resp) else "."),
                                  status=status, hint="Check that the token has read access to this repository's contents.")
            if status == 401:
                raise GitHubError("bad_token", "GitHub rejected the token: it's wrong, expired or revoked.", status=401,
                                  hint="Create a new token, or clear the field to scan public repositories.")
            if status == 404:
                if self.token:
                    raise GitHubError("not_found", "Repository not found, or your token can't see it.", status=404,
                                      hint="Check the spelling. For a fine-grained token, the repository must be selected "
                                      "under Repository access with Contents: read-only.")
                raise GitHubError("not_found", "Repository not found. If it's private, GitHub hides it from anonymous requests.",
                                  status=404, hint="Check the spelling, or add a token that can read it.")
            if status == 451:
                raise GitHubError("unavailable", "GitHub has blocked access to this repository for legal reasons.", status=451)
            if status >= 500 and attempt < self.max_retries:
                self.sleep(2 ** attempt)
                continue
            if status >= 500:
                raise GitHubError("github_down", f"GitHub returned an error ({status}).", status=status,
                                  hint="Check githubstatus.com and try again shortly.")
            raise GitHubError("unexpected", f"Unexpected response from GitHub ({status}).", status=status)
        raise GitHubError("unexpected", "GitHub request failed.")

    def repo(self, ref: RepoRef) -> RepoInfo:
        d = self.get(f"repos/{ref.owner}/{ref.name}")
        return RepoInfo(owner=d["owner"]["login"], name=d["name"], full_name=d["full_name"],
                        private=bool(d.get("private")), visibility=d.get("visibility") or ("private" if d.get("private") else "public"),
                        default_branch=d.get("default_branch") or "main", size_kb=int(d.get("size") or 0),
                        archived=bool(d.get("archived")), fork=bool(d.get("fork")), html_url=d.get("html_url", ""),
                        description=d.get("description"), pushed_at=d.get("pushed_at"), language=d.get("language"),
                        stars=int(d.get("stargazers_count") or 0))


# -------------------------------------------------------------------- cloning
def scrub(text: str, token: str | None) -> str:
    if token:
        text = text.replace(token, "[token]")
        text = text.replace(base64.b64encode(f"x-access-token:{token}".encode()).decode(), "[token]")
    return re.sub(r"https://[^@\s]+@", "https://", text)


def clone_env(token: str | None) -> dict:
    """Git environment that never prompts and never uses the server owner's credentials or config."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="", SSH_ASKPASS="", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_LFS_SKIP_SMUDGE="1")
    if token:
        # The token goes in an HTTP header via environment config: never in the URL, argv or .git/config.
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                   GIT_CONFIG_VALUE_0=f"AUTHORIZATION: basic {basic}")
    return env


def clone(ref: RepoRef, dest: Path, *, token: str | None = None, depth: int = 200, branch: str | None = None,
          timeout: float = 180, should_stop=None, popen=subprocess.Popen) -> None:
    cmd = ["git", "-c", "core.symlinks=false", "-c", "protocol.file.allow=never", "-c", "core.hooksPath=/dev/null",
           "-c", "submodule.recurse=false", "clone", "--quiet", "--no-tags", "--single-branch", f"--depth={max(1, depth)}"]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--", f"https://github.com/{ref.slug}.git", str(dest)]
    proc = popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=clone_env(token))
    started = time.monotonic()
    try:
        while proc.poll() is None:
            if should_stop:
                should_stop()
            if time.monotonic() - started > timeout:
                raise GitHubError("timeout", f"Cloning took longer than {int(timeout)} seconds, so it was stopped.",
                                  hint="Turn off history or lower the history depth, or use the CLI for very large repos.")
            time.sleep(0.2)
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    err = scrub((proc.stderr.read() if proc.stderr else b"").decode("utf-8", "replace"), token)
    if proc.returncode == 0:
        return
    low = err.lower()
    if "repository not found" in low or "could not read username" in low or "terminal prompts disabled" in low:
        raise GitHubError("not_found", "Git couldn't access the repository.",
                          hint="If it's private, add a token with Contents: read access.")
    if "authentication failed" in low or "403" in low:
        raise GitHubError("bad_token", "Git rejected the credentials while cloning.",
                          hint="Check that the token hasn't expired and can read this repository.")
    if "remote branch" in low and "not found" in low:
        raise GitHubError("clone_failed", "The default branch couldn't be found.")
    last = next((l for l in reversed(err.strip().splitlines()) if l.strip()), "unknown error")
    raise GitHubError("clone_failed", f"Cloning failed: {last[:200]}")
