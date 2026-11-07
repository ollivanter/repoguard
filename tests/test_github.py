import base64
import subprocess
import time

import pytest
import requests

from repoguard import github, pins
from repoguard.github import GitHubClient, GitHubError, InvalidRepoRef, RepoRef, parse_repo_ref

from conftest import TOKENS, commit


@pytest.mark.parametrize("text,slug", [
    ("ollivanter/repoguard", "ollivanter/repoguard"),
    ("https://github.com/ollivanter/repoguard", "ollivanter/repoguard"),
    ("github.com/ollivanter/repoguard.git", "ollivanter/repoguard"),
    ("https://www.github.com/psf/requests/tree/main/src?tab=readme#top", "psf/requests"),
    ("git@github.com:ollivanter/life-automations.git", "ollivanter/life-automations"),
    ("  a-b/c.d_e  ", "a-b/c.d_e"),
])
def test_parse_repo_ref(text, slug):
    assert parse_repo_ref(text).slug == slug


@pytest.mark.parametrize("text,needle", [
    ("", "Enter a repository"),
    ("https://gitlab.com/a/b", "not gitlab.com"),
    ("ollivanter", "doesn't look like"),
    ("-bad/repo", "doesn't look like"),
    ("owner/..", "doesn't look like"),
    ("owner/repo; rm -rf /", "doesn't look like"),
    ("https://github.com/owner", "doesn't look like"),
    ("a" * 40 + "/repo", "doesn't look like"),             # owners are at most 39 characters
    ("../../etc/passwd", "doesn't look like"),
])
def test_parse_repo_ref_rejects(text, needle):
    with pytest.raises(InvalidRepoRef, match=needle):
        parse_repo_ref(text)


def test_check_token():
    assert github.check_token("") is None and github.check_token(None) is None
    tok = TOKENS["github-fine-grained-token"]()
    assert github.check_token(f"  {tok} ") == tok
    with pytest.raises(GitHubError) as e:
        github.check_token("hunter2")
    assert e.value.code == "bad_token_format"


# ------------------------------------------------------------------ API client
class Resp:
    def __init__(self, status, data=None, headers=None):
        self.status_code, self._data, self.headers = status, data if data is not None else {}, headers or {}

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, headers))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


REPO = {"owner": {"login": "me"}, "name": "app", "full_name": "me/app", "private": True, "visibility": "private",
        "default_branch": "trunk", "size": 2048, "archived": False, "fork": False, "html_url": "https://github.com/me/app",
        "description": "x", "pushed_at": "2026-11-01T00:00:00Z", "language": "Python", "stargazers_count": 3}
RATE = {"x-ratelimit-limit": "60", "x-ratelimit-remaining": "57", "x-ratelimit-reset": str(int(time.time()) + 600)}


def client(*responses, token=None):
    return GitHubClient(token=token, session=FakeSession(*responses), sleep=lambda s: None)


def test_repo_metadata_and_rate():
    c = client(Resp(200, REPO, RATE))
    info = c.repo(RepoRef("me", "app"))
    assert (info.full_name, info.private, info.default_branch, info.size_kb) == ("me/app", True, "trunk", 2048)
    assert c.rate["remaining"] == 57 and c.rate["authenticated"] is False


def test_token_sent_as_bearer_header():
    tok = TOKENS["github-token"]()
    c = client(Resp(200, REPO, RATE), token=tok)
    c.repo(RepoRef("me", "app"))
    url, headers = c.http.calls[0]
    assert headers["Authorization"] == f"Bearer {tok}" and tok not in url


@pytest.mark.parametrize("resp,code,needle", [
    (Resp(404, {"message": "Not Found"}), "not_found", "private"),
    (Resp(401, {"message": "Bad credentials"}), "bad_token", "rejected"),
    (Resp(403, {"message": "API rate limit exceeded"}, {**RATE, "x-ratelimit-remaining": "0"}), "rate_limited", "60 requests"),
    (Resp(403, {"message": "Resource protected by organization SAML enforcement."}, {"X-GitHub-SSO": "required; url=x"}), "sso_required", "single sign-on"),
    (Resp(403, {"message": "Resource not accessible by personal access token"}), "forbidden", "not accessible"),
    (Resp(451, {}), "unavailable", "legal"),
])
def test_error_mapping(resp, code, needle):
    with pytest.raises(GitHubError) as e:
        client(resp).repo(RepoRef("me", "app"))
    assert e.value.code == code and needle in e.value.message


def test_rate_limit_has_reset_time_and_token_hint():
    reset = int(time.time()) + 1200
    with pytest.raises(GitHubError) as e:
        client(Resp(429, {}, {**RATE, "x-ratelimit-remaining": "0", "x-ratelimit-reset": str(reset)})).repo(RepoRef("a", "b"))
    assert e.value.retry_at == reset and "token" in e.value.hint


def test_secondary_rate_limit_retries_short_waits():
    waits = []
    c = GitHubClient(session=FakeSession(Resp(403, {"message": "You have exceeded a secondary rate limit"}, {"retry-after": "3"}),
                                         Resp(200, REPO, RATE)), sleep=waits.append)
    assert c.repo(RepoRef("me", "app")).name == "app"
    assert waits == [3.0]


def test_secondary_rate_limit_long_wait_fails_fast():
    with pytest.raises(GitHubError) as e:
        client(Resp(403, {"message": "secondary rate limit"}, {"retry-after": "120"})).repo(RepoRef("a", "b"))
    assert e.value.code == "rate_limited" and e.value.retry_at > time.time() + 100


def test_server_errors_retry_then_fail():
    c = client(Resp(502), Resp(503), Resp(200, REPO, RATE))
    assert c.repo(RepoRef("me", "app")).name == "app"
    with pytest.raises(GitHubError) as e:
        client(Resp(500), Resp(500), Resp(500)).repo(RepoRef("a", "b"))
    assert e.value.code == "github_down"


def test_timeouts_and_network_errors():
    with pytest.raises(GitHubError) as e:
        client(requests.Timeout(), requests.Timeout(), requests.Timeout()).repo(RepoRef("a", "b"))
    assert e.value.code == "timeout"
    with pytest.raises(GitHubError) as e:
        client(requests.ConnectionError(), requests.ConnectionError(), requests.ConnectionError()).repo(RepoRef("a", "b"))
    assert e.value.code == "network"


def test_error_messages_never_contain_the_token():
    tok = TOKENS["github-token"]()
    c = client(Resp(403, {"message": f"token {tok} lacks scope"}), token=tok)
    with pytest.raises(GitHubError) as e:
        c.repo(RepoRef("a", "b"))
    assert tok not in e.value.message and "[token]" in e.value.message


# --------------------------------------------------------------------- cloning
def test_clone_env_keeps_token_out_of_argv_and_host_config(monkeypatch):
    monkeypatch.setenv("GIT_ASKPASS", "/usr/bin/operator-helper")
    tok = TOKENS["github-token"]()
    env = github.clone_env(tok)
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_CONFIG_GLOBAL"] and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_ASKPASS"] == ""
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    assert base64.b64decode(env["GIT_CONFIG_VALUE_0"].split()[-1]).decode() == f"x-access-token:{tok}"
    assert "GIT_CONFIG_COUNT" not in github.clone_env(None)


class FakeProc:
    def __init__(self, code=0, stderr=b"", runs=0):
        self.returncode, self._runs = None, runs
        self.final, self.killed = code, False
        self.stderr = type("E", (), {"read": lambda s: stderr})()

    def poll(self):
        if self.killed:
            return -9
        if self._runs <= 0:
            self.returncode = self.final
            return self.final
        self._runs -= 1
        return None

    def kill(self):
        self.killed = True

    def wait(self):
        return self.returncode


def test_clone_argv_and_hardening(tmp_path):
    seen = {}

    def popen(cmd, **kw):
        seen["cmd"], seen["env"] = cmd, kw["env"]
        return FakeProc(0)
    tok = TOKENS["github-token"]()
    github.clone(RepoRef("me", "app"), tmp_path / "x", token=tok, depth=50, branch="trunk", popen=popen)
    cmd = seen["cmd"]
    assert tok not in " ".join(cmd)
    assert "core.symlinks=false" in cmd and "protocol.file.allow=never" in cmd and "--depth=50" in cmd
    assert cmd[cmd.index("--") + 1] == "https://github.com/me/app.git"


@pytest.mark.parametrize("stderr,code", [
    (b"remote: Repository not found.\nfatal: repository 'https://github.com/a/b.git/' not found", "not_found"),
    (b"fatal: could not read Username for 'https://github.com': terminal prompts disabled", "not_found"),
    (b"fatal: Authentication failed for 'https://github.com/a/b.git/'", "bad_token"),
    (b"fatal: early EOF", "clone_failed"),
])
def test_clone_failures_are_mapped_and_scrubbed(tmp_path, stderr, code):
    tok = TOKENS["github-token"]()
    with pytest.raises(GitHubError) as e:
        github.clone(RepoRef("a", "b"), tmp_path / "x", token=tok, popen=lambda *a, **k: FakeProc(128, stderr + tok.encode()))
    assert e.value.code == code and tok not in e.value.message


def test_clone_timeout_kills_git(tmp_path):
    proc = FakeProc(0, runs=10**9)
    with pytest.raises(GitHubError) as e:
        github.clone(RepoRef("a", "b"), tmp_path / "x", timeout=0.3, popen=lambda *a, **k: proc)
    assert e.value.code == "timeout" and proc.killed


def test_clone_cancel_kills_git(tmp_path):
    proc = FakeProc(0, runs=10**9)

    class Stop(Exception):
        pass

    def should_stop():
        raise Stop()
    with pytest.raises(Stop):
        github.clone(RepoRef("a", "b"), tmp_path / "x", popen=lambda *a, **k: proc, should_stop=should_stop)
    assert proc.killed


def test_real_clone_of_local_repo_respects_no_symlinks(repo, tmp_path, monkeypatch):
    """End to end with real git, cloning over file:// (allowed only for this test)."""
    commit(repo, {"a.txt": "hello\n"})
    (repo / "link").symlink_to("/etc/passwd")
    subprocess.run(["git", "-C", str(repo), "add", "link"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "link"], check=True)
    dest = tmp_path / "clone"
    subprocess.run(["git", "-c", "core.symlinks=false", "clone", "-q", "--depth=1", f"file://{repo}", str(dest)], check=True,
                   env=github.clone_env(None))
    assert not (dest / "link").is_symlink() and (dest / "link").read_text() == "/etc/passwd"


# ------------------------------------------------------------------------ pins
def test_ls_remote_prefers_peeled_tags():
    out = ("1111111111111111111111111111111111111111\trefs/tags/v4\n"
           "2222222222222222222222222222222222222222\trefs/tags/v4^{}\n")
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")
    assert pins.ls_remote("actions/checkout", "v4", runner=runner) == "2" * 40
    assert calls[0][:3] == ["git", "ls-remote", "--"]
    assert pins.ls_remote("actions/checkout", "--upload-pack=evil", runner=runner) is None
    assert pins.ls_remote("bad repo/x", "v1", runner=runner) is None


def test_apply_pins_builds_patch():
    from repoguard import workflows
    text = "on: push\npermissions: {contents: read}\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-python@v6\n"
    findings = workflows.Checker(".github/workflows/a.yml", text).run()
    stats = pins.apply(findings, resolver=lambda repo, ref: "a" * 40 if (repo, ref) == ("actions/setup-python", "v6") else None)
    f = next(x for x in findings if x.rule == "workflow/unpinned-action")
    assert stats == {"actions_resolved": 1, "actions_unresolved": 0}
    assert f.patch["after"] == ["      - uses: actions/setup-python@" + "a" * 40 + " # v6"]
    assert f.details["resolved_sha"] == "a" * 40 and "a" * 40 in f.fix
