import json

import pytest

from repoguard import cli, ghcomment, report, scoring
from repoguard.models import Finding, ScanResult, Severity
from repoguard.scanner import github_slug, scan_path

from conftest import TOKENS, commit


def F(sev, rule="x/y", cat="workflows", **kw):
    return Finding(rule=rule, title=kw.pop("title", f"{sev.label} thing"), severity=sev, category=cat, **kw)


def test_score_and_grades():
    assert scoring.score([]) == (100, "A")
    assert scoring.score([F(Severity.LOW)]) == (98, "A")
    one, many = scoring.score([F(Severity.MEDIUM)])[0], scoring.score([F(Severity.MEDIUM)] * 8)[0]
    assert one == 95 and many == 80          # 8 repeats cost 4x, not 8x
    assert scoring.score([F(Severity.CRITICAL)]) == (59, "F")    # any critical fails
    assert scoring.score([F(Severity.HIGH, rule=f"r{i}") for i in range(10)])[0] == 0


def sample_result():
    r = ScanResult(target="demo", repo="me/demo", commit="a" * 40, scanned_at="2026-11-07 10:00 UTC")
    r.findings = [
        F(Severity.HIGH, rule="secret/github-token", cat="secrets", file="src/app.py", line=3,
          title="GitHub token committed to the repo", evidence='T = "ghp_****" <script>alert(1)</script>'),
        F(Severity.HIGH, rule="secret/aws-access-key", cat="secrets", file="old.sh", line=1, commit="b" * 40,
          title="AWS access key ID in git history"),
        F(Severity.LOW, file=".github/workflows/ci.yml", line=7, title="Action `actions/checkout@v6` is not pinned",
          description="Use `uses: x@sha`"),
        F(Severity.MEDIUM, rule="dependency/vulnerable", cat="dependencies", file="requirements.txt", line=2,
          title="jinja2 2.10 has 1 known vulnerability", description="PyPI package:\n- [medium] GHSA-1: XSS",
          references=["https://osv.dev/vulnerability/GHSA-1"]),
    ]
    r.notes = ["Dependency vulnerabilities weren't checked: offline."]
    r.score, r.grade = scoring.score(r.findings)
    return r


def test_links():
    r = sample_result()
    assert report.link(r, r.findings[0]) == f"https://github.com/me/demo/blob/{'a' * 40}/src/app.py#L3"
    assert report.link(r, r.findings[1]) == f"https://github.com/me/demo/commit/{'b' * 40}"


def test_markdown():
    md = report.markdown(sample_result())
    assert md.startswith(report.MARKER)
    assert "| 0 | 2 | 1 | 1 |" in md
    assert "<script>" not in md and "&lt;script&gt;" in md
    assert md.index("🟠 High") < md.index("🟡 Medium") < md.index("🔵 Low")
    assert "<details open><summary><b>🟠 High (2)" in md
    assert "(commit bbbbbbb)" in md


def test_markdown_truncates(monkeypatch):
    r = sample_result()
    r.findings = [F(Severity.LOW, rule=f"r{i}", description="x" * 500, title=f"t{i}") for i in range(300)]
    md = report.markdown(r)
    assert len(md) < 64000 and "more. Download the full HTML report" in md


def test_html_is_escaped_and_complete():
    page = report.html_report(sample_result())
    assert page.startswith("<!doctype html>") and page.rstrip().endswith("</html>")
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert page.count('class="finding"') == 4
    assert "<code>actions/checkout@v6</code>" in page
    assert "Dependency vulnerabilities weren" in page


def test_html_empty_state():
    r = ScanResult(target="clean")
    assert "No findings." in report.html_report(r)


def test_json_roundtrip():
    data = json.loads(report.to_json(sample_result()))
    assert data["score"] == sample_result().score and data["counts"]["high"] == 2
    assert data["findings"][0]["severity"] == "high"


def test_github_slug():
    assert github_slug("https://github.com/ollivanter/life-automations") == "ollivanter/life-automations"
    assert github_slug("git@github.com:ollivanter/repoguard.git") == "ollivanter/repoguard"
    assert github_slug("ollivanter/repoguard") == "ollivanter/repoguard"
    assert github_slug("https://gitlab.com/a/b") is None


def test_scan_path_end_to_end(repo, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    commit(repo, {
        "app.py": f'TOKEN = "{TOKENS["github-token"]()}"\n',
        "requirements.txt": "requests\n",
        ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v6\n",
    })
    r = scan_path(repo, offline=True)
    assert {f.rule for f in r.findings} == {"secret/github-token", "dependency/unpinned", "workflow/unpinned-action",
                                            "workflow/missing-permissions", "workflow/persist-credentials"}
    assert r.grade == "F" and r.commit
    assert r.stats["files_scanned"] == 3 and r.stats["workflows_scanned"] == 1


def test_github_actions_env_sets_repo(repo, monkeypatch):
    commit(repo, {"a.txt": "x"})
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "me/demo")
    monkeypatch.setenv("GITHUB_SHA", "c" * 40)
    r = scan_path(repo, offline=True)
    assert (r.repo, r.commit) == ("me/demo", "c" * 40)


def test_cli_exit_codes_and_outputs(repo, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    commit(repo, {"requirements.txt": "flask\n"})
    out = tmp_path / "out"
    out.mkdir()
    code = cli.main(["scan", str(repo), "--offline", "--fail-on", "low",
                     "--json", str(out / "r.json"), "--markdown", str(out / "r.md"), "--html", str(out / "r.html")])
    assert code == 1
    assert json.loads((out / "r.json").read_text())["counts"]["low"] == 1
    assert (out / "r.md").read_text().startswith(report.MARKER)
    assert "RepoGuard" in capsys.readouterr().out
    assert cli.main(["scan", str(repo), "--offline", "--fail-on", "medium"]) == 0
    assert cli.main(["scan", str(repo), "--offline"]) == 0


def test_cli_only_flag(repo, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    commit(repo, {"requirements.txt": "flask\n", "k.txt": TOKENS["aws-access-key"]()})
    assert cli.main(["scan", str(repo), "--offline", "--only", "workflows", "--fail-on", "low"]) == 0


def test_cli_bad_target(capsys):
    assert cli.main(["scan", "/definitely/not/here"]) == 2
    assert "neither a folder nor a GitHub repo" in capsys.readouterr().err


# ------------------------------------------------------------- PR comment
class Resp:
    def __init__(self, data=None, status=200):
        self._data, self.status_code = data, status

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(response=self)


class FakeGitHub:
    def __init__(self, comments):
        self.comments, self.calls = comments, []

    def get(self, url, params=None, timeout=None):
        self.calls.append(("GET", url))
        page = params["page"]
        return Resp(self.comments[(page - 1) * 100: page * 100])

    def patch(self, url, json=None, timeout=None):
        self.calls.append(("PATCH", url))
        return Resp({})

    def post(self, url, json=None, timeout=None):
        self.calls.append(("POST", url))
        return Resp({})


def test_comment_updates_existing():
    gh = FakeGitHub([{"id": i, "body": "hi"} for i in range(150)] + [{"id": 999, "body": report.MARKER + "\nold"}])
    assert ghcomment.upsert(gh, "https://api", "me/demo", 5, "new") == "updated"
    assert gh.calls[-1] == ("PATCH", "https://api/repos/me/demo/issues/comments/999")


def test_comment_creates_when_missing():
    gh = FakeGitHub([{"id": 1, "body": "hi"}])
    assert ghcomment.upsert(gh, "https://api", "me/demo", 5, "new") == "created"
    assert gh.calls[-1] == ("POST", "https://api/repos/me/demo/issues/5/comments")


def test_pr_number(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps({"pull_request": {"number": 12}}))
    assert ghcomment.pr_number(str(p)) == 12
    p.write_text(json.dumps({"ref": "refs/heads/main"}))
    assert ghcomment.pr_number(str(p)) is None
    assert ghcomment.pr_number(None) is None
