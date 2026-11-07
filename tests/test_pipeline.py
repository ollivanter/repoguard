import json
import shutil
import subprocess
import textwrap
import threading
import time

import pytest

from repoguard import deps, pipeline, secrets, workflows
from repoguard.files import is_safe_file, list_files, read_text
from repoguard.github import GitHubError, RepoInfo, RepoRef
from repoguard.pipeline import STEP_IDS, Cancelled, Context, InvalidTransition, Options, Progress

from conftest import TOKENS, commit


# ------------------------------------------------------------- state machine
def test_progress_transitions_and_events():
    events = []
    p = Progress(["validate", "clone"], events.append)
    p.start("validate", "a/b")
    p.done("validate", "ok")
    p.skip("clone", "local folder")
    assert [(e["id"], e["state"]) for e in events] == [("validate", "running"), ("validate", "done"), ("clone", "skipped")]
    assert events[1]["ms"] is not None and events[2]["ms"] is None or events[2]["ms"] == 0
    with pytest.raises(InvalidTransition):
        p.done("validate")                    # already finished
    with pytest.raises(InvalidTransition):
        p.start("clone")                      # skipped is terminal


def test_cancel_rest_marks_pending_and_running():
    events = []
    p = Progress(["validate", "metadata", "clone"], events.append)
    p.start("validate")
    p.cancel_rest()
    assert [s["state"] for s in p.snapshot()] == ["cancelled", "cancelled", "cancelled"]


# ---------------------------------------------------------- dependency paths
def test_npm_paths_follow_node_resolution():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"express": "^4"}, "devDependencies": {"jest": "^29"}},
        "node_modules/express": {"version": "4.17.1", "dependencies": {"qs": "6.7.0", "body-parser": "1"}},
        "node_modules/body-parser": {"version": "1.19.0", "dependencies": {"qs": "6.7.0"}},
        "node_modules/qs": {"version": "6.7.0"},
        "node_modules/express/node_modules/debug": {"version": "2.6.9"},
        "node_modules/jest": {"version": "29.0.0", "dev": True, "dependencies": {"@babel/core": "7"}},
        "node_modules/@babel/core": {"version": "7.0.0", "dev": True},
        "node_modules/orphan": {"version": "1.0.0"},
    }}
    pkgs = {p.name: p for p in deps.parse_npm_lock(json.dumps(lock), "package-lock.json")}
    assert pkgs["qs"].path == ("express", "qs")
    assert pkgs["body-parser"].path == ("express", "body-parser")
    assert pkgs["@babel/core"].path == ("jest", "@babel/core") and pkgs["@babel/core"].dev
    assert pkgs["express"].path == ("express",) and not pkgs["express"].dev
    assert pkgs["orphan"].path == ()


def test_poetry_paths_and_dev_detection():
    lock = textwrap.dedent('''
        [[package]]
        name = "Flask"
        version = "2.0.1"
        [package.dependencies]
        Jinja2 = ">=3.0"
        [[package]]
        name = "jinja2"
        version = "3.0.0"
        [package.dependencies]
        MarkupSafe = ">=2"
        [[package]]
        name = "markupsafe"
        version = "2.0.0"
        [[package]]
        name = "pytest"
        version = "7.0.0"
    ''')
    pyproject = textwrap.dedent('''
        [tool.poetry.dependencies]
        python = "^3.11"
        flask = "^2"
        [tool.poetry.group.dev.dependencies]
        pytest = "^7"
    ''')
    pkgs = {p.name.lower(): p for p in deps.parse_poetry_lock(lock, "poetry.lock", pyproject)}
    assert pkgs["markupsafe"].path == ("Flask", "jinja2", "markupsafe")
    assert pkgs["pytest"].dev and not pkgs["jinja2"].dev


def test_dependency_patch_bumps_exact_line(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nJinja2[i18n]==2.10 ; python_version>'3'  # web\n")
    pkg = deps.Package("Jinja2", "2.10", "PyPI", "requirements.txt", 2, path=("Jinja2",))
    patch = deps.dependency_patch(tmp_path, pkg, "3.1.4")
    assert patch == {"start": 2, "before": ["Jinja2[i18n]==2.10 ; python_version>'3'  # web"],
                     "after": ["Jinja2[i18n]==3.1.4 ; python_version>'3'  # web"]}
    (tmp_path / "package.json").write_text('{\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}\n')
    pkg = deps.Package("lodash", "4.17.20", "npm", "package.json", 3, path=("lodash",))
    assert deps.dependency_patch(tmp_path, pkg, "4.17.21")["after"] == ['    "lodash": "4.17.21"']


# ------------------------------------------------------------- secret patches
@pytest.mark.parametrize("file,line,expected", [
    ("app/config.py", 'GITHUB_TOKEN = "{t}"', 'GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]'),
    ("src/client.ts", "const apiKey = '{t}';", "const apiKey = process.env.APIKEY;"),
    ("deploy.sh", "export GH_TOKEN={t}", 'export GH_TOKEN="${GH_TOKEN:?GH_TOKEN is not set}"'),
    (".github/workflows/ci.yml", "          token: {t}", "          token: ${{ secrets.TOKEN }}"),
    (".env", "GITHUB_TOKEN={t}", "# GITHUB_TOKEN comes from the environment or your secret manager; don't commit .env files"),
])
def test_secret_patches_never_contain_the_secret(file, line, expected):
    tok = TOKENS["github-token"]()
    hit = secrets.scan_line(line.format(t=tok), 7)[0]
    patch = secrets.secret_patch(hit, file)
    assert patch["after"] == [expected] and patch["start"] == 7
    assert tok not in json.dumps(patch)


def test_no_patch_for_private_keys_or_unknown_files():
    hit = secrets.scan_line(TOKENS["private-key"](), 1)[0]
    assert secrets.secret_patch(hit, "id_rsa") is None
    hit = secrets.scan_line(f'k = "{TOKENS["github-token"]()}"', 1)[0]
    assert secrets.secret_patch(hit, "notes.txt") is None


def test_generic_rules_skip_very_long_lines_quickly():
    line = "x" * 900 + "a" * 4000 + ' password = "Xk9#mQ2$vL7p"'
    t = time.perf_counter()
    secrets.scan_line(line, 1)
    assert time.perf_counter() - t < 0.5
    assert secrets.scan_line('password = "Xk9#mQ2$vL7p"', 1)


# ----------------------------------------------------------- workflow patches
def test_workflow_patches_are_valid_yaml():
    import yaml
    text = textwrap.dedent("""
        on: issues
        jobs:
          triage:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - name: Greet
                env:
                  FOO: bar
                run: |
                  echo "${{ github.event.issue.title }}"
    """).lstrip()
    findings = workflows.Checker(".github/workflows/t.yml", text).run()
    lines = text.splitlines()
    for f in findings:
        if not f.patch:
            continue
        start = f.patch["start"] - 1
        patched = lines[:start] + f.patch["after"] + lines[start + len(f.patch["before"]):]
        data = yaml.safe_load("\n".join(patched))
        assert data["jobs"]["triage"]["steps"], f.rule
        if f.rule == "workflow/script-injection":
            step = data["jobs"]["triage"]["steps"][1]
            assert step["env"]["ISSUE_TITLE"] == "${{ github.event.issue.title }}" and step["env"]["FOO"] == "bar"
            assert "${{" not in step["run"]
        if f.rule == "workflow/persist-credentials":
            assert data["jobs"]["triage"]["steps"][0]["with"] == {"persist-credentials": False}
        if f.rule == "workflow/missing-permissions":
            assert data["permissions"] == {"contents": "read"}


# -------------------------------------------------------------- file safety
def test_symlinks_are_never_read(repo):
    commit(repo, {"ok.py": "x = 1\n"})
    (repo / "leak.txt").symlink_to("/etc/hostname")
    subprocess.run(["git", "-C", str(repo), "add", "leak.txt"], check=True)
    assert "leak.txt" not in list_files(repo)
    assert not is_safe_file(repo, "leak.txt")
    assert read_text(repo / "leak.txt") is None


# ----------------------------------------------------------- full pipeline
class FakeClient:
    def __init__(self, size_kb=100, error=None):
        self.size_kb, self.error, self.rate = size_kb, error, {"limit": 60, "remaining": 59, "reset": 0, "authenticated": False}

    def repo(self, ref):
        if self.error:
            raise self.error
        return RepoInfo(owner=ref.owner, name=ref.name, full_name=ref.slug, private=False, visibility="public",
                        default_branch="main", size_kb=self.size_kb, archived=False, fork=False,
                        html_url=f"https://github.com/{ref.slug}", description=None, pushed_at=None, language=None, stars=0)


def local_cloner(source):
    def cloner(ref, dest, *, token, depth, branch, timeout, should_stop):
        shutil.copytree(source, dest, symlinks=True)
    return cloner


def test_scan_github_end_to_end(repo):
    tok = TOKENS["github-token"]()
    commit(repo, {"app.py": f'TOKEN = "{tok}"\n', "Dockerfile": "FROM python\nCMD python app.py\n",
                  ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v6\n"})
    events = []
    ctx = Context(progress=Progress(STEP_IDS, events.append), pin_resolver=lambda r, ref: "b" * 40)
    result = pipeline.scan_github(RepoRef("me", "demo"), Options(resolve_pins=True, osv=False), ctx,
                                  client=FakeClient(), cloner=local_cloner(repo))
    steps = [(e["id"], e["state"]) for e in events if e["type"] == "step"]
    assert steps[0] == ("validate", "running") and steps[-1] == ("score", "done")
    finished = {sid: state for sid, state in steps if state != "running"}
    assert finished == {"validate": "done", "metadata": "done", "clone": "done", "secrets": "done", "history": "done",
                        "dependencies": "done", "osv": "skipped", "workflows": "done", "containers": "done",
                        "pins": "done", "score": "done"}
    assert any(e["type"] == "meta" for e in events) and any(e["type"] == "rate" for e in events)
    rules = {f.rule for f in result.findings}
    assert {"secret/github-token", "container/runs-as-root", "container/unpinned-base-image", "workflow/unpinned-action"} <= rules
    pinned = next(f for f in result.findings if f.rule == "workflow/unpinned-action")
    assert "b" * 40 in pinned.patch["after"][0]
    assert result.repo == "me/demo" and result.meta["visibility"] == "public" and result.commit
    assert tok not in json.dumps(result.to_dict())
    assert result.to_dict()["breakdown"][0]["points"] > 0


def test_scan_github_rejects_huge_repos():
    events = []
    ctx = Context(progress=Progress(STEP_IDS, events.append))
    with pytest.raises(GitHubError) as e:
        pipeline.scan_github(RepoRef("me", "big"), Options(max_repo_kb=1000), ctx, client=FakeClient(size_kb=5000),
                             cloner=lambda *a, **k: pytest.fail("should not clone"))
    assert e.value.code == "too_large"
    assert ("clone", "failed") in [(ev["id"], ev["state"]) for ev in events if ev["type"] == "step"]


def test_scan_github_metadata_error_marks_step_failed():
    events = []
    ctx = Context(progress=Progress(STEP_IDS, events.append))
    with pytest.raises(GitHubError):
        pipeline.scan_github(RepoRef("me", "x"), Options(), ctx, client=FakeClient(error=GitHubError("not_found", "nope")))
    assert ("metadata", "failed") in [(ev["id"], ev["state"]) for ev in events if ev["type"] == "step"]


def test_cancel_between_steps(repo):
    commit(repo, {"a.txt": "x"})
    ctx = Context(progress=Progress(STEP_IDS))
    ctx.cancel.set()
    with pytest.raises(Cancelled):
        pipeline.scan_github(RepoRef("me", "x"), Options(), ctx, client=FakeClient(), cloner=local_cloner(repo))


def test_no_manifests_reports_cleanly(repo):
    commit(repo, {"README.md": "hi"})
    events = []
    r = pipeline.scan_local(repo, Options(), Context(progress=Progress(STEP_IDS, events.append)))
    done = {e["id"]: e["detail"] for e in events if e["type"] == "step" and e["state"] in ("done", "skipped")}
    assert done["dependencies"] == "no dependency manifests found"
    assert done["osv"] == "no pinned packages to check"
    assert done["workflows"] == "no workflows found" and done["containers"] == "no Dockerfiles found"
    assert r.score == 100 and r.stats["manifests"] == 0


def test_lockfiles_reach_the_dependency_scanner(repo):
    """Lockfiles are skipped by the secret scan but must still be parsed for dependencies."""
    lock = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "4"}}, "node_modules/lodash": {"version": "4.17.20"}}}
    commit(repo, {"web/package-lock.json": json.dumps(lock), "web/package.json": '{"dependencies": {"lodash": "^4"}}',
                  "poetry.lock": '[[package]]\nname = "jinja2"\nversion = "2.10"\n'})
    r = pipeline.scan_local(repo, Options(osv=False), Context(progress=Progress(STEP_IDS)))
    assert r.stats["manifests"] == 3 and r.stats["packages_found"] == 2
    assert "web/package-lock.json" not in list_files(repo)


def test_empty_repository_gets_a_clear_error():
    def failing_clone(*a, **k):
        raise GitHubError("clone_failed", "Cloning failed: warning: You appear to have cloned an empty repository.")
    with pytest.raises(GitHubError) as e:
        pipeline.scan_github(RepoRef("me", "empty"), Options(), Context(progress=Progress(STEP_IDS)),
                             client=FakeClient(size_kb=0), cloner=failing_clone)
    assert e.value.code == "empty_repo" and "no commits" in e.value.message
