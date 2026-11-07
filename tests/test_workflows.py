import textwrap

from repoguard import workflows
from repoguard.models import Severity

SHA = "d23441a48e516b6c34aea4fa41551a30e30af803"


def check(yaml_text: str, rel: str = ".github/workflows/ci.yml"):
    return workflows.Checker(rel, textwrap.dedent(yaml_text).lstrip()).run()


def rules(findings):
    return sorted(f.rule.split("/")[1] for f in findings)


def test_clean_workflow_has_no_findings():
    f = check(f"""
    name: CI
    on: [push, pull_request]
    permissions:
      contents: read
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@{SHA} # v6
            with:
              persist-credentials: false
          - uses: ./.github/actions/local
          - run: echo "hello"
    """)
    assert f == []


def test_unpinned_actions_and_severity_by_owner():
    f = check("""
    on: push
    permissions: {contents: read}
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/setup-python@v6
          - uses: tj-actions/changed-files@v45
          - uses: someone/action
          - uses: docker://alpine:3.20
          - uses: docker://alpine@sha256:abc123
      reuse:
        uses: org/shared/.github/workflows/build.yml@main
    """)
    by_title = {x.title: x for x in f}
    assert by_title["Action `actions/setup-python@v6` is not pinned to a commit SHA"].severity == Severity.LOW
    assert by_title["Action `tj-actions/changed-files@v45` is not pinned to a commit SHA"].severity == Severity.MEDIUM
    assert "default branch" in by_title["Action `someone/action` is not pinned to a commit SHA"].description
    assert "Docker image `docker://alpine:3.20` is not pinned by digest" in by_title
    assert "Action `org/shared/.github/workflows/build.yml@main` is not pinned to a commit SHA" in by_title
    assert len(f) == 5
    assert by_title["Action `actions/setup-python@v6` is not pinned to a commit SHA"].line == 7
    assert "git ls-remote https://github.com/tj-actions/changed-files refs/tags/v45" in \
        by_title["Action `tj-actions/changed-files@v45` is not pinned to a commit SHA"].fix


def test_missing_and_write_all_permissions():
    f = check(f"""
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        steps: [{{run: "true"}}]
      b:
        runs-on: ubuntu-latest
        permissions: write-all
        steps: [{{run: "true"}}]
    """)
    assert rules(f) == ["missing-permissions", "write-all"]
    missing = next(x for x in f if x.rule.endswith("missing-permissions"))
    assert "`a`" in missing.description and "`b`" not in missing.description
    assert missing.line == 2


def test_job_level_permissions_are_enough():
    f = check("""
    on: push
    jobs:
      a:
        runs-on: ubuntu-latest
        permissions: {contents: read}
        steps: [{run: "true"}]
    """)
    assert f == []


def test_script_injection_and_safe_env_pattern():
    f = check("""
    on: issues
    permissions: {contents: read}
    jobs:
      triage:
        runs-on: ubuntu-latest
        steps:
          - run: |
              echo "New issue"
              echo "${{ github.event.issue.title }}"
          - env:
              TITLE: ${{ github.event.issue.title }}
            run: echo "$TITLE"
          - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
            with:
              script: console.log("${{ github.event.comment.body }}")
    """)
    inj = [x for x in f if x.rule == "workflow/script-injection"]
    assert len(inj) == 2
    assert inj[0].severity == Severity.HIGH and inj[0].line == 9
    assert "github.event.issue.title" in inj[0].title
    assert "github-script" in inj[1].title


def test_head_ref_and_inputs():
    f = check("""
    on:
      pull_request:
      workflow_dispatch:
        inputs:
          name: {type: string}
    permissions: {contents: read}
    jobs:
      x:
        runs-on: ubuntu-latest
        steps:
          - run: git checkout ${{ github.head_ref }}
          - run: echo ${{ inputs.name }}
    """)
    assert rules(f) == ["input-injection", "script-injection"]


def test_secret_printed():
    f = check("""
    on: push
    permissions: {contents: read}
    jobs:
      x:
        runs-on: ubuntu-latest
        steps:
          - run: echo "token is ${{ secrets.API_TOKEN }}"
          - run: echo "::add-mask::${{ secrets.OTHER }}"
          - run: echo "${{ secrets.PASS }}" | docker login -u me --password-stdin
    """)
    assert rules(f) == ["secret-printed"]
    assert f[0].line == 7


def test_pwn_request():
    f = check(f"""
    on: pull_request_target
    permissions: {{contents: read}}
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@{SHA}
            with:
              ref: ${{{{ github.event.pull_request.head.sha }}}}
              persist-credentials: false
          - run: npm ci && npm test
    """)
    assert rules(f) == ["pwn-request"]
    assert f[0].severity == Severity.CRITICAL and f[0].line == 9


def test_pull_request_trigger_with_head_ref_is_fine():
    f = check(f"""
    on: pull_request
    permissions: {{contents: read}}
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@{SHA}
            with:
              ref: ${{{{ github.event.pull_request.head.sha }}}}
              persist-credentials: false
    """)
    assert f == []


def test_persist_credentials_variants():
    base = """
    on: push
    permissions: {{contents: read}}
    jobs:
      x:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@""" + SHA + """
            with:
              persist-credentials: {}
    """
    assert rules(check(base.format("true"))) == ["persist-credentials"]
    assert check(base.format("false")) == []
    assert check(base.format("'false'")) == []


def test_composite_action_steps_are_checked():
    f = check("""
    name: my action
    runs:
      using: composite
      steps:
        - uses: actions/setup-python@v6
        - shell: bash
          run: echo "${{ github.event.pull_request.title }}"
    """, rel="action.yml")
    assert rules(f) == ["script-injection", "unpinned-action"]


def test_on_key_variants():
    assert workflows.triggers({True: "push"}) == {"push"}
    assert workflows.triggers({"on": ["push", "pull_request"]}) == {"push", "pull_request"}
    assert workflows.triggers({True: {"push": None, "schedule": [], "__line__": 1}}) == {"push", "schedule"}


def test_invalid_yaml_is_a_note(tmp_path):
    p = tmp_path / ".github" / "workflows"
    p.mkdir(parents=True)
    (p / "bad.yml").write_text("on: push\njobs: [\n")
    findings, stats, notes = workflows.scan(tmp_path, [".github/workflows/bad.yml"])
    assert findings == [] and stats["workflows_scanned"] == 1
    assert notes and "bad.yml" in notes[0]


def test_find_workflow_files():
    files = [".github/workflows/a.yml", ".github/workflows/b.yaml", ".github/workflows/sub/c.yml",
             "action.yml", ".github/actions/setup/action.yaml", "docs/action.yml"]
    assert workflows.find_workflow_files(files) == [
        ".github/actions/setup/action.yaml", ".github/workflows/a.yml", ".github/workflows/b.yaml", "action.yml"]
