import pytest

from repoguard import secrets
from repoguard.models import Severity

from conftest import TOKENS, commit, fake


@pytest.mark.parametrize("rule_id", sorted(TOKENS))
def test_each_rule_detects_its_token(rule_id):
    token = TOKENS[rule_id]()
    hits = secrets.scan_line(f'value = "{token}"', 1)
    assert [h.rule.id for h in hits] == [rule_id]


@pytest.mark.parametrize("line", [
    'key = "AKIAIOSFODNN7EXAMPLE"',                      # AWS's documented example key
    'token = "' + "gh" + 'p_' + "x" * 36 + '"',         # obvious placeholder
    'password = "your-password-here"',
    'api_key = "${API_KEY}"',
    "token: ${{ secrets.GITHUB_TOKEN }}",
    'password = os.environ["DB_PASSWORD"]',
    'SECRET_KEY = "change_me_please"',
    'auth_token = "access_token_name"',                 # identifier, not a secret
    'password_file = "/run/secrets/db_password"',       # path
])
def test_placeholders_are_ignored(line):
    assert secrets.scan_line(line, 1) == []


def test_generic_rule_needs_entropy():
    assert secrets.scan_line('db_password = "Xk9#mQ2$vL7p"', 1)[0].rule.id == "generic-secret"
    assert secrets.scan_line('db_password = "aaaabbbb"', 1) == []


def test_env_style_assignment():
    hits = secrets.scan_line("STRIPE_SECRET=" + fake("", 30), 1)
    assert hits and hits[0].rule.id == "env-secret"


def test_database_url_password():
    hits = secrets.scan_line("DATABASE_URL=postgres://app:Sup3rS3cretPw@db.internal:5432/app", 1)
    assert hits[0].rule.id == "database-url-password"
    assert hits[0].secret == "Sup3rS3cretPw"


def test_ignore_marker():
    token = TOKENS["github-token"]()
    assert secrets.scan_line(f'x = "{token}"  # repoguard:ignore', 1) == []


def test_specific_rule_wins_over_generic():
    token = TOKENS["github-token"]()
    hits = secrets.scan_line(f'GITHUB_TOKEN = "{token}"', 1)
    assert [h.rule.id for h in hits] == ["github-token"]


def test_evidence_never_contains_the_secret():
    for rule_id, make in TOKENS.items():
        token = make()
        hit = secrets.scan_line(f'k = "{token}"', 1)[0]
        if rule_id != "private-key":
            assert token not in hit.evidence()
            assert hit.evidence().count("*") >= 4


def test_current_secret_in_working_tree(repo):
    token = TOKENS["github-token"]()
    commit(repo, {"app.py": f'TOKEN = "{token}"\n'})
    findings, stats = secrets.scan(repo, is_git=True)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL and f.file == "app.py" and f.line == 1 and f.commit is None
    assert "first committed in" in f.description
    assert token not in f.evidence and token not in f.description
    assert stats["commits_scanned"] == 1


def test_secret_removed_but_still_in_history(repo):
    token = TOKENS["aws-access-key"]()
    leak = commit(repo, {"config.py": "x = 1\n", "deploy.sh": f"export AWS_KEY={token}\n"}, "add deploy")
    commit(repo, {"deploy.sh": "export AWS_KEY=$AWS_KEY\n"}, "remove key")
    commit(repo, {"README.md": "hi\n"}, "docs")
    findings, _ = secrets.scan(repo, is_git=True)
    assert len(findings) == 1
    f = findings[0]
    assert f.commit == leak
    assert f.severity == Severity.HIGH              # one level below critical, but still serious
    assert f.file == "deploy.sh" and f.line == 1
    assert "git history" in f.title


def test_history_reports_once_with_earliest_commit(repo):
    token = TOKENS["slack-token"]()
    first = commit(repo, {"a.txt": f"t={token}\n"}, "one")
    commit(repo, {"b.txt": f"t={token}\n"}, "two")
    commit(repo, {"a.txt": None, "b.txt": None}, "cleanup")
    findings, _ = secrets.scan(repo, is_git=True)
    assert len(findings) == 1
    assert findings[0].commit == first
    assert "2 commits" in findings[0].description


def test_history_can_be_disabled(repo):
    token = TOKENS["aws-access-key"]()
    commit(repo, {"k.txt": token})
    commit(repo, {"k.txt": None})
    assert secrets.scan(repo, is_git=True, history=False)[0] == []


def test_repoguardignore_and_gitignore(repo):
    token = TOKENS["github-token"]()
    commit(repo, {".repoguardignore": "fixtures/\n", "fixtures/t.txt": token, ".gitignore": ".env\n"})
    (repo / ".env").write_text(f"GITHUB_TOKEN={token}\n")    # local only: never committed
    findings, _ = secrets.scan(repo, is_git=True)
    assert findings == []


def test_untracked_file_is_scanned(repo):
    commit(repo, {"README.md": "x"})
    (repo / "new.py").write_text(f'k = "{TOKENS["stripe-live-key"]()}"')
    findings, _ = secrets.scan(repo, is_git=True)
    assert [f.file for f in findings] == ["new.py"]


def test_plain_folder_without_git(tmp_path):
    (tmp_path / "x.env").write_text(f"NOTION={TOKENS['notion-token']()}\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "y.js").write_text(TOKENS["github-token"]())
    findings, stats = secrets.scan(tmp_path, is_git=False)
    assert [f.rule for f in findings] == ["secret/notion-token"]
    assert "commits_scanned" not in stats
