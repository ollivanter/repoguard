import subprocess
from pathlib import Path

import pytest

# Fake credentials are assembled at runtime so this file never contains a
# string that looks like a real token (GitHub push protection would block it).
ALNUM = "Zq7XvB2mK9pLw4Rt8Ny3Hd6Jc1Fs5Gu0Ae"   # 34 mixed chars


def fake(prefix: str, length: int, alphabet: str = ALNUM) -> str:
    body = (alphabet * (length // len(alphabet) + 1))[:length]
    return prefix + body


TOKENS = {
    "github-token": lambda: fake("gh" + "p_", 36),
    "aws-access-key": lambda: "AK" + "IA" + "QW7RT5YU3IO1PZ8X",
    "slack-token": lambda: "xo" + "xb-" + "2847561930-" + fake("", 24),
    "google-api-key": lambda: "AI" + "za" + fake("", 35),
    "stripe-live-key": lambda: "sk" + "_live_" + fake("", 28),
    "telegram-bot-token": lambda: "6072513" + "976:" + "AA" + fake("", 33),
    "notion-token": lambda: "nt" + "n_" + fake("", 46),
    "anthropic-key": lambda: "sk-" + "ant-api03-" + fake("", 90),
    "openai-key": lambda: "sk-" + "proj-" + fake("", 24) + "T3Blbk" + "FJ" + fake("", 24),
    "private-key": lambda: "-----BEGIN " + "RSA PRIVATE KEY-----",
    "github-fine-grained-token": lambda: "github" + "_pat_" + fake("", 82),
}


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "Test")
    git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def commit(repo: Path, files: dict[str, str | None], message: str = "change") -> str:
    for name, content in files.items():
        p = repo / name
        if content is None:
            p.unlink()
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")
