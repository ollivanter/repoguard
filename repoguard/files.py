"""Finding which files to scan."""
from __future__ import annotations

import fnmatch
import os
import subprocess
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "env",
             "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", "coverage",
             "site-packages", "bower_components", ".terraform"}

SKIP_PATTERNS = ["*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json",
                 "npm-shrinkwrap.json", "pnpm-lock.yaml", "go.sum", "*.svg"]

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".pdf", ".zip",
    ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class", ".so", ".dll",
    ".dylib", ".exe", ".bin", ".o", ".a", ".pyc", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".ogg", ".webm", ".psd", ".sqlite", ".db",
}

MAX_FILE_BYTES = 1_000_000
IGNORE_FILE = ".repoguardignore"


def is_git_repo(root: Path) -> bool:
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
                             capture_output=True, text=True, timeout=30)
        return out.returncode == 0 and out.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def load_ignore_patterns(root: Path) -> list[str]:
    path = root / IGNORE_FILE
    if not path.is_file():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line.rstrip("/"))
    return patterns


def is_excluded(rel: str, extra: list[str] = ()) -> bool:
    """rel is a POSIX path relative to the repo root."""
    parts = rel.split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return True
    name = parts[-1]
    if Path(name).suffix.lower() in BINARY_EXTENSIONS:
        return True
    for pat in list(SKIP_PATTERNS) + list(extra):
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel, pat) or rel.startswith(pat + "/"):
            return True
    return False


def list_files(root: Path, extra_ignores: list[str] | None = None) -> list[str]:
    """Files that are (or would be) committed: tracked + untracked-but-not-gitignored.
    Gitignored files (like a local .env) never reach GitHub, so they aren't leaks."""
    extra = list(extra_ignores or []) + load_ignore_patterns(root)
    rels: list[str] = []
    if is_git_repo(root):
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "-co", "--exclude-standard"],
                             capture_output=True, timeout=120)
        rels = [p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                rels.append(Path(dirpath, fn).relative_to(root).as_posix())
    return sorted(r for r in set(rels) if not is_excluded(r, extra) and (root / r).is_file())


def read_text(path: Path) -> str | None:
    """Text content, or None for binary/huge/unreadable files."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")
