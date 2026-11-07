"""Dockerfile checks: root user, secrets in ENV/ARG, unpinned base images, risky downloads."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from . import secrets as secret_rules
from .files import read_text
from .models import Finding, Severity

SECRET_NAME = re.compile(r"(?i)(pass(?:word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|"
                         r"credential|auth[_-]?key|client[_-]?secret)")
NOT_A_SECRET = re.compile(r"(?i)(_FILE|_PATH|_URL|_DIR|_ENDPOINT|_HOST|_NAME|_ID|_REGION|_TYPE|_HEADER)$")
PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/)?(?:ba|z|da|k)?sh\b")
ROOT_USERS = {"root", "0", "root:root", "0:0", "root:0", "0:root"}
DOCKERFILE_NAME = re.compile(r"(?i)^(?:dockerfile|containerfile)(?:\.[\w.-]+)?$|^[\w.-]+\.(?:dockerfile|containerfile)$")


@dataclass
class Instruction:
    cmd: str
    args: str
    line: int          # 1-based line where the instruction starts
    end: int           # 1-based last line
    stage: int


def parse(text: str) -> list[Instruction]:
    """Instructions with line-continuations joined, comments dropped and heredocs kept."""
    lines = text.splitlines()
    escape = "\\"
    for raw in lines[:5]:
        m = re.match(r"^\s*#\s*escape\s*=\s*([\\`])\s*$", raw)
        if m:
            escape = m.group(1)
        elif raw.strip() and not raw.lstrip().startswith("#"):
            break
    out: list[Instruction] = []
    stage = -1
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i
        parts = []
        while True:
            text = lines[i].rstrip()
            if text.strip().startswith("#") and i != start:      # comments inside continuations
                i += 1
                if i >= len(lines):
                    break
                continue
            if text.endswith(escape):
                parts.append(text[:-1])
                i += 1
                if i >= len(lines):
                    break
                continue
            parts.append(text)
            break
        joined = " ".join(p.strip() for p in parts)
        m = re.match(r"^([A-Za-z]+)\s*(.*)$", joined)
        i += 1
        if not m:
            continue
        cmd, args = m.group(1).upper(), m.group(2)
        heredoc = re.search(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?", args)
        if heredoc and cmd in ("RUN", "COPY"):
            term = heredoc.group(1)
            body = []
            while i < len(lines) and lines[i].strip() != term:
                body.append(lines[i])
                i += 1
            i += 1
            args = args + "\n" + "\n".join(body)
        if cmd == "FROM":
            stage += 1
        out.append(Instruction(cmd, args, start + 1, i, max(stage, 0)))
    return out


def _tokens(args: str) -> list[str]:
    try:
        return shlex.split(args, posix=True)
    except ValueError:
        return args.split()


def env_pairs(args: str) -> list[tuple[str, str]]:
    toks = _tokens(args)
    if toks and "=" not in toks[0]:                 # legacy form: ENV KEY value with spaces
        return [(toks[0], " ".join(toks[1:]))]
    return [tuple(t.split("=", 1)) for t in toks if "=" in t]


def image_of(args: str) -> tuple[str, str | None]:
    toks = [t for t in args.split() if not t.startswith("--")]
    image = toks[0] if toks else ""
    alias = toks[2] if len(toks) >= 3 and toks[1].lower() == "as" else None
    return image, alias


class DockerChecker:
    def __init__(self, rel: str, text: str, has_dockerignore: bool):
        self.rel, self.lines = rel, text.splitlines()
        self.instructions = parse(text)
        self.has_dockerignore = has_dockerignore
        self.findings: list[Finding] = []

    def line_text(self, n: int) -> str:
        return self.lines[n - 1] if 0 < n <= len(self.lines) else ""

    def add(self, rule, sev, title, ins: Instruction, description, fix, evidence=None, patch=None, details=None):
        self.findings.append(Finding(
            rule=f"container/{rule}", category="containers", severity=sev, title=title, file=self.rel,
            line=ins.line, description=description, fix=fix,
            evidence=(evidence if evidence is not None else self.line_text(ins.line)).strip()[:160],
            patch=patch, details=details or {}))

    def run(self) -> list[Finding]:
        stages: list[dict] = []
        names: set[str] = set()
        for ins in self.instructions:
            if ins.cmd == "FROM":
                image, alias = image_of(ins.args)
                stages.append({"from": ins, "image": image, "user": None, "user_ins": None, "cmd": None})
                self.check_base(ins, image, names)
                if alias:
                    names.add(alias.lower())
            elif not stages:
                if ins.cmd == "ARG":
                    self.check_secret_assignment(ins)
                continue
            elif ins.cmd == "USER":
                stages[-1]["user"] = ins.args.strip().split()[0] if ins.args.strip() else ""
                stages[-1]["user_ins"] = ins
            elif ins.cmd in ("CMD", "ENTRYPOINT"):
                stages[-1]["cmd"] = ins
            elif ins.cmd in ("ENV", "ARG"):
                self.check_secret_assignment(ins)
            elif ins.cmd == "RUN":
                self.check_run(ins)
            elif ins.cmd in ("ADD", "COPY"):
                self.check_copy(ins)
            elif ins.cmd == "EXPOSE":
                if re.search(r"(?<![\d])22(?:/tcp)?\b", ins.args):
                    self.add("ssh-exposed", Severity.LOW, "SSH port 22 is exposed", ins,
                             "Running an SSH server inside a container adds a long-lived, password- or key-protected "
                             "entry point that bypasses your orchestrator's access controls.",
                             "Remove the SSH server. Use `docker exec` / `kubectl exec` for debugging.")
        if stages:
            self.check_final_user(stages[-1])
        return self.findings

    # -- rules ---------------------------------------------------------------
    def check_base(self, ins: Instruction, image: str, names: set[str]) -> None:
        if not image or "$" in image or image.lower() in names or image.lower() == "scratch":
            return
        if "@sha256:" in image:
            return
        last = image.rsplit("/", 1)[-1]
        tag = last.split(":", 1)[1] if ":" in last else None
        if tag in (None, "latest"):
            shown = f"{image}" + ("" if tag else " (no tag)")
            self.add("unpinned-base-image", Severity.LOW, f"Base image `{image}` isn't pinned to a version", ins,
                     f"`{shown}` means whatever was pushed last. Rebuilds silently pick up new major versions "
                     "and you can't tell which OS packages (and CVEs) an image contains.",
                     f"Use a specific version tag, ideally with its digest: `FROM {image.split(':')[0]}:<version>@sha256:<digest>`. "
                     "Dependabot (package-ecosystem: docker) keeps both updated.",
                     details={"image": image, "tag": tag})

    def check_secret_assignment(self, ins: Instruction) -> None:
        raw = self.line_text(ins.line)
        if secret_rules.scan_line(raw, ins.line):
            return                                  # the secrets scanner already reports it precisely
        if ins.cmd == "ARG":
            toks = _tokens(ins.args)
            pairs = [(t.split("=", 1)[0], t.split("=", 1)[1] if "=" in t else None) for t in toks]
        else:
            pairs = env_pairs(ins.args)
        for key, value in pairs:
            if not SECRET_NAME.search(key) or NOT_A_SECRET.search(key):
                continue
            literal = value is not None and value.strip() != "" and not re.fullmatch(r"\$\{?\w+\}?", value.strip())
            if literal and secret_rules.is_placeholder(value, generic=False):
                literal = False
            masked = secret_rules.mask(value) if literal else None
            evidence = raw.replace(value, masked) if literal and value in raw else (raw if not literal else f"{ins.cmd} {key}=****")
            if ins.cmd == "ENV" and literal:
                self.add("secret-in-env", Severity.HIGH, f"Secret `{key}` is baked into the image with ENV", ins,
                         "ENV values are stored in the image config. Anyone who can pull the image reads them with "
                         "`docker inspect`, and they stay in every layer built on top.",
                         f"Remove it from the Dockerfile and pass it when the container starts "
                         f"(`docker run -e {key}` or your orchestrator's secret store).", evidence,
                         patch={"start": ins.line, "before": [evidence],
                                "after": [f"# {key} is injected at runtime (docker run -e {key} / secret store)"]},
                         details={"variable": key})
            elif ins.cmd == "ARG" and literal:
                self.add("secret-in-arg", Severity.HIGH, f"Secret `{key}` has a default value in ARG", ins,
                         "Build arguments are recorded in the image history (`docker history`), "
                         "so the default value ships with the image.",
                         f"Use a BuildKit secret instead: `RUN --mount=type=secret,id={key.lower()} …` and build with "
                         f"`docker build --secret id={key.lower()},env={key}`.", evidence,
                         patch={"start": ins.line, "before": [evidence],
                                "after": [f"# use: RUN --mount=type=secret,id={key.lower()} <command reading /run/secrets/{key.lower()}>"]},
                         details={"variable": key})
            elif ins.cmd == "ARG":
                self.add("secret-build-arg", Severity.LOW, f"Secret `{key}` is passed as a build argument", ins,
                         "Values passed with `--build-arg` end up in the image history even without a default.",
                         f"Switch to a BuildKit secret mount: `RUN --mount=type=secret,id={key.lower()} …`.",
                         details={"variable": key})

    def check_run(self, ins: Instruction) -> None:
        if PIPE_TO_SHELL.search(ins.args):
            self.add("pipe-to-shell", Severity.MEDIUM, "Remote script is piped straight into a shell", ins,
                     "Whatever the server returns at build time runs as root in your image, with no integrity check. "
                     "A compromised or hijacked URL compromises every image you build.",
                     "Download to a file, verify its checksum or signature, then run it.")
        if re.search(r"\bchmod\s+(?:-R\s+)?0?777\b", ins.args):
            self.add("world-writable", Severity.LOW, "Files are made world-writable (chmod 777)", ins,
                     "Any process in the container, including a compromised one, can modify these files.",
                     "Grant only what's needed, e.g. `chmod 755` for directories and `644` for files.")

    def check_copy(self, ins: Instruction) -> None:
        toks = [t for t in _tokens(ins.args.split("\n", 1)[0]) if not t.startswith("--")]
        flags = [t for t in ins.args.split() if t.startswith("--")]
        sources = toks[:-1]
        if ins.cmd == "ADD" and any(s.startswith(("http://", "https://")) for s in sources) \
                and not any(f.startswith("--checksum") for f in flags):
            self.add("add-remote-url", Severity.MEDIUM, "ADD downloads a remote file without a checksum", ins,
                     "The file is fetched at build time and trusted blindly. If the URL changes or is hijacked, "
                     "your image changes with it.",
                     "Add `--checksum=sha256:<hash>` to the ADD instruction, or download with curl and verify.")
        if any(s in (".", "./", "*") for s in sources) and not self.has_dockerignore and \
                not any(f.startswith("--from") for f in flags):
            self.add("copy-whole-context", Severity.LOW, "Whole build context is copied without a .dockerignore", ins,
                     "`COPY .` includes everything next to the Dockerfile: `.env` files, `.git` history, local "
                     "credentials. They end up inside the image.",
                     "Add a `.dockerignore` listing at least `.git`, `.env*`, `*.pem`, `node_modules`.",
                     patch={"start": 1, "before": [], "after": [".git", ".env*", "*.pem", "*.key", "node_modules", "__pycache__"],
                            "file": ".dockerignore"})

    def check_final_user(self, stage: dict) -> None:
        image = stage["image"].lower()
        if image == "scratch" or image.endswith(":nonroot") or ("distroless" in image and "nonroot" in image):
            return
        user = stage["user"]
        if user is not None and user.lower() not in ROOT_USERS:
            return
        anchor = stage["user_ins"] or stage["cmd"] or stage["from"]
        title = "Container runs as root" if user is None else "Container switches back to root"
        alpine = "alpine" in image
        add_user = ("RUN addgroup -S app && adduser -S -G app app" if alpine
                    else "RUN useradd --system --create-home --uid 10001 app")
        cmd_ins = stage["cmd"]
        if user is not None and stage["user_ins"]:
            patch = {"start": stage["user_ins"].line, "before": [self.line_text(stage["user_ins"].line)],
                     "after": [add_user, "USER app"]}
        elif cmd_ins:
            before = self.lines[cmd_ins.line - 1: cmd_ins.end]
            patch = {"start": cmd_ins.line, "before": before, "after": [add_user, "USER app"] + before}
        else:
            last = len(self.lines)
            patch = {"start": last, "before": [self.line_text(last)], "after": [self.line_text(last), add_user, "USER app"]}
        self.add("runs-as-root", Severity.MEDIUM, title, anchor,
                 ("The final stage never sets a non-root USER" if user is None else f"The final stage sets `USER {user}`")
                 + ", so the app runs as root inside the container (unless the base image sets its own user). "
                 "If it's compromised, a container escape bug or a mounted host path gives the attacker root.",
                 "Create an unprivileged user and switch to it before CMD/ENTRYPOINT.", patch=patch,
                 details={"base_image": stage["image"], "user": user})


def find_dockerfiles(files: list[str]) -> list[str]:
    return sorted(f for f in files if DOCKERFILE_NAME.match(f.rsplit("/", 1)[-1]))


def scan(root: Path, files: list[str]) -> tuple[list[Finding], dict, list[str]]:
    findings, notes = [], []
    targets = find_dockerfiles(files)
    present = set(files)
    for rel in targets:
        text = read_text(root / rel, root)
        if text is None:
            notes.append(f"Skipped {rel}: it's a symlink, binary or too large.")
            continue
        folder = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        ignore = (folder + ".dockerignore") in present or ".dockerignore" in present or \
            (root / (rel + ".dockerignore")).exists()
        findings += DockerChecker(rel, text, ignore).run()
    return findings, {"dockerfiles_scanned": len(targets)}, notes
