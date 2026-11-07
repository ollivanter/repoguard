import textwrap

from repoguard import docker
from repoguard.models import Severity

from conftest import TOKENS


def check(text, ignore=False, rel="Dockerfile"):
    return docker.DockerChecker(rel, textwrap.dedent(text).lstrip(), ignore).run()


def rules(findings):
    return sorted(f.rule.split("/")[1] for f in findings)


def test_parser_joins_continuations_and_heredocs():
    ins = docker.parse(textwrap.dedent("""
        # syntax=docker/dockerfile:1
        FROM python:3.12-slim AS build
        RUN apt-get update && \\
            # comment inside a continuation
            apt-get install -y curl
        RUN <<EOF
        echo one
        echo two
        EOF
        FROM build
        CMD ["python", "app.py"]
    """).lstrip())
    assert [(i.cmd, i.line, i.stage) for i in ins] == [("FROM", 2, 0), ("RUN", 3, 0), ("RUN", 6, 0), ("FROM", 10, 1), ("CMD", 11, 1)]
    assert "apt-get install -y curl" in ins[1].args and "comment" not in ins[1].args
    assert "echo two" in ins[2].args


def test_clean_dockerfile():
    f = check("""
        FROM python:3.12-slim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS base
        WORKDIR /app
        COPY . .
        RUN useradd --uid 10001 app
        USER app
        ENV PASSWORD_FILE=/run/secrets/db
        CMD ["python", "app.py"]
    """, ignore=True)
    assert f == []


def test_runs_as_root_with_patch_before_cmd():
    f = check("""
        FROM node:20-alpine
        WORKDIR /app
        COPY package*.json ./
        CMD ["node", "server.js"]
    """, ignore=True)
    assert rules(f) == ["runs-as-root"]
    root = f[0]
    assert root.severity == Severity.MEDIUM and root.line == 4
    assert root.patch["after"] == ["RUN addgroup -S app && adduser -S -G app app", "USER app", 'CMD ["node", "server.js"]']


def test_switching_back_to_root_and_multistage():
    f = check("""
        FROM golang:1.22 AS build
        RUN go build -o /out/app
        FROM debian:12-slim
        USER nobody
        USER root
        CMD ["/app"]
    """, ignore=True)
    assert rules(f) == ["runs-as-root"]
    assert f[0].title == "Container switches back to root" and f[0].line == 5


def test_build_stage_user_does_not_count():
    f = check("""
        FROM golang:1.22 AS build
        USER builder
        FROM scratch
        COPY --from=build /out/app /app
    """)
    assert f == []


def test_secrets_in_env_and_arg_are_masked():
    f = check("""
        FROM python:3.12
        ARG NPM_TOKEN
        ARG API_KEY=Zq7XvB2mK9pLw4Rt8Ny3
        ENV DB_PASSWORD=S3cr3tP4ss! LOG_LEVEL=info
        ENV AWS_REGION=eu-west-1 SECRET_NAME=prod/db
        USER app
    """)
    assert rules(f) == ["secret-build-arg", "secret-in-arg", "secret-in-env"]
    env = next(x for x in f if x.rule.endswith("secret-in-env"))
    assert env.severity == Severity.HIGH and "S3cr3tP4ss!" not in env.evidence and "S3" in env.evidence
    assert "S3cr3tP4ss!" not in "".join(env.patch["before"] + env.patch["after"])
    arg = next(x for x in f if x.rule.endswith("secret-in-arg"))
    assert "Zq7XvB2mK9pLw4Rt8Ny3" not in arg.evidence


def test_specific_token_in_env_left_to_secret_scanner():
    f = check(f"""
        FROM python:3.12
        ENV GITHUB_TOKEN={TOKENS['github-token']()}
        USER app
    """)
    assert f == []


def test_unpinned_base_images():
    f = check("""
        FROM ubuntu
        FROM node:latest AS web
        FROM python:3.12
        FROM web
        FROM ${BASE_IMAGE}
        USER app
    """)
    assert [x.title for x in f] == ["Base image `ubuntu` isn't pinned to a version", "Base image `node:latest` isn't pinned to a version"]


def test_risky_downloads_and_permissions():
    f = check("""
        FROM debian:12
        RUN curl -fsSL https://get.example.sh | bash
        RUN wget -qO- https://x.example/install.sh | sudo sh
        ADD https://example.com/tool.tgz /opt/
        ADD --checksum=sha256:abc https://example.com/ok.tgz /opt/
        RUN chmod -R 777 /app
        EXPOSE 22 8080
        USER app
    """, ignore=True)
    assert rules(f) == ["add-remote-url", "pipe-to-shell", "pipe-to-shell", "ssh-exposed", "world-writable"]


def test_copy_context_without_dockerignore():
    f = check("""
        FROM python:3.12
        COPY . /app
        COPY --from=build /x /x
        USER app
    """)
    assert rules(f) == ["copy-whole-context"]
    assert f[0].patch["file"] == ".dockerignore" and ".env*" in f[0].patch["after"]


def test_scan_finds_dockerfiles_and_dockerignore(tmp_path):
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "Dockerfile").write_text("FROM python:3.12\nCOPY . .\nUSER app\n")
    (tmp_path / "svc" / ".dockerignore").write_text(".git\n")
    (tmp_path / "web.Dockerfile").write_text("FROM node\n")
    files = ["svc/Dockerfile", "svc/.dockerignore", "web.Dockerfile", "README.md"]
    findings, stats, notes = docker.scan(tmp_path, files)
    assert stats["dockerfiles_scanned"] == 2
    assert sorted(f.rule for f in findings) == ["container/runs-as-root", "container/unpinned-base-image"]
