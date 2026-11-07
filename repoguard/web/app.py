"""Web UI: start a scan, stream its progress over Server-Sent Events, show the report.

Security posture (this server clones untrusted repositories and may receive GitHub tokens):
- binds to localhost by default and rejects unexpected Host headers (DNS rebinding);
- state-changing requests must be JSON from the same origin (blocks cross-site form posts);
- tokens live only in memory for the duration of one scan and are never logged or returned;
- the scanner never uses the server owner's git credentials or GITHUB_TOKEN;
- strict Content-Security-Policy; the frontend builds the DOM with textContent only.
"""
from __future__ import annotations

import json
import logging
import secrets as pysecrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .. import report
from ..github import GitHubError, InvalidRepoRef, check_token, parse_repo_ref
from ..pipeline import STEP_IDS, Cancelled, Context, Options, Progress, scan_github

log = logging.getLogger("repoguard.web")
STATIC = Path(__file__).parent / "static"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}
JOB_TTL = 30 * 60
MAX_JOBS = 100
HEARTBEAT = 15


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo: str = Field(min_length=1, max_length=300)
    token: str | None = Field(default=None, max_length=255)
    history: bool = True
    depth: int = Field(default=200, ge=1, le=1000)
    osv: bool = True
    resolve_pins: bool = True


@dataclass
class Job:
    id: str
    repo: str
    options: Options
    token: str | None
    created: float = field(default_factory=time.time)
    state: str = "queued"            # queued → running → succeeded | failed | cancelled
    events: list[dict] = field(default_factory=list)
    result: object | None = None
    error: dict | None = None
    cancel: threading.Event = field(default_factory=threading.Event)
    cond: threading.Condition = field(default_factory=threading.Condition)
    progress: Progress | None = None

    def push(self, event: dict) -> None:
        with self.cond:
            event = {**event, "seq": len(self.events) + 1}      # "id" is the step id; seq orders the stream
            self.events.append(event)
            self.cond.notify_all()

    @property
    def finished(self) -> bool:
        return self.state in ("succeeded", "failed", "cancelled")

    def summary(self) -> dict:
        return {"id": self.id, "repo": self.repo, "state": self.state, "error": self.error,
                "steps": self.progress.snapshot() if self.progress else [],
                "result": self.result.to_dict() if self.result is not None else None}


class JobStore:
    def __init__(self, max_running: int):
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.max_running = max_running

    def purge(self) -> None:
        now = time.time()
        with self.lock:
            for jid in [j.id for j in self.jobs.values() if j.finished and now - j.created > JOB_TTL]:
                del self.jobs[jid]
            while len(self.jobs) > MAX_JOBS:
                oldest = min((j for j in self.jobs.values() if j.finished), key=lambda j: j.created, default=None)
                if not oldest:
                    break
                del self.jobs[oldest.id]

    def running(self) -> int:
        return sum(1 for j in self.jobs.values() if not j.finished)

    def add(self, job: Job) -> bool:
        with self.lock:
            if self.running() >= self.max_running:
                return False
            self.jobs[job.id] = job
            return True

    def get(self, jid: str) -> Job | None:
        return self.jobs.get(jid)


def error_payload(code: str, message: str, hint: str | None = None, status: int = 400, **extra) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message, "hint": hint, **extra}}, status_code=status)


def create_app(*, allowed_hosts: list[str] | None = None, max_running: int = 2,
               scan_fn=scan_github, client_factory=None, osv_factory=None, pin_resolver=None,
               max_repo_kb: int = 512_000, clone_timeout: float = 180, history_budget: float = 90) -> FastAPI:
    app = FastAPI(title="RepoGuard", docs_url=None, redoc_url=None, openapi_url=None)
    store = JobStore(max_running)
    hosts = {h.lower() for h in (allowed_hosts or ["127.0.0.1", "localhost", "[::1]", "testserver"])}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = (request.headers.get("host") or "").lower()
        hostname = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        if hostname not in hosts:
            return Response("Unknown host", status_code=400, media_type="text/plain")
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            if origin and origin.split("://", 1)[-1].lower() != host:
                return error_payload("cross_origin", "Requests from other sites aren't allowed.", status=403)
            if not (request.headers.get("content-type") or "").startswith("application/json"):
                return error_payload("bad_content_type", "Send JSON.", status=415)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_body(request: Request, exc: RequestValidationError):
        first = (exc.errors() or [{}])[0]
        field_name = ".".join(str(x) for x in first.get("loc", [])[1:]) or "request"
        return error_payload("invalid_request", f"Invalid value for {field_name}: {first.get('msg', 'invalid')}.", status=422)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.error("unhandled error on %s: %s", request.url.path, type(exc).__name__)
        return error_payload("internal", "Something went wrong on the server.", status=500)

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html", media_type="text/html; charset=utf-8")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/api/health")
    def health():
        return {"ok": True, "running": store.running()}

    def run(job: Job) -> None:
        progress = Progress(STEP_IDS, job.push)
        job.progress = progress
        job.state = "running"
        job.push({"type": "state", "state": "running"})
        ctx = Context(progress=progress, cancel=job.cancel,
                      osv_client=osv_factory() if osv_factory else None, pin_resolver=pin_resolver)
        token, job.token = job.token, None
        try:
            ref = parse_repo_ref(job.repo)
            client = client_factory(token) if client_factory else None
            kwargs = {"token": token}
            if client is not None:
                kwargs["client"] = client
            job.result = scan_fn(ref, job.options, ctx, **kwargs)
            job.state = "succeeded"
            job.push({"type": "result", "result": job.result.to_dict()})
        except GitHubError as exc:
            job.error = exc.to_dict()
            job.state = "failed"
            progress.cancel_rest()
            job.push({"type": "error", "error": job.error})
        except Cancelled:
            job.error = {"code": "cancelled", "message": "Scan cancelled.", "hint": None}
            job.state = "cancelled"
            progress.cancel_rest()
            job.push({"type": "error", "error": job.error})
        except Exception as exc:     # never leak internals (or the token) to the client
            log.exception("scan %s failed: %s", job.id, type(exc).__name__)
            job.error = {"code": "internal", "message": "The scan failed unexpectedly.",
                         "hint": "Try again. If it keeps happening, run the CLI to see details."}
            job.state = "failed"
            try:
                running = progress.current
                if running:
                    progress.fail(running, "unexpected error")
                progress.cancel_rest()
            except Exception:
                pass
            job.push({"type": "error", "error": job.error})
        finally:
            del token

    @app.post("/api/scans", status_code=202)
    def start(body: ScanRequest):
        store.purge()
        try:
            ref = parse_repo_ref(body.repo)
            token = check_token(body.token)
        except InvalidRepoRef as exc:
            return error_payload("invalid_repo", str(exc), status=422)
        except GitHubError as exc:
            return error_payload(exc.code, exc.message, exc.hint, status=422)
        opts = Options(history=body.history, max_commits=body.depth, osv=body.osv, resolve_pins=body.resolve_pins,
                       max_repo_kb=max_repo_kb, clone_timeout=clone_timeout, history_time_budget=history_budget)
        job = Job(id=pysecrets.token_urlsafe(16), repo=ref.slug, options=opts, token=token)
        if not store.add(job):
            return error_payload("busy", f"{store.max_running} scans are already running.",
                                 "Wait for one to finish, then try again.", status=429)
        threading.Thread(target=run, args=(job,), name=f"scan-{job.id[:6]}", daemon=True).start()
        return {"id": job.id, "repo": ref.slug, "events": f"/api/scans/{job.id}/events"}

    def find(jid: str) -> Job | None:
        return store.get(jid) if len(jid) <= 64 else None

    @app.get("/api/scans/{jid}")
    def status(jid: str):
        job = find(jid)
        if not job:
            return error_payload("unknown_scan", "That scan doesn't exist or has expired.", status=404)
        return job.summary()

    @app.post("/api/scans/{jid}/cancel", status_code=202)
    def cancel(jid: str):
        job = find(jid)
        if not job:
            return error_payload("unknown_scan", "That scan doesn't exist or has expired.", status=404)
        job.cancel.set()
        return {"ok": True, "state": job.state}

    @app.get("/api/scans/{jid}/events")
    def events(jid: str, request: Request):
        job = find(jid)
        if not job:
            return error_payload("unknown_scan", "That scan doesn't exist or has expired.", status=404)
        try:
            last = int(request.headers.get("last-event-id") or 0)
        except ValueError:
            last = 0

        def stream():
            sent = last
            yield "retry: 3000\n\n"
            while True:
                with job.cond:
                    if len(job.events) <= sent and not job.finished:
                        job.cond.wait(timeout=HEARTBEAT)
                    batch = job.events[sent:]
                    done = job.finished
                if not batch:
                    if done:
                        return
                    yield ": keep-alive\n\n"
                    continue
                for event in batch:
                    sent = event["seq"]
                    yield f"id: {event['seq']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
                if done and sent >= len(job.events):
                    return

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.get("/api/scans/{jid}/report.{fmt}")
    def download(jid: str, fmt: str):
        job = find(jid)
        if not job or job.result is None:
            return error_payload("unknown_scan", "No finished report for that scan.", status=404)
        writers = {"json": (report.to_json, "application/json"), "md": (report.markdown, "text/markdown"),
                   "html": (report.html_report, "text/html")}
        if fmt not in writers:
            return error_payload("bad_format", "Use json, md or html.", status=404)
        fn, media = writers[fmt]
        name = job.repo.replace("/", "-") + f"-repoguard.{fmt}"
        return Response(fn(job.result), media_type=f"{media}; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    app.state.store = store
    return app
