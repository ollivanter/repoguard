import json
import threading
import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from repoguard.github import GitHubError  # noqa: E402
from repoguard.models import Finding, ScanResult, Severity  # noqa: E402
from repoguard.web.app import create_app  # noqa: E402

from conftest import TOKENS  # noqa: E402

JSON = {"Content-Type": "application/json"}


def fake_scan(ref, opts, ctx, token=None, **_):
    p = ctx.progress
    p.start("validate", ref.slug)
    p.done("validate", ref.slug)
    p.emit({"type": "rate", "limit": 60, "remaining": 58, "reset": 0, "authenticated": bool(token)})
    for sid in ("metadata", "clone", "secrets", "history", "dependencies", "osv", "workflows", "containers", "pins", "score"):
        ctx.check()
        p.start(sid)
        p.done(sid, "ok")
    r = ScanResult(target=ref.slug, repo=ref.slug, scanned_at="now")
    r.findings = [Finding(rule="workflow/x", title="<img src=x onerror=alert(1)>", severity=Severity.HIGH, category="workflows",
                          file=".github/workflows/a.yml", line=3)]
    r.score, r.grade = 88, "B"
    return r


def make(scan=fake_scan, **kw):
    return TestClient(create_app(scan_fn=scan, **kw))


def events(client, jid):
    with client.stream("GET", f"/api/scans/{jid}/events") as resp:
        assert resp.headers["content-type"].startswith("text/event-stream")
        out = []
        for line in resp.iter_lines():
            if line.startswith("data: "):
                out.append(json.loads(line[6:]))
        return out


def test_index_and_security_headers():
    c = make()
    r = c.get("/")
    assert r.status_code == 200 and "Find the leak" in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["referrer-policy"] == "no-referrer"
    assert c.get("/static/app.js").status_code == 200
    assert c.get("/static/../app.py").status_code == 404


def test_rejects_unknown_host_header():
    c = make()
    assert c.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert c.get("/api/health", headers={"Host": "localhost:8000"}).status_code == 200


def test_post_requires_json_and_same_origin():
    c = make()
    r = c.post("/api/scans", content="repo=a/b", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415
    r = c.post("/api/scans", json={"repo": "a/b"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "cross_origin"


@pytest.mark.parametrize("body,code", [
    ({"repo": "https://gitlab.com/a/b"}, "invalid_repo"),
    ({"repo": "not a repo"}, "invalid_repo"),
    ({"repo": "a/b", "token": "hunter2"}, "bad_token_format"),
    ({"repo": "a/b", "depth": 5000}, "invalid_request"),
    ({"repo": "a/b", "extra": 1}, "invalid_request"),
])
def test_validation_errors(body, code):
    r = make().post("/api/scans", json=body)
    assert r.status_code == 422 and r.json()["error"]["code"] == code


def test_full_scan_streams_events_and_result():
    c = make()
    r = c.post("/api/scans", json={"repo": "https://github.com/me/app/tree/main", "token": TOKENS["github-token"]()})
    assert r.status_code == 202
    body = r.json()
    assert body["repo"] == "me/app" and len(body["id"]) >= 20 and "token" not in json.dumps(body)
    evs = events(c, body["id"])
    types = [e["type"] for e in evs]
    assert types[0] == "state" and types[-1] == "result" and "rate" in types
    assert [e["seq"] for e in evs] == list(range(1, len(evs) + 1))
    assert evs[-1]["result"]["score"] == 88
    rate = next(e for e in evs if e["type"] == "rate")
    assert rate["authenticated"] is True
    status = c.get(f"/api/scans/{body['id']}").json()
    assert status["state"] == "succeeded" and all(s["state"] == "done" for s in status["steps"])
    assert TOKENS["github-token"]() not in json.dumps(status)


def test_resume_with_last_event_id():
    c = make()
    jid = c.post("/api/scans", json={"repo": "me/app"}).json()["id"]
    all_events = events(c, jid)
    with c.stream("GET", f"/api/scans/{jid}/events", headers={"Last-Event-ID": "5"}) as resp:
        ids = [json.loads(l[6:])["seq"] for l in resp.iter_lines() if l.startswith("data: ")]
    assert ids == [e["seq"] for e in all_events if e["seq"] > 5]


def test_downloads():
    c = make()
    jid = c.post("/api/scans", json={"repo": "me/app"}).json()["id"]
    events(c, jid)
    md = c.get(f"/api/scans/{jid}/report.md")
    assert md.status_code == 200 and "attachment" in md.headers["content-disposition"] and "&lt;img" in md.text
    html = c.get(f"/api/scans/{jid}/report.html")
    assert "<img src=x onerror" not in html.text and "\\u003cimg" in html.text
    assert c.get(f"/api/scans/{jid}/report.exe").status_code == 404
    assert c.get("/api/scans/nope/report.md").status_code == 404


def test_github_errors_become_error_events():
    def failing(ref, opts, ctx, token=None, **_):
        ctx.progress.start("validate")
        ctx.progress.done("validate")
        ctx.progress.start("metadata")
        ctx.progress.fail("metadata", "nope")
        raise GitHubError("rate_limited", "Limit hit.", status=403, retry_at=time.time() + 60, hint="Add a token.")
    c = make(failing)
    jid = c.post("/api/scans", json={"repo": "me/app"}).json()["id"]
    evs = events(c, jid)
    err = evs[-1]
    assert err["type"] == "error" and err["error"]["code"] == "rate_limited" and err["error"]["retry_at"]
    states = {e["id"]: e["state"] for e in evs if e["type"] == "step"}
    assert states["metadata"] == "failed" and states["clone"] == "cancelled"


def test_unexpected_errors_do_not_leak_details():
    tok = TOKENS["github-token"]()

    def boom(ref, opts, ctx, token=None, **_):
        raise RuntimeError(f"internal path /srv/x with {token}")
    c = make(boom)
    jid = c.post("/api/scans", json={"repo": "me/app", "token": tok}).json()["id"]
    err = events(c, jid)[-1]["error"]
    assert err["code"] == "internal" and "/srv" not in json.dumps(err) and tok not in json.dumps(err)


def test_cancel_and_capacity():
    gate = threading.Event()

    def slow(ref, opts, ctx, token=None, **_):
        ctx.progress.start("validate")
        while not gate.is_set():
            ctx.check()
            time.sleep(0.01)
        return fake_scan(ref, opts, ctx)
    c = make(slow, max_running=1)
    jid = c.post("/api/scans", json={"repo": "me/app"}).json()["id"]
    busy = c.post("/api/scans", json={"repo": "me/other"})
    assert busy.status_code == 429 and busy.json()["error"]["code"] == "busy"
    assert c.post(f"/api/scans/{jid}/cancel", json={}).status_code == 202
    err = events(c, jid)[-1]
    assert err["type"] == "error" and err["error"]["code"] == "cancelled"
    assert c.post("/api/scans", json={"repo": "me/other"}).status_code == 202   # slot is free again
    gate.set()


def test_unknown_scan_ids():
    c = make()
    assert c.get("/api/scans/does-not-exist").status_code == 404
    assert c.get("/api/scans/" + "x" * 200).status_code == 404
    assert c.post("/api/scans/nope/cancel", json={}).status_code == 404
    assert c.get("/api/scans/nope/events").status_code == 404
