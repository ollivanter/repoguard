/* RepoGuard UI. Every piece of scan data is inserted with textContent / DOM nodes, never innerHTML:
   file names, code lines, advisory text and commit messages all come from untrusted repositories. */
(() => {
  "use strict";

  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const CATEGORY_NAMES = { secrets: "Secrets", dependencies: "Dependencies", workflows: "Workflows", containers: "Containers" };
  const GRADE_COLOR = { A: "var(--secure)", B: "#9fdc8a", C: "var(--medium)", D: "var(--warn)", F: "var(--critical)" };
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /* ------------------------------------------------------------- DOM helpers */
  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    if (props) {
      for (const [key, value] of Object.entries(props)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === "class") el.className = value;
        else if (key === "text") el.textContent = String(value);
        else if (key === "style") for (const [p, v] of Object.entries(value)) el.style.setProperty(p, v);
        else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
        else if (key === "href") { const safe = safeUrl(value); if (safe) el.setAttribute("href", safe); }
        else el.setAttribute(key, value === true ? "" : String(value));
      }
    }
    append(el, children);
    return el;
  }
  function append(el, children) {
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }
  function safeUrl(value) {
    try {
      const url = new URL(String(value), window.location.href);
      if (url.protocol === "https:" || (url.origin === window.location.origin && url.protocol !== "javascript:")) return url.href;
    } catch (_) { /* fall through */ }
    return null;
  }
  /* `code` spans → <code>; everything else stays text. */
  function rich(text) {
    const frag = document.createDocumentFragment();
    String(text || "").split("`").forEach((part, i) => frag.append(i % 2 ? h("code", null, part) : document.createTextNode(part)));
    return frag;
  }
  const plural = (n, word, many) => `${n} ${n === 1 ? word : (many || word + "s")}`;
  const fmtMs = (ms) => { const s = ms / 1000; const m = Math.floor(s / 60); return `${String(m).padStart(2, "0")}:${(s - m * 60).toFixed(1).padStart(4, "0")}`; };
  const clockTime = (epoch) => new Date(epoch * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const shortSha = (sha) => (sha || "").slice(0, 7);

  /* ------------------------------------------------------------------ state */
  const state = {
    phase: "idle", job: null, es: null, steps: new Map(), result: null, meta: null, rate: null,
    startedAt: 0, clockTimer: null, live: true,
    filters: { sev: new Set(SEVERITIES), category: "all", q: "", file: null },
    tab: "findings", open: new Set(), lastRequest: null,
    options: { history: true, osv: true, resolve_pins: true },
  };

  /* ------------------------------------------------------------- navigation */
  function setNavReport(enabled) {
    $$('[data-nav="report"]').forEach((a) => {
      a.setAttribute("aria-disabled", enabled ? "false" : "true");
      if (enabled) a.removeAttribute("tabindex"); else a.setAttribute("tabindex", "-1");
    });
  }
  function initNavSpy() {
    const links = $$(".nav a[data-nav]");
    if (!("IntersectionObserver" in window) || !links.length) return;
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (!e.isIntersecting) return;
        links.forEach((a) => a.setAttribute("aria-current", a.dataset.nav === e.target.id ? "true" : "false"));
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    ["audit", "report", "method"].forEach((id) => { const el = document.getElementById(id); if (el) io.observe(el); });
  }

  /* ----------------------------------------------------------------- drawer */
  function initDrawer() {
    const drawer = $("#drawer"), openBtn = $("[data-drawer-open]"), backdrop = $(".drawer-backdrop");
    if (!drawer || !openBtn) return;
    let lastFocus = null;
    const open = () => {
      lastFocus = document.activeElement;
      backdrop.hidden = false;
      drawer.removeAttribute("inert"); drawer.setAttribute("aria-hidden", "false");
      openBtn.setAttribute("aria-expanded", "true"); document.body.classList.add("locked");
      requestAnimationFrame(() => {
        drawer.classList.add("open"); backdrop.classList.add("open");
        // focus once the drawer is visible; hidden elements can't take focus
        requestAnimationFrame(() => { const first = $("nav a:not([aria-disabled='true'])", drawer); if (first) first.focus(); });
      });
    };
    const close = (restore = true) => {
      drawer.classList.remove("open"); backdrop.classList.remove("open");
      drawer.setAttribute("inert", ""); drawer.setAttribute("aria-hidden", "true");
      openBtn.setAttribute("aria-expanded", "false"); document.body.classList.remove("locked");
      setTimeout(() => { if (!drawer.classList.contains("open")) backdrop.hidden = true; }, 400);
      if (restore && lastFocus) lastFocus.focus();
    };
    openBtn.addEventListener("click", () => (drawer.classList.contains("open") ? close() : open()));
    $$("[data-drawer-close]").forEach((b) => b.addEventListener("click", () => close()));
    $$("nav a", drawer).forEach((a) => a.addEventListener("click", () => close(false)));
    document.addEventListener("keydown", (e) => {
      if (!drawer.classList.contains("open")) return;
      if (e.key === "Escape") { e.preventDefault(); close(); }
      else if (e.key === "Tab") trapFocus(e, drawer);
    });
    window.matchMedia("(min-width: 881px)").addEventListener("change", (m) => { if (m.matches && drawer.classList.contains("open")) close(false); });
  }
  function trapFocus(e, container) {
    const items = $$('a[href]:not([aria-disabled="true"]), button:not([disabled]), input, select, [tabindex="0"]', container).filter((el) => el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  /* ------------------------------------------------------------------ modal */
  function initModals() {
    const backdrop = $("[data-modal-backdrop]");
    let current = null, lastFocus = null;
    const close = () => {
      if (!current) return;
      current.hidden = true; backdrop.hidden = true; document.body.classList.remove("locked");
      current.removeEventListener("keydown", onKey); current = null;
      if (lastFocus) lastFocus.focus();
    };
    const onKey = (e) => { if (e.key === "Escape") { e.preventDefault(); close(); } else if (e.key === "Tab") trapFocus(e, current); };
    $$("[data-modal-open]").forEach((btn) => btn.addEventListener("click", () => {
      const modal = document.getElementById(btn.dataset.modalOpen);
      if (!modal) return;
      lastFocus = btn; current = modal;
      backdrop.hidden = false; modal.hidden = false; document.body.classList.add("locked");
      modal.addEventListener("keydown", onKey);
      const focusable = $("button, a[href], input", modal); if (focusable) focusable.focus();
    }));
    $$("[data-modal-close]").forEach((b) => b.addEventListener("click", close));
    if (backdrop) backdrop.addEventListener("click", close);
  }

  /* ------------------------------------------------------- proximity glow */
  function initGlow() {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || window.matchMedia("(hover: none)").matches) return;
    let x = -9999, y = -9999, queued = false;
    const update = () => {
      queued = false;
      for (const el of $$("[data-glow]")) {
        const r = el.getBoundingClientRect();
        if (r.bottom < -200 || r.top > window.innerHeight + 200) continue;
        const dx = Math.max(r.left - x, 0, x - r.right), dy = Math.max(r.top - y, 0, y - r.bottom);
        const dist = Math.hypot(dx, dy);
        el.style.setProperty("--mx", `${x - r.left}px`);
        el.style.setProperty("--my", `${y - r.top}px`);
        el.style.setProperty("--glow", String(Math.max(0, 1 - dist / 140).toFixed(3)));
      }
    };
    document.addEventListener("pointermove", (e) => { x = e.clientX; y = e.clientY; if (!queued) { queued = true; requestAnimationFrame(update); } }, { passive: true });
    document.addEventListener("pointerleave", () => { x = y = -9999; requestAnimationFrame(update); });
  }

  /* ------------------------------------------------------------------- form */
  function initForm() {
    const form = $("#scan-form");
    if (!form) return;
    const repo = $("#repo"), token = $("#token");
    const disclosure = $("[data-disclosure]"), options = $("#options");
    disclosure.addEventListener("click", () => {
      const open = disclosure.getAttribute("aria-expanded") !== "true";
      disclosure.setAttribute("aria-expanded", String(open)); options.hidden = !open;
      if (open) token.focus();
    });
    const reveal = $("[data-reveal]");
    reveal.addEventListener("click", () => {
      const show = token.type === "password";
      token.type = show ? "text" : "password";
      reveal.setAttribute("aria-pressed", String(show)); reveal.textContent = show ? "Hide" : "Show";
    });
    $$("[data-switch]", form).forEach((sw) => {
      const toggle = () => {
        const on = sw.getAttribute("aria-checked") !== "true";
        sw.setAttribute("aria-checked", String(on));
        state.options[sw.dataset.switch] = on;
        if (sw.dataset.switch === "history") { $("[data-depth-field]").hidden = !on; }
      };
      sw.addEventListener("click", toggle);
      sw.addEventListener("keydown", (e) => { if (e.key === " " || e.key === "Enter") { e.preventDefault(); toggle(); } });
    });
    repo.addEventListener("input", () => setFieldError(null));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const value = repo.value.trim();
      const problem = validateRepo(value);
      if (problem) { setFieldError(problem); repo.focus(); return; }
      startScan({
        repo: value, token: token.value.trim() || null, history: state.options.history,
        depth: Number($("#depth").value), osv: state.options.osv, resolve_pins: state.options.resolve_pins,
      });
    });
  }
  function validateRepo(value) {
    if (!value) return "Enter a repository, like owner/name.";
    if (/\s/.test(value)) return "Repository names can't contain spaces.";
    const host = value.match(/^(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})\//i);
    if (host && host[1].toLowerCase() !== "github.com") return `Only github.com repositories are supported, not ${host[1]}.`;
    const ok = /^(?:(?:https?:\/\/)?(?:www\.)?github\.com\/|git@github\.com:)?[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}\/[A-Za-z0-9._-]{1,100}(?:\.git)?(?:\/.*)?$/.test(value.split(/[?#]/)[0]);
    return ok ? null : "That doesn't look like a GitHub repository. Use owner/name or a github.com link.";
  }
  function setFieldError(message) {
    const el = $("#repo-error"), wrap = $(".repo-input"), input = $("#repo");
    if (!el) return;
    el.textContent = message || ""; el.hidden = !message;
    wrap.classList.toggle("invalid", !!message);
    if (message) input.setAttribute("aria-invalid", "true"); else input.removeAttribute("aria-invalid");
  }

  /* --------------------------------------------------------------- scanning */
  async function startScan(body) {
    if (state.phase === "running") return;
    state.lastRequest = { ...body, token: null };
    setRunning(true);
    resetProgress(body.repo);
    show("progress");
    let res, data;
    try {
      res = await fetch("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), credentials: "same-origin" });
      data = await res.json().catch(() => ({}));
    } catch (_) {
      return fail({ code: "server_unreachable", message: "Couldn't reach the RepoGuard server.", hint: "Is `repoguard serve` still running?" });
    }
    if (!res.ok) {
      const err = (data && data.error) || { code: "internal", message: `The server answered ${res.status}.` };
      if (err.code === "invalid_repo") { setRunning(false); show("audit-only"); setFieldError(err.message); $("#repo").focus(); return; }
      return fail(err);
    }
    state.job = data.id;
    $("[data-progress-repo]").textContent = data.repo;
    log(`job ${data.id.slice(0, 8)} accepted for ${data.repo}`, "dim");
    listen(data.events);
  }

  function listen(url) {
    const es = new EventSource(url);
    state.es = es;
    es.onmessage = (msg) => {
      let event;
      try { event = JSON.parse(msg.data); } catch (_) { return; }
      handleEvent(event);
    };
    es.onerror = () => {
      if (state.phase !== "running") return;
      if (es.readyState === EventSource.CLOSED) recover();
      else log("connection interrupted, reconnecting…", "warn");
    };
  }

  async function recover() {
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(state.job)}`);
      const data = await res.json();
      if (res.ok && data.result) return finish(data.result);
      if (res.ok && data.error) return fail(data.error);
    } catch (_) { /* fall through */ }
    fail({ code: "connection_lost", message: "Lost the connection to the scanner before the scan finished.", hint: "Run the audit again." });
  }

  function handleEvent(e) {
    switch (e.type) {
      case "step": return updateStep(e);
      case "log": return log(e.text, e.level === "error" ? "err" : e.level === "warn" ? "warn" : "");
      case "meta": state.meta = e.repo; log(`${e.repo.full_name}: ${e.repo.visibility}, ${e.repo.size_kb < 1024 ? `${e.repo.size_kb} KB` : `${(e.repo.size_kb / 1024).toFixed(1)} MB`}, default branch ${e.repo.default_branch}`, "dim"); return;
      case "rate": return setRate(e);
      case "result": return finish(e.result);
      case "error": return fail(e.error);
      default: return;
    }
  }

  function closeStream() { if (state.es) { state.es.close(); state.es = null; } }

  function setRunning(on) {
    state.phase = on ? "running" : state.phase === "running" ? "idle" : state.phase;
    const btn = $("[data-run]");
    if (btn) { btn.disabled = on; btn.firstElementChild.textContent = on ? "Scanning…" : "Run audit"; }
    clearInterval(state.clockTimer);
    if (on) {
      state.startedAt = performance.now();
      state.clockTimer = setInterval(tick, 100);
    }
  }
  function tick() {
    const clock = $("[data-clock]");
    if (clock) clock.textContent = fmtMs(performance.now() - state.startedAt);
    for (const [, step] of state.steps) {
      if (step.state === "running" && step.el) step.el.querySelector(".ms").textContent = fmtMs(performance.now() - step.t0);
    }
  }

  function resetProgress(repo) {
    closeStream();
    state.steps.clear(); state.job = null; state.result = null; state.meta = null; state.open.clear();
    $("[data-progress-repo]").textContent = repo;
    const list = $("[data-steps]"); list.replaceChildren();
    $("[data-log]").replaceChildren();
    $("[data-progress-fill]").style.width = "0%";
    $(".progress-bar").setAttribute("aria-valuenow", "0");
    const cancel = $("[data-cancel]"); cancel.disabled = false; cancel.textContent = "Cancel";
    log(`$ repoguard scan ${repo}`, "");
  }

  function updateStep(e) {
    let step = state.steps.get(e.id);
    if (!step) {
      const el = h("li", { "data-state": "pending" },
        h("span", { class: "marker", "aria-hidden": "true" }),
        h("span", null, h("span", { class: "label", text: e.label }), h("span", { class: "detail" })),
        h("span", { class: "ms" }));
      $("[data-steps]").append(el);
      step = { el, state: "pending", t0: performance.now() };
      state.steps.set(e.id, step);
    }
    const prev = step.state;
    step.state = e.state;
    step.el.dataset.state = e.state;
    step.el.querySelector(".detail").textContent = e.detail || "";
    if (e.state === "running") {
      step.t0 = performance.now();
      log(`▸ ${e.label}${e.detail ? ` (${e.detail})` : ""}`, "");
      announce(`${e.label}…`);
    } else {
      step.el.querySelector(".ms").textContent = e.ms != null && prev === "running" ? `${(e.ms / 1000).toFixed(1)}s` : "";
      if (e.state === "done") log(`  ✓ ${e.detail || "done"}`, "ok");
      if (e.state === "failed") log(`  ✗ ${e.label}: ${e.detail}`, "err");
      if (e.state === "skipped") log(`  – ${e.label.toLowerCase()} skipped: ${e.detail}`, "dim");
    }
    const all = state.steps.size || 1;
    const finished = [...state.steps.values()].filter((s) => !["pending", "running"].includes(s.state)).length;
    const pct = Math.round((finished / Math.max(all, 11)) * 100);
    $("[data-progress-fill]").style.width = `${pct}%`;
    $(".progress-bar").setAttribute("aria-valuenow", String(pct));
  }

  function log(text, cls) {
    const box = $("[data-log]");
    if (!box) return;
    const elapsed = state.startedAt ? fmtMs(performance.now() - state.startedAt) : "00:00.0";
    $$(".cursor", box).forEach((c) => c.classList.remove("cursor"));
    const line = h("p", null, h("span", { class: "t", text: elapsed }), h("span", { class: `${cls || ""} cursor`, text }));
    const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    box.append(line);
    if (box.childElementCount > 500) box.firstElementChild.remove();
    if (stick) box.scrollTop = box.scrollHeight;
  }
  function announce(text) { const el = $("[data-announce]"); if (el) el.textContent = text; }

  function initCancel() {
    const btn = $("[data-cancel]");
    if (!btn) return;
    btn.addEventListener("click", async () => {
      if (!state.job || state.phase !== "running") return;
      btn.disabled = true; btn.textContent = "Cancelling…";
      log("cancel requested", "warn");
      try {
        await fetch(`/api/scans/${encodeURIComponent(state.job)}/cancel`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      } catch (_) { btn.disabled = false; btn.textContent = "Cancel"; }
    });
  }

  /* ----------------------------------------------------------------- errors */
  const ERRORS = {
    not_found: { title: "We can't see that repository.", action: "token" },
    bad_token: { title: "That token was rejected.", action: "token" },
    bad_token_format: { title: "That isn't a GitHub token.", action: "token" },
    rate_limited: { title: "GitHub rate limit reached.", action: "token", soft: true },
    sso_required: { title: "Your token needs SSO authorization.", action: "token" },
    forbidden: { title: "GitHub refused access.", action: "token" },
    too_large: { title: "Too big for a live scan.", soft: true },
    timeout: { title: "That took too long.", action: "options", soft: true },
    network: { title: "Can't reach GitHub.", soft: true },
    github_down: { title: "GitHub is having trouble.", soft: true },
    clone_failed: { title: "The clone failed." },
    empty_repo: { title: "Nothing to scan yet.", soft: true },
    unavailable: { title: "Blocked for legal reasons." },
    busy: { title: "The scanner is busy.", soft: true },
    cancelled: { title: "Scan cancelled.", soft: true },
    connection_lost: { title: "Lost connection to the scanner.", soft: true },
    server_unreachable: { title: "The RepoGuard server isn't answering." },
    invalid_request: { title: "The request was invalid." },
    internal: { title: "Something broke on our side." },
  };
  let countdownTimer = null;

  function fail(error) {
    closeStream();
    setRunning(false);
    state.phase = "error";
    const err = error || {};
    const meta = ERRORS[err.code] || { title: "The scan failed." };
    const panel = $("#error");
    panel.classList.toggle("soft", !!meta.soft);
    $("[data-error-code]").textContent = `${err.status ? err.status + " · " : ""}${err.code || "error"}`;
    $("[data-error-title]").textContent = meta.title;
    $("[data-error-message]").replaceChildren(rich(err.message || ""));
    const hint = $("[data-error-hint]"); hint.replaceChildren(rich(err.hint || "")); hint.hidden = !err.hint;
    const cd = $("[data-countdown]");
    clearInterval(countdownTimer);
    cd.hidden = true;
    if (err.retry_at) {
      const update = () => {
        const left = Math.max(0, Math.round(err.retry_at - Date.now() / 1000));
        cd.hidden = false;
        cd.textContent = left ? `Retry available in ${Math.floor(left / 60)}m ${String(left % 60).padStart(2, "0")}s (at ${clockTime(err.retry_at)})` : "You can retry now.";
        if (!left) clearInterval(countdownTimer);
      };
      update(); countdownTimer = setInterval(update, 1000);
    }
    const actions = $("[data-error-actions]"); actions.replaceChildren();
    if (meta.action === "token") actions.append(h("button", { class: "run-button small", type: "button", onclick: () => focusOptions("token") }, "Add or fix a token"));
    if (meta.action === "options") actions.append(h("button", { class: "run-button small", type: "button", onclick: () => focusOptions("depth") }, "Lower the history depth"));
    if (state.lastRequest) actions.append(h("button", { class: "ghost-button", type: "button", onclick: retry }, "Try again"));
    actions.append(h("button", { class: "ghost-button", type: "button", onclick: () => focusOptions("repo") }, "Edit repository"));
    log(`✗ ${err.message || meta.title}`, "err");
    show("error");
    panel.setAttribute("tabindex", "-1"); panel.focus({ preventScroll: true });
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  function retry() {
    const token = $("#token");
    startScan({ ...state.lastRequest, token: token && token.value.trim() ? token.value.trim() : null });
  }
  function focusOptions(which) {
    if (state.phase !== "report") show("audit-only");
    if (which !== "repo") {
      const d = $("[data-disclosure]");
      if (d.getAttribute("aria-expanded") !== "true") d.click();
    }
    const target = which === "token" ? $("#token") : which === "depth" ? $("#depth") : $("#repo");
    $("#audit").scrollIntoView({ behavior: "smooth", block: "start" });
    setTimeout(() => target && target.focus(), 350);
  }

  function setRate(rate) {
    state.rate = rate;
    const level = rate.remaining === 0 ? "out" : rate.remaining < Math.max(10, rate.limit * 0.1) ? "low" : "ok";
    $$("[data-rate]").forEach((el) => { el.dataset.level = level; });
    $$("[data-rate-text]").forEach((el) => {
      el.textContent = `GitHub API ${rate.remaining}/${rate.limit}${rate.reset ? ` · resets ${clockTime(rate.reset)}` : ""}${rate.authenticated ? " · token" : ""}`;
    });
  }

  /* ------------------------------------------------------------- visibility */
  function show(what) {
    const progress = $("#progress"), error = $("#error"), report = $("#report");
    if (progress) progress.hidden = !(what === "progress");
    if (error) error.hidden = what !== "error";
    if (report) report.hidden = what !== "report";
    if (what === "progress") progress.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /* ----------------------------------------------------------------- report */
  function finish(result) {
    closeStream();
    setRunning(false);
    state.phase = "report";
    state.result = result;
    log(`✓ finished: ${result.score}/100, grade ${result.grade}`, "ok");
    renderReport(result);
    show("report");
    setNavReport(true);
    const report = $("#report");
    report.setAttribute("tabindex", "-1");
    report.focus({ preventScroll: true });
    report.scrollIntoView({ behavior: "smooth", block: "start" });
    announce(`Scan finished. Score ${result.score} out of 100, grade ${result.grade}.`);
  }

  function verdict(r) {
    const c = r.counts, live = (r.findings || []).filter((f) => f.category === "secrets" && !f.commit).length;
    if (live) return [`${plural(live, "live credential")} in the code. Rotate ${live === 1 ? "it" : "them"} today.`, "Revoke first, then remove: deleting the line doesn't un-leak it."];
    if (c.critical) return [`${plural(c.critical, "critical issue")} to fix before anything else.`, "Critical findings cap the score at 59 until they're gone."];
    if (c.high) return [`No leaked keys, but ${plural(c.high, "high-severity problem")} worth an afternoon.`, "Start with the top of the list; each fix shows the exact change."];
    if (c.medium || c.low) return ["Nothing on fire. A few hardening steps left.", `${plural(c.medium + c.low, "lower-severity finding")}, most with a ready-made patch.`];
    return ["Clean. Nothing leaked, nothing known-vulnerable.", "Keep it that way: run RepoGuard on every pull request with the GitHub Action."];
  }

  function renderReport(r) {
    const root = $("#report");
    root.replaceChildren();
    const findings = r.findings || [];
    state.filters = { sev: new Set(SEVERITIES), category: "all", q: "", file: null };
    state.tab = "findings";

    // header
    const meta = r.meta || {};
    const chips = h("div", { class: "chips" },
      meta.visibility ? h("span", { class: `chip${meta.private ? " private" : ""}`, text: meta.visibility }) : null,
      meta.default_branch ? h("span", { class: "chip" }, "⎇ ", meta.default_branch) : null,
      meta.archived ? h("span", { class: "chip private", text: "archived" }) : null,
      r.commit ? h("span", { class: "chip" }, `@${shortSha(r.commit)}`,
        h("button", { type: "button", "aria-label": "Copy full commit SHA", onclick: (e) => copy(r.commit, e.currentTarget) }, "copy")) : null,
      h("span", { class: "chip", text: r.scanned_at || "" }));
    const head = h("div", { class: "report-head" },
      h("div", null, h("p", { class: "eyebrow", text: "// report" }), h("h2", { id: "report-title", text: r.repo || r.target }), chips),
      h("div", { class: "head-actions" }, exportMenu(r), state.live ? h("button", { class: "ghost-button", type: "button", onclick: () => focusOptions("repo") }, "New audit") : null));

    root.append(head, overview(r), workspace(r));
  }

  function overview(r) {
    const [title, sub] = verdict(r);
    const lost = (r.breakdown || []).reduce((a, b) => a + b.points, 0);
    const bar = h("div", { class: "points-bar", role: "img", "aria-label": `${r.score} points kept, ${Math.round(Math.min(lost, 100))} lost` });
    bar.append(h("span", { class: "keep", style: { "flex-basis": `${r.score}%` } }));
    const sevLost = {};
    (r.breakdown || []).forEach((b) => { sevLost[b.severity] = (sevLost[b.severity] || 0) + b.points; });
    const total = Object.values(sevLost).reduce((a, b) => a + b, 0) || 1;
    SEVERITIES.forEach((s) => { if (sevLost[s]) bar.append(h("span", { "data-sev": s, style: { "flex-basis": `${((100 - r.score) * sevLost[s]) / total}%`, background: `var(--${s})`, opacity: "0.85" } })); });

    const strip = h("div", { class: "sev-strip", role: "group", "aria-label": "Filter findings by severity" },
      ["critical", "high", "medium", "low"].map((s) => h("button", {
        type: "button", "data-sev": s, class: r.counts[s] ? "" : "zero", "aria-pressed": "false",
        "aria-label": `${r.counts[s]} ${s} — show only ${s}`,
        onclick: (e) => soloSeverity(s, e.currentTarget),
      }, h("b", { text: r.counts[s] }), h("span", { text: s }))));

    const score = h("section", { class: "panel score-panel", "aria-label": "Score", style: { "--grade-color": GRADE_COLOR[r.grade] || "var(--text)" }, "data-glow": "" },
      h("div", { class: "score-line" }, h("span", { class: "score-num", text: r.score }), h("span", { class: "score-of", text: "/ 100" }), h("span", { class: "grade", text: `GRADE ${r.grade}` })),
      h("p", { class: "verdict", text: title }), h("p", { class: "verdict-sub", text: sub }),
      bar, h("div", { class: "points-legend" }, h("span", { text: `${r.score} kept` }), h("span", { text: `${Math.round(100 - r.score)} lost` })),
      fixFirst(r), strip);

    const rows = (r.breakdown || []).slice(0, 7);
    const maxPts = Math.max(...rows.map((b) => b.points), 1);
    const breakdown = h("section", { class: "panel breakdown-panel", "aria-labelledby": "bd-title", "data-glow": "" },
      h("h3", { id: "bd-title", text: "Where the points went" }),
      rows.length ? h("table", { class: "breakdown" },
        h("thead", null, h("tr", null, h("th", { scope: "col", text: "Rule" }), h("th", { scope: "col", text: "Severity" }), h("th", { scope: "col", class: "num", text: "Hits" }), h("th", { scope: "col", class: "bar" }, h("span", { class: "sr-only", text: "Relative weight" })), h("th", { scope: "col", class: "num", text: "Points" }))),
        h("tbody", null, rows.map((b) => h("tr", { "data-sev": b.severity },
          h("td", { class: "rule", text: b.rule }), h("td", null, badge(b.severity)), h("td", { class: "num", text: `×${b.count}` }),
          h("td", { class: "bar" }, h("div", { class: "mini-bar" }, h("span", { style: { width: `${(b.points / maxPts) * 100}%` } }))),
          h("td", { class: "num", text: `−${b.points}` }))))) :
        h("p", { class: "help", text: "Nothing deducted. Full marks." }),
      (r.breakdown || []).length > rows.length ? h("p", { class: "help", text: `+ ${r.breakdown.length - rows.length} smaller items` }) : null);

    const st = r.stats || {};
    const statItems = [["files scanned", st.files_scanned], ["commits replayed", st.commits_scanned], ["packages checked", st.packages_checked],
      ["manifests", st.manifests], ["workflows", st.workflows_scanned], ["Dockerfiles", st.dockerfiles_scanned]].filter(([, v]) => v !== undefined && v !== null);
    const stats = h("section", { class: "panel stats-panel", "aria-labelledby": "st-title", "data-glow": "" }, h("h3", { id: "st-title", text: "Coverage" }),
      h("dl", { class: "stats" }, statItems.map(([k, v]) => h("div", null, h("dt", { text: k }), h("dd", { text: Number(v).toLocaleString() })))));

    const notes = r.notes || [];
    const notesPanel = h("section", { class: `panel notes-panel${notes.length ? "" : " clear"}`, "aria-labelledby": "nt-title" }, h("h3", { id: "nt-title", text: notes.length ? "Caveats" : "Completeness" }),
      h("ul", null, notes.length ? notes.map((n) => h("li", null, rich(n))) : h("li", { text: "Every scanner ran to completion." })));
    return h("div", { class: "overview" }, score, breakdown, stats, notesPanel);
  }

  /* The three findings worth the most points, as jump links into the list. */
  function fixFirst(r) {
    const top = (r.findings || []).filter((f) => f.severity !== "info").slice(0, 3);
    if (!top.length) return null;
    return h("div", { class: "fix-first" }, h("h3", { text: "Fix first" }),
      h("ol", null, top.map((f) => h("li", null, h("button", { type: "button", class: "jump", onclick: () => openFinding(f.fingerprint) },
        badge(f.severity), h("span", null, rich(f.title)), f.file ? h("small", null, f.file, f.line ? `:${f.line}` : "") : null)))));
  }
  function openFinding(fp) {
    resetFilters();
    selectTab("findings");
    const toggle = document.querySelector(`[aria-controls="f-${CSS.escape(fp)}-body"]`);
    if (!toggle) return;
    if (toggle.getAttribute("aria-expanded") !== "true") toggle.click();
    toggle.scrollIntoView({ behavior: "smooth", block: "center" });
    setTimeout(() => toggle.focus({ preventScroll: true }), 300);
  }

  function badge(sev) { return h("span", { class: `badge ${sev}`, text: sev }); }

  function exportMenu(r) {
    const wrap = h("div", { class: "menu-wrap" });
    const btn = h("button", { class: "ghost-button", type: "button", "aria-haspopup": "menu", "aria-expanded": "false", "aria-controls": "export-menu" }, "Export ▾");
    const items = [];
    if (state.live && state.job) {
      const base = `/api/scans/${encodeURIComponent(state.job)}/report`;
      items.push(h("a", { role: "menuitem", href: `${base}.md`, download: "", tabindex: "-1" }, "Markdown", h("span", { text: "PR comment" })));
      items.push(h("a", { role: "menuitem", href: `${base}.html`, download: "", tabindex: "-1" }, "HTML report", h("span", { text: "offline" })));
    }
    items.push(h("button", { role: "menuitem", type: "button", tabindex: "-1", onclick: () => downloadJson(r) }, "JSON", h("span", { text: "raw" })));
    items.push(h("button", { role: "menuitem", type: "button", tabindex: "-1", onclick: () => window.print() }, "Print / PDF", h("span", { text: "⌘P" })));
    const menu = h("div", { class: "menu", role: "menu", id: "export-menu", "aria-label": "Export report", hidden: true }, items);
    const open = (focusLast = false) => {
      menu.hidden = false; btn.setAttribute("aria-expanded", "true");
      (focusLast ? items[items.length - 1] : items[0]).focus();
      setTimeout(() => document.addEventListener("pointerdown", outside), 0);
    };
    const close = (restore = true) => {
      if (menu.hidden) return;
      menu.hidden = true; btn.setAttribute("aria-expanded", "false");
      document.removeEventListener("pointerdown", outside);
      if (restore) btn.focus();
    };
    const outside = (e) => { if (!wrap.contains(e.target)) close(false); };
    btn.addEventListener("click", () => (menu.hidden ? open() : close()));
    btn.addEventListener("keydown", (e) => { if (e.key === "ArrowDown") { e.preventDefault(); open(); } if (e.key === "ArrowUp") { e.preventDefault(); open(true); } });
    menu.addEventListener("keydown", (e) => {
      const i = items.indexOf(document.activeElement);
      if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
      else if (e.key === "Home") { e.preventDefault(); items[0].focus(); }
      else if (e.key === "End") { e.preventDefault(); items[items.length - 1].focus(); }
      else if (e.key === "Escape") { e.preventDefault(); close(); }
      else if (e.key === "Tab") close(false);
    });
    items.forEach((it) => it.addEventListener("click", () => close()));
    wrap.append(btn, menu);
    return wrap;
  }
  function downloadJson(r) {
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
    const a = h("a", { download: `${(r.repo || r.target || "repo").replace(/[^\w.-]+/g, "-")}-repoguard.json` });
    a.href = URL.createObjectURL(blob);
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  async function copy(text, button) {
    try {
      await navigator.clipboard.writeText(text);
      if (button) { const was = button.textContent; button.textContent = "copied"; setTimeout(() => { button.textContent = was; }, 1400); }
    } catch (_) { if (button) button.textContent = "copy failed"; }
  }

  /* -------------------------------------------------------------- workspace */
  function workspace(r) {
    const findings = r.findings || [];
    const tree = fileTree(findings);
    const tabsDef = [
      ["findings", "Findings", findings.length],
      ["dependencies", "Dependencies", findings.filter((f) => f.category === "dependencies").length],
      ["json", "Raw JSON", null],
    ];
    const tablist = h("div", { class: "tabs", role: "tablist", "aria-label": "Report views" });
    const panels = {};
    tabsDef.forEach(([id, label, n]) => {
      const tab = h("button", { class: "tab", role: "tab", id: `tab-${id}`, type: "button", "aria-controls": `panel-${id}`, "aria-selected": id === state.tab ? "true" : "false", tabindex: id === state.tab ? "0" : "-1" },
        label, n !== null ? h("span", { class: "n", text: n }) : null);
      tab.addEventListener("click", () => selectTab(id));
      tablist.append(tab);
      panels[id] = h("div", { role: "tabpanel", id: `panel-${id}`, "aria-labelledby": `tab-${id}`, tabindex: "0", hidden: id !== state.tab });
    });
    tablist.addEventListener("keydown", (e) => {
      const tabs = $$('[role="tab"]', tablist), i = tabs.indexOf(document.activeElement);
      let next = null;
      if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
      if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
      if (e.key === "Home") next = tabs[0];
      if (e.key === "End") next = tabs[tabs.length - 1];
      if (next) { e.preventDefault(); next.focus(); selectTab(next.id.slice(4)); }
    });

    panels.findings.append(toolbar(r), h("div", { "data-findings": "" }));
    panels.dependencies.append(dependencyView(r));
    const json = JSON.stringify(r, null, 2);
    panels.json.append(h("div", { class: "row-actions" }, h("button", { class: "ghost-button", type: "button", onclick: (e) => copy(json, e.currentTarget) }, "Copy JSON")),
      h("pre", { class: "json-view", style: { "margin-top": "12px" } }, json));

    const main = h("div", { class: "findings-pane" }, tablist, Object.values(panels));
    const ws = h("div", { class: "workspace" }, tree, main);
    queueMicrotask(renderFindings);
    return ws;
  }

  function selectTab(id) {
    state.tab = id;
    $$('#report [role="tab"]').forEach((t) => { const on = t.id === `tab-${id}`; t.setAttribute("aria-selected", String(on)); t.tabIndex = on ? 0 : -1; });
    $$('#report [role="tabpanel"]').forEach((p) => { p.hidden = p.id !== `panel-${id}`; });
  }

  function toolbar(r) {
    const badges = h("div", { class: "filter-badges", role: "group", "aria-label": "Severities to show" },
      ["critical", "high", "medium", "low"].map((s) => h("button", { type: "button", "aria-pressed": "true", "data-filter-sev": s, onclick: (e) => toggleSeverity(s, e.currentTarget) },
        h("span", { class: `badge ${s}` }, `${s} ${r.counts[s]}`))));
    const cats = h("select", { "aria-label": "Category", onchange: (e) => { state.filters.category = e.target.value; renderFindings(); } },
      h("option", { value: "all" }, "All categories"),
      Object.entries(CATEGORY_NAMES).filter(([k]) => (r.categories || Object.keys(CATEGORY_NAMES)).includes(k)).map(([k, v]) => h("option", { value: k }, v)));
    let t = null;
    const search = h("input", { class: "search", type: "search", placeholder: "Filter by text, file or rule…", "aria-label": "Filter findings",
      oninput: (e) => { clearTimeout(t); t = setTimeout(() => { state.filters.q = e.target.value.trim().toLowerCase(); renderFindings(); }, 120); } });
    return h("div", { class: "toolbar" }, badges, cats, search, h("p", { class: "showing", "aria-live": "polite", "data-showing": "" }));
  }

  function toggleSeverity(sev, btn) {
    const set = state.filters.sev;
    if (set.has(sev)) set.delete(sev); else set.add(sev);
    btn.setAttribute("aria-pressed", String(set.has(sev)));
    $$(".sev-strip button").forEach((b) => b.setAttribute("aria-pressed", "false"));
    renderFindings();
  }
  function soloSeverity(sev, btn) {
    const solo = btn.getAttribute("aria-pressed") !== "true";
    $$(".sev-strip button").forEach((b) => b.setAttribute("aria-pressed", String(solo && b === btn)));
    state.filters.sev = solo ? new Set([sev]) : new Set(SEVERITIES);
    $$("[data-filter-sev]").forEach((b) => b.setAttribute("aria-pressed", String(state.filters.sev.has(b.dataset.filterSev))));
    selectTab("findings");
    renderFindings();
    const pane = $(".findings-pane"); if (pane) pane.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function matches(f) {
    const fl = state.filters;
    if (!fl.sev.has(f.severity)) return false;
    if (fl.category !== "all" && f.category !== fl.category) return false;
    if (fl.file && f.file !== fl.file && !(f.patch && f.patch.file === fl.file)) return false;
    if (fl.q) {
      const hay = `${f.title} ${f.file || ""} ${f.rule} ${f.description}`.toLowerCase();
      if (!hay.includes(fl.q)) return false;
    }
    return true;
  }

  function renderFindings() {
    const box = $("[data-findings]");
    if (!box || !state.result) return;
    const all = state.result.findings || [];
    const shown = all.filter(matches);
    const label = $("[data-showing]");
    if (label) label.textContent = `Showing ${shown.length} of ${plural(all.length, "finding")}${state.filters.file ? ` in ${state.filters.file}` : ""}`;
    box.replaceChildren();
    if (!all.length) {
      box.append(h("div", { class: "empty secure" }, h("h4", { text: "No findings." }), h("p", { text: "No secrets in code or replayed history, no known-vulnerable pinned packages, and the workflows and Dockerfiles pass every rule." })));
      return;
    }
    if (!shown.length) {
      box.append(h("div", { class: "empty" }, h("h4", { text: "Nothing matches these filters." }),
        h("p", null, "Clear the search or turn severities back on. ", h("button", { class: "text-button", type: "button", onclick: resetFilters }, "Reset filters"))));
      return;
    }
    for (const sev of SEVERITIES) {
      const group = shown.filter((f) => f.severity === sev);
      if (!group.length) continue;
      box.append(h("h4", { class: "group-title" }, badge(sev), plural(group.length, "finding")));
      group.forEach((f) => box.append(findingRow(f)));
    }
  }
  function resetFilters() {
    state.filters = { sev: new Set(SEVERITIES), category: "all", q: "", file: null };
    $$("[data-filter-sev]").forEach((b) => b.setAttribute("aria-pressed", "true"));
    $$(".sev-strip button").forEach((b) => b.setAttribute("aria-pressed", "false"));
    const s = $(".toolbar .search"); if (s) s.value = "";
    const c = $(".toolbar select"); if (c) c.value = "all";
    $$(".tree [aria-pressed]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.file === "")));
    renderFindings();
  }

  function locationNode(f) {
    if (!f.file) return null;
    const url = linkFor(f);
    const text = [h("span", { text: f.file }), f.line ? h("b", { text: `:${f.line}` }) : null, f.commit ? ` · commit ${shortSha(f.commit)}` : null];
    return url ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer", class: "finding-loc", onclick: (e) => e.stopPropagation() }, text) : h("span", { class: "finding-loc" }, text);
  }
  function linkFor(f) {
    const r = state.result;
    if (!r || !r.repo || !f.file || !/^[\w.-]+\/[\w.-]+$/.test(r.repo)) return null;
    const base = `${(r.server_url || "https://github.com").replace(/\/$/, "")}/${r.repo}`;
    if (f.commit && /^[0-9a-f]{7,40}$/.test(f.commit)) return `${base}/commit/${f.commit}`;
    if (!r.commit || !/^[0-9a-f]{7,40}$/.test(r.commit)) return null;
    return `${base}/blob/${r.commit}/${f.file.split("/").map(encodeURIComponent).join("/")}${f.line ? `#L${f.line}` : ""}`;
  }

  function findingRow(f) {
    const id = `f-${f.fingerprint}`;
    const open = state.open.has(f.fingerprint);
    const article = h("article", { class: `finding${open ? " open" : ""}`, "data-sev": f.severity, "data-glow": "" });
    const bodyId = `${id}-body`;
    const toggle = h("button", { class: "finding-toggle", type: "button", "aria-expanded": String(open), "aria-controls": bodyId },
      badge(f.severity),
      h("span", null, h("span", { class: "finding-title" }, rich(f.title)), f.file ? h("span", { class: "finding-loc" }, f.file, f.line ? h("b", { text: `:${f.line}` }) : null, f.commit ? ` · ${shortSha(f.commit)}` : null) : null),
      h("span", { class: "finding-cat" }, CATEGORY_NAMES[f.category] || f.category, h("span", { class: "chev", "aria-hidden": "true" })));
    const inner = h("div", { class: "finding-inner" });
    const body = h("div", { class: "finding-body", id: bodyId, role: "region", "aria-label": `Details: ${f.title.replace(/`/g, "")}` }, inner);
    const fill = () => { if (!inner.firstChild) inner.append(findingContent(f)); };
    if (open) fill();
    if (!open) inner.setAttribute("inert", "");
    toggle.addEventListener("click", () => {
      const now = !article.classList.contains("open");
      if (now) { fill(); state.open.add(f.fingerprint); inner.removeAttribute("inert"); }
      else { state.open.delete(f.fingerprint); inner.setAttribute("inert", ""); }
      article.classList.toggle("open", now);
      toggle.setAttribute("aria-expanded", String(now));
    });
    article.append(toggle, body);
    return article;
  }

  function findingContent(f) {
    const parts = [];
    const lines = String(f.description || "").split("\n");
    if (f.category === "dependencies" && f.details && f.details.vulns) {
      parts.push(h("p", null, rich(`${f.details.ecosystem} package \`${f.details.package}\` ${f.details.version}${f.details.dev ? " (dev dependency)" : ""}.`)));
      parts.push(depPath(f.details));
      parts.push(vulnList(f.details.vulns));
    } else {
      const paras = [], bullets = [];
      lines.forEach((l) => (l.startsWith("- ") ? bullets.push(l.slice(2)) : l.trim() && paras.push(l)));
      paras.forEach((p) => parts.push(h("p", null, rich(p))));
      if (bullets.length) parts.push(h("ul", null, bullets.map((b) => h("li", null, rich(b)))));
    }
    const loc = locationNode(f);
    if (f.patch) parts.push(diffView(f));
    else if (f.evidence) parts.push(codeBlock([f.evidence], f.line));
    parts.push(h("div", { class: "fix" }, h("span", { class: "fix-label", text: "FIX" }), h("p", null, rich(f.fix))));
    const actions = [];
    if (loc && loc.tagName === "A") actions.push(h("a", { class: "ghost-button", href: loc.getAttribute("href"), target: "_blank", rel: "noopener noreferrer" }, f.commit ? "Open commit on GitHub ↗" : "Open on GitHub ↗"));
    if (f.patch && f.patch.after && f.patch.after.length) actions.push(h("button", { class: "ghost-button", type: "button", onclick: (e) => copy(f.patch.after.join("\n"), e.currentTarget) }, "Copy suggested change"));
    if (actions.length) parts.push(h("div", { class: "row-actions" }, actions));
    const refs = (f.references || []).filter((u) => safeUrl(u) && /^https:/.test(u));
    if (refs.length && !(f.details && f.details.vulns)) parts.push(h("div", { class: "refs" }, refs.map((u) => h("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, u.split("/").pop()))));
    parts.push(h("p", { class: "finding-loc", text: `rule ${f.rule}` }));
    return h("div", { class: "finding-content" }, parts);
  }

  function codeBlock(lines, start) {
    return h("pre", { class: "code" }, lines.map((l, i) => h("div", { class: "code-line" }, h("span", { class: "ln", text: start ? start + i : "" }), h("code", null, l))));
  }

  /* LCS line diff → aligned side-by-side rows. */
  function diffRows(before, after) {
    const n = before.length, m = after.length;
    const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = before[i] === after[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    const ops = []; let i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && before[i] === after[j]) { ops.push(["same", i++, j++]); }
      else if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) { ops.push(["add", null, j++]); }
      else { ops.push(["del", i++, null]); }
    }
    const rows = []; let k = 0;
    while (k < ops.length) {
      if (ops[k][0] === "same") { rows.push([ops[k][1], ops[k][2], "same"]); k++; continue; }
      const dels = [], adds = [];
      while (k < ops.length && ops[k][0] !== "same") { (ops[k][0] === "del" ? dels : adds).push(ops[k]); k++; }
      for (let x = 0; x < Math.max(dels.length, adds.length); x++) rows.push([dels[x] ? dels[x][1] : null, adds[x] ? adds[x][2] : null, "change"]);
    }
    return rows;
  }

  function diffView(f) {
    const p = f.patch, before = p.before || [], after = p.after || [], start = p.start || 1;
    const file = p.file || f.file || "";
    const isNew = !before.length;
    const grid = h("div", { class: "diff-rows" });
    diffRows(before, after).forEach(([b, a, kind]) => {
      const left = b === null ? h("div", { class: "diff-cell blank", "aria-hidden": "true" }) :
        h("div", { class: `diff-cell${kind === "change" ? " del" : ""}` }, h("span", { class: "ln", text: start + b }), h("span", { class: "sign", text: kind === "change" ? "−" : " " }), h("code", null, before[b]));
      const right = a === null ? h("div", { class: "diff-cell blank", "aria-hidden": "true" }) :
        h("div", { class: `diff-cell${kind === "change" ? " add" : ""}` }, h("span", { class: "ln", text: (isNew ? 1 : start) + a }), h("span", { class: "sign", text: kind === "change" ? "+" : " " }), h("code", null, after[a]));
      if (kind === "change" && b !== null) left.setAttribute("aria-label", `removed line ${start + b}`);
      if (kind === "change" && a !== null) right.setAttribute("aria-label", "added line");
      grid.append(left, right);
    });
    return h("div", null,
      h("p", { class: "diff-cap", text: isNew ? `New file: ${file}` : `Suggested change · ${file}:${start}` }),
      h("div", { class: "diff", role: "group", "aria-label": `Suggested change for ${file}` },
        h("div", { class: "diff-head", "aria-hidden": "true" }, h("span", { text: isNew ? "missing" : `vulnerable · L${start}` }), h("span", { text: "suggested" })), grid));
  }

  function depPath(d) {
    const nodes = [h("span", { class: "node root", text: d.manifest || "project" })];
    const path = d.path && d.path.length ? d.path : null;
    if (path) path.forEach((n, i) => { nodes.push(h("span", { class: "sep", "aria-hidden": "true", text: "›" }), h("span", { class: `node${i === path.length - 1 ? " hit" : ""}`, text: i === path.length - 1 ? `${n}@${d.version}` : n })); });
    else nodes.push(h("span", { class: "sep", "aria-hidden": "true", text: "›" }), h("span", { class: "node hit", text: `${d.package}@${d.version}` }), h("span", { class: "tag", text: "path unknown" }));
    return h("div", { class: "dep-path", role: "list", "aria-label": `Dependency path: ${path ? path.join(" then ") : d.package}` },
      nodes.map((n) => (n.classList.contains("sep") ? n : (n.setAttribute("role", "listitem"), n))),
      d.direct ? h("span", { class: "tag", text: "direct" }) : path ? h("span", { class: "tag", text: `transitive · depth ${path.length}` }) : null,
      d.dev ? h("span", { class: "tag", text: "dev" }) : null);
  }

  function vulnList(vulns) {
    return h("ul", { class: "vulns", "aria-label": "Advisories" }, vulns.map((v, i) => {
      const id = `v-${v.id}-${i}`.replace(/[^\w-]/g, "");
      const body = h("div", { class: "vuln-body", id, hidden: true },
        h("p", { text: v.summary }),
        h("div", { class: "kv" }, h("span", null, "severity ", h("b", { text: v.severity })), v.cvss != null ? h("span", null, "CVSS ", h("b", { text: Number(v.cvss).toFixed(1) })) : h("span", { text: "no CVSS v3 vector" }), h("span", null, "fixed in ", h("b", { text: v.fixed || "no fix yet" }))),
        v.vector ? h("div", { class: "vector", text: v.vector }) : null,
        v.aliases && v.aliases.length ? h("div", { class: "kv" }, "aliases ", v.aliases.map((a) => h("b", { text: a }))) : null,
        safeUrl(v.url) ? h("a", { href: v.url, target: "_blank", rel: "noopener noreferrer", class: "refs" }, `${v.id} on OSV.dev ↗`) : null);
      const btn = h("button", { class: "vuln-toggle", type: "button", "aria-expanded": "false", "aria-controls": id, "data-sev": v.severity },
        badge(v.severity), h("span", { class: "vuln-id" }, v.id, h("small", { text: v.summary })), h("span", { class: "cvss", text: v.cvss != null ? Number(v.cvss).toFixed(1) : "—" }));
      btn.addEventListener("click", () => { const open = btn.getAttribute("aria-expanded") !== "true"; btn.setAttribute("aria-expanded", String(open)); body.hidden = !open; });
      return h("li", null, btn, body);
    }));
  }

  function dependencyView(r) {
    const deps = (r.findings || []).filter((f) => f.category === "dependencies");
    const vulnerable = deps.filter((f) => f.details && f.details.vulns);
    const unpinned = deps.filter((f) => f.rule === "dependency/unpinned");
    const st = r.stats || {};
    const osvNote = (r.notes || []).find((n) => /vulnerabilities weren't checked/i.test(n));
    if (!(r.categories || []).includes("dependencies")) return h("div", { class: "empty" }, h("h4", { text: "Dependency scanning was off." }), h("p", { text: "Run the audit with dependencies enabled to see this view." }));
    if (!st.manifests) {
      return h("div", { class: "empty" }, h("h4", { text: "No dependency manifests in this repo." }),
        h("p", null, rich("RepoGuard reads `requirements*.txt`, `package-lock.json`, `package.json`, `poetry.lock` and `Pipfile.lock`. None were found, so there's nothing to check.")));
    }
    const main = h("div");
    if (osvNote) main.append(h("div", { class: "empty", style: { "margin-bottom": "16px", "border-color": "rgba(240,136,62,0.45)" } }, h("h4", { text: "Vulnerabilities weren't checked." }), h("p", null, rich(osvNote))));
    if (!vulnerable.length && !osvNote) {
      main.append(h("div", { class: "empty secure" }, h("h4", { text: "No known-vulnerable packages." }),
        h("p", { text: `${plural(st.packages_checked || 0, "pinned package")} checked against OSV.dev across ${plural(st.manifests, "manifest")}.` })));
    }
    const byManifest = {};
    vulnerable.forEach((f) => { (byManifest[f.details.manifest] = byManifest[f.details.manifest] || []).push(f); });
    Object.entries(byManifest).forEach(([manifest, list]) => {
      const sec = h("section", { class: "manifest", "aria-label": manifest }, h("h4", { class: "manifest-title" }, manifest, h("span", { text: plural(list.length, "vulnerable package") })));
      list.forEach((f) => {
        const d = f.details, id = `pkg-${f.fingerprint}`;
        const body = h("div", { class: "pkg-body", id, hidden: true }, depPath(d), vulnList(d.vulns),
          h("div", { class: "fix" }, h("span", { class: "fix-label", text: "FIX" }), h("p", null, rich(f.fix))),
          f.patch ? diffView(f) : null);
        const btn = h("button", { type: "button", "aria-expanded": "false", "aria-controls": id },
          badge(f.severity), h("span", { class: "pkg-name" }, `${d.package} `, h("small", { text: `${d.version} · ${plural(d.vulns.length, "advisory", "advisories")}${d.fixed_in ? ` · fix ${d.fixed_in}` : ""}` })),
          h("span", { class: "chev", "aria-hidden": "true" }));
        btn.addEventListener("click", () => { const open = btn.getAttribute("aria-expanded") !== "true"; btn.setAttribute("aria-expanded", String(open)); body.hidden = !open; });
        sec.append(h("div", { class: "pkg", "data-sev": f.severity, "data-glow": "" }, btn, body));
      });
      main.append(sec);
    });
    const side = h("aside", { class: "side-note", "aria-label": "Dependency coverage" },
      h("h4", { text: "Coverage" }),
      h("ul", null, h("li", { text: `${plural(st.manifests, "manifest")} parsed` }), h("li", { text: `${plural(st.packages_found || 0, "pinned package")}` }),
        h("li", { text: `${plural(st.packages_checked || 0, "package")} checked on OSV.dev` })),
      unpinned.length ? [h("h4", { text: "Unpinned", style: { "margin-top": "16px" } }),
        h("ul", null, unpinned.flatMap((u) => ((u.details && u.details.packages) || []).slice(0, 12).map((p) => h("li", null, h("code", null, `${p.name} ${p.spec}`), ` · ${u.file}`))))] : null);
    return h("div", { class: "deps-grid" }, main, side);
  }

  /* collapsible file tree of affected files */
  function fileTree(findings) {
    const root = { dirs: {}, files: {} };
    findings.forEach((f) => {
      const file = (f.patch && f.patch.file && !f.file) ? f.patch.file : f.file;
      if (!file) return;
      const parts = file.split("/");
      let node = root;
      parts.slice(0, -1).forEach((p) => { node = node.dirs[p] = node.dirs[p] || { dirs: {}, files: {} }; });
      const leaf = parts[parts.length - 1];
      const entry = node.files[leaf] = node.files[leaf] || { path: file, count: 0, worst: "info" };
      entry.count++;
      if (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(entry.worst)) entry.worst = f.severity;
    });
    const fileCount = findings.filter((f) => f.file).map((f) => f.file).filter((v, i, a) => a.indexOf(v) === i).length;
    const select = (path) => {
      state.filters.file = state.filters.file === path || path === "" ? null : path;
      $$(".tree [data-file]").forEach((b) => b.setAttribute("aria-pressed", String((b.dataset.file || null) === state.filters.file || (b.dataset.file === "" && !state.filters.file))));
      selectTab("findings");
      renderFindings();
    };
    const build = (node, depth) => {
      const ul = h("ul", depth ? null : { class: "tree" });
      Object.keys(node.dirs).sort().forEach((name) => {
        // collapse single-child chains: .github/workflows
        let label = name, child = node.dirs[name];
        while (Object.keys(child.files).length === 0 && Object.keys(child.dirs).length === 1) {
          const only = Object.keys(child.dirs)[0]; label += `/${only}`; child = child.dirs[only];
        }
        const sub = build(child, depth + 1);
        const id = `dir-${Math.random().toString(36).slice(2, 9)}`;
        sub.id = id;
        const btn = h("button", { type: "button", "aria-expanded": "true", "aria-controls": id }, h("span", { class: "chev", "aria-hidden": "true" }), h("span", { class: "name", text: `${label}/` }));
        btn.addEventListener("click", () => { const open = btn.getAttribute("aria-expanded") !== "true"; btn.setAttribute("aria-expanded", String(open)); sub.hidden = !open; });
        ul.append(h("li", { class: "folder" }, btn, sub));
      });
      Object.keys(node.files).sort().forEach((name) => {
        const e = node.files[name];
        ul.append(h("li", null, h("button", { type: "button", "aria-pressed": "false", "data-file": e.path, "data-sev": e.worst, title: e.path, onclick: () => select(e.path) },
          h("span", { class: "dot", "aria-hidden": "true" }), h("span", { class: "name", text: name }), h("span", { class: "count", text: e.count }))));
      });
      return ul;
    };
    const panel = h("nav", { class: "tree-panel", "aria-label": "Affected files" });
    const body = h("div", { class: "tree-body" },
      h("ul", { class: "tree tree-all" }, h("li", null, h("button", { type: "button", "aria-pressed": "true", "data-file": "", onclick: () => select("") },
        h("span", { class: "name", text: "All files" }), h("span", { class: "count", text: fileCount })))),
      fileCount ? build(root, 0) : h("p", { class: "help", text: "No files with findings." }));
    const toggle = h("button", { class: "tree-toggle", type: "button", "aria-expanded": "false" }, `Affected files (${fileCount})`, h("span", { class: "chev", "aria-hidden": "true" }));
    toggle.addEventListener("click", () => { const open = !panel.classList.contains("open"); panel.classList.toggle("open", open); toggle.setAttribute("aria-expanded", String(open)); });
    panel.append(h("h3", { text: "Affected files" }), toggle, body);
    return panel;
  }

  /* ------------------------------------------------------------------- boot */
  function boot() {
    initDrawer(); initModals(); initGlow(); initNavSpy();
    const embedded = document.getElementById("repoguard-data");
    if (embedded) {
      state.live = false;
      document.body.classList.add("report-only");
      try {
        const result = JSON.parse(embedded.textContent);
        state.result = result;
        renderReport(result);
        $("#report").hidden = false;
      } catch (_) {
        $("#report").hidden = false;
        $("#report").append(h("div", { class: "empty" }, h("h4", { text: "This report file is damaged." }), h("p", { text: "Re-run repoguard to generate it again." })));
      }
      return;
    }
    initForm(); initCancel();
    fetch("/api/health").catch(() => fail({ code: "server_unreachable", message: "Couldn't reach the RepoGuard server.", hint: "Start it with `repoguard serve`." }));
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
