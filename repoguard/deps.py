"""Vulnerable and unpinned dependencies, checked against the OSV.dev database."""
from __future__ import annotations

import json
import re
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import cvss
from .files import SKIP_DIRS, read_text
from .models import Finding, Severity

OSV_API = "https://api.osv.dev/v1"
BATCH = 500
MANIFEST_MAX_BYTES = 25_000_000
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")
OTHER_JS_LOCKS = ("yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock")


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str      # "PyPI" or "npm"
    file: str
    line: int | None = None
    dev: bool = False
    path: tuple[str, ...] = ()          # dependency chain from the project to this package; () = unknown


@dataclass(frozen=True)
class Unpinned:
    name: str
    spec: str
    file: str
    line: int | None


def normalize(name: str, ecosystem: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


# --------------------------------------------------------------------------
# Manifest parsing
# --------------------------------------------------------------------------
REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def parse_requirements(text: str, file: str) -> tuple[list[Package], list[Unpinned]]:
    pinned, unpinned = [], []
    logical, start = "", 0
    lines = text.splitlines()
    for i, raw in enumerate(lines, 1):
        if not logical:
            start = i
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            logical += stripped[:-1] + " "
            continue
        logical += stripped
        line, logical = logical, ""
        line = re.split(r"(?:^|\s)#", line, maxsplit=1)[0].strip()
        if not line or line.startswith(("-", ".", "/")) or "://" in line or line.startswith("git+"):
            continue
        line = line.split(";", 1)[0]
        line = " ".join(t for t in line.split() if not t.startswith("--"))
        m = REQ_LINE.match(line)
        if not m:
            continue
        name, spec = m.group(1), m.group(3).strip()
        exact = re.fullmatch(r"===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)", spec)
        if exact:
            pinned.append(Package(name, exact.group(1), "PyPI", file, start, path=(name,)))
        else:
            unpinned.append(Unpinned(name, spec or "(any version)", file, start))
    return pinned, unpinned


def _npm_name(key: str, info: dict) -> str:
    return info.get("name") or key.rsplit("node_modules/", 1)[-1]


def npm_paths(packages: dict) -> dict[str, tuple[str, ...]]:
    """Shortest dependency chain from the project root to every installed package,
    following Node's resolution (nearest node_modules folder upwards)."""
    def resolve(frm: str, dep: str) -> str | None:
        base = frm
        while True:
            cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if cand in packages:
                info = packages[cand]
                if isinstance(info, dict) and info.get("link") and info.get("resolved") in packages:
                    return info["resolved"]
                return cand
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            base = base[:idx] if idx != -1 else ""

    paths: dict[str, tuple[str, ...]] = {"": ()}
    queue = [""]
    while queue:
        node = queue.pop(0)
        info = packages.get(node) or {}
        names = list((info.get("dependencies") or {})) + list((info.get("optionalDependencies") or {})) \
            + list((info.get("peerDependencies") or {}))
        if node == "":
            names += list((info.get("devDependencies") or {}))
        for dep in names:
            key = resolve(node, dep)
            if key is not None and key not in paths:
                paths[key] = paths[node] + (_npm_name(key, packages.get(key) or {}),)
                queue.append(key)
    return paths


def parse_npm_lock(text: str, file: str) -> list[Package]:
    data = json.loads(text)
    out: list[Package] = []
    if isinstance(data.get("packages"), dict):
        packages = data["packages"]
        paths = npm_paths(packages)
        for key, info in packages.items():
            if not key or not isinstance(info, dict) or info.get("link") or "node_modules/" not in key:
                continue
            if info.get("version"):
                name = _npm_name(key, info)
                out.append(Package(name, info["version"], "npm", file,
                                   dev=bool(info.get("dev") or info.get("devOptional")),
                                   path=paths.get(key, ())))
    else:
        def walk(deps: dict, chain: tuple[str, ...]) -> None:
            for name, info in (deps or {}).items():
                if isinstance(info, dict):
                    here = chain + (name,)
                    if info.get("version") and not str(info["version"]).startswith(("file:", "git", "http")):
                        out.append(Package(name, info["version"], "npm", file, dev=bool(info.get("dev")),
                                           path=here if chain else ()))
                    walk(info.get("dependencies"), here)
        walk(data.get("dependencies"), ())
    return out


SEMVER_EXACT = re.compile(r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")


def parse_package_json(text: str, file: str) -> tuple[list[Package], list[Unpinned]]:
    data = json.loads(text)
    pinned, unpinned = [], []
    lines = text.splitlines()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec).strip()
            if spec.startswith(("file:", "link:", "workspace:", "git", "http", "github:", "npm:")) or "/" in spec:
                continue
            line = next((i for i, l in enumerate(lines, 1) if f'"{name}"' in l), None)
            if SEMVER_EXACT.fullmatch(spec):
                pinned.append(Package(name, spec.lstrip("v"), "npm", file, line,
                                      dev=section == "devDependencies", path=(name,)))
            else:
                unpinned.append(Unpinned(name, spec, file, line))
    return pinned, unpinned


def _pyproject_roots(pyproject_text: str | None) -> tuple[set[str], set[str]]:
    """(main, dev) top-level dependency names declared in pyproject.toml."""
    if not pyproject_text:
        return set(), set()
    try:
        data = tomllib.loads(pyproject_text)
    except tomllib.TOMLDecodeError:
        return set(), set()
    main, dev = set(), set()
    poetry = (data.get("tool") or {}).get("poetry") or {}
    main |= {normalize(n, "PyPI") for n in (poetry.get("dependencies") or {}) if n.lower() != "python"}
    for group in (poetry.get("group") or {}).values():
        dev |= {normalize(n, "PyPI") for n in ((group or {}).get("dependencies") or {})}
    dev |= {normalize(n, "PyPI") for n in (poetry.get("dev-dependencies") or {})}
    for spec in (data.get("project") or {}).get("dependencies") or []:
        m = REQ_LINE.match(str(spec).strip())
        if m:
            main.add(normalize(m.group(1), "PyPI"))
    return main, dev


def parse_poetry_lock(text: str, file: str, pyproject_text: str | None = None) -> list[Package]:
    data = tomllib.loads(text)
    pkgs = [p for p in data.get("package", []) if p.get("name") and p.get("version")]
    main, dev = _pyproject_roots(pyproject_text)
    graph = {normalize(p["name"], "PyPI"): [normalize(d, "PyPI") for d in (p.get("dependencies") or {})] for p in pkgs}
    display = {normalize(p["name"], "PyPI"): p["name"] for p in pkgs}
    paths: dict[str, tuple[str, ...]] = {}
    queue = [(r, (display.get(r, r),)) for r in sorted(main) + sorted(dev - main) if r in graph]
    while queue:
        node, chain = queue.pop(0)
        if node in paths:
            continue
        paths[node] = chain
        queue += [(d, chain + (display.get(d, d),)) for d in graph.get(node, []) if d not in paths and d in graph]
    reach_main: set[str] = set()
    stack = [r for r in main if r in graph]
    while stack:
        n = stack.pop()
        if n not in reach_main:
            reach_main.add(n)
            stack += graph.get(n, [])
    out = []
    for p in pkgs:
        key = normalize(p["name"], "PyPI")
        is_dev = p.get("category") == "dev" or bool((main or dev) and key not in reach_main)
        out.append(Package(p["name"], p["version"], "PyPI", file, dev=is_dev, path=paths.get(key, ())))
    return out


def parse_pipfile_lock(text: str, file: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            ver = str((info or {}).get("version", ""))
            if ver.startswith("=="):
                out.append(Package(name, ver[2:], "PyPI", file, dev=section == "develop"))
    return out


def find_manifests(root: Path, files: list[str]) -> list[str]:
    names = {"package.json", "poetry.lock", "Pipfile.lock", *NPM_LOCKS}
    out = []
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        if name in names or re.fullmatch(r"requirements[\w.-]*\.(?:txt|in)", name) or \
                (rel.split("/")[-2:-1] == ["requirements"] and name.endswith(".txt")):
            if not any(p in SKIP_DIRS for p in rel.split("/")[:-1]):
                out.append(rel)
    return sorted(out)


def collect(root: Path, manifests: list[str]) -> tuple[list[Package], list[Unpinned], list[str]]:
    packages: list[Package] = []
    unpinned: list[Unpinned] = []
    notes: list[str] = []
    present = set(manifests)
    for rel in manifests:
        folder = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        name = rel.rsplit("/", 1)[-1]
        try:
            text = read_text(root / rel, root, max_bytes=MANIFEST_MAX_BYTES)
            if text is None:
                notes.append(f"Skipped {rel}: it's a symlink, binary or larger than {MANIFEST_MAX_BYTES // 1_000_000} MB.")
                continue
            if name in NPM_LOCKS:
                packages += parse_npm_lock(text, rel)
            elif name == "package.json":
                if any(folder + lock in present for lock in NPM_LOCKS):
                    continue
                other = [lock for lock in OTHER_JS_LOCKS if (root / folder / lock).exists()]
                if other:
                    notes.append(f"{folder}{other[0]} isn't supported yet; checked the exact versions in {rel} only.")
                p, u = parse_package_json(text, rel)
                packages += p
                if not other:
                    unpinned += u
            elif name == "poetry.lock":
                packages += parse_poetry_lock(text, rel, read_text(root / folder / "pyproject.toml", root))
            elif name == "Pipfile.lock":
                packages += parse_pipfile_lock(text, rel)
            else:
                p, u = parse_requirements(text, rel)
                packages += p
                unpinned += u
        except (ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
            notes.append(f"Couldn't parse {rel}: {exc}")
    seen, unique = set(), []
    for p in packages:
        key = (normalize(p.name, p.ecosystem), p.version, p.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique, unpinned, notes


# --------------------------------------------------------------------------
# OSV.dev
# --------------------------------------------------------------------------
class OSVError(RuntimeError):
    pass


class OSVClient:
    def __init__(self, session=None, timeout: int = 30, base: str = OSV_API):
        if session is None:
            import requests
            session = requests.Session()
            session.headers["User-Agent"] = "repoguard"
        self.http, self.timeout, self.base = session, timeout, base
        self._cache: dict[str, dict] = {}

    def _post(self, path: str, body: dict) -> dict:
        try:
            r = self.http.post(f"{self.base}/{path}", json=body, timeout=self.timeout)
        except Exception as exc:
            raise OSVError(f"couldn't reach OSV.dev ({type(exc).__name__})") from None
        if r.status_code != 200:
            raise OSVError(f"OSV.dev returned HTTP {r.status_code}")
        return r.json()

    def query(self, packages: list[Package]) -> list[list[str]]:
        """Vulnerability IDs for each package, in order."""
        results: list[list[str]] = [[] for _ in packages]
        for offset in range(0, len(packages), BATCH):
            chunk = list(range(offset, min(offset + BATCH, len(packages))))
            tokens: dict[int, str | None] = {i: None for i in chunk}
            while tokens:
                queries = []
                order = list(tokens)
                for i in order:
                    p = packages[i]
                    q = {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
                    if tokens[i]:
                        q["page_token"] = tokens[i]
                    queries.append(q)
                data = self._post("querybatch", {"queries": queries})
                nxt: dict[int, str | None] = {}
                for i, res in zip(order, data.get("results", [])):
                    results[i] += [v["id"] for v in (res or {}).get("vulns", []) or []]
                    if (res or {}).get("next_page_token"):
                        nxt[i] = res["next_page_token"]
                tokens = nxt
        return results

    def vuln(self, vid: str) -> dict:
        if vid not in self._cache:
            try:
                r = self.http.get(f"{self.base}/vulns/{vid}", timeout=self.timeout)
            except Exception as exc:
                raise OSVError(f"couldn't reach OSV.dev ({type(exc).__name__})") from None
            if r.status_code != 200:
                raise OSVError(f"OSV.dev returned HTTP {r.status_code} for {vid}")
            self._cache[vid] = r.json()
        return self._cache[vid]

    def vulns(self, ids: set[str]) -> dict[str, dict]:
        with ThreadPoolExecutor(max_workers=8) as pool:
            return dict(zip(ids, pool.map(self.vuln, ids)))


def severity_of(v: dict) -> Severity | None:
    ds = (v.get("database_specific") or {}).get("severity")
    if ds:
        try:
            return Severity.parse(ds)
        except ValueError:
            pass
    best = None
    for s in v.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss.base_score(s.get("score", ""))
            if score is not None:
                sev = Severity.parse(cvss.label(score))
                best = sev if best is None else max(best, sev)
    return best


def _version_key(ecosystem: str, v: str):
    if ecosystem == "PyPI":
        from packaging.version import InvalidVersion, Version
        try:
            return Version(v)
        except InvalidVersion:
            return None
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?", v)
    return (int(m[1]), int(m[2]), int(m[3]), 0 if m[4] else 1) if m else None


def fixed_version(v: dict, pkg: Package) -> str | None:
    """Lowest fixed version above the installed one, for this package."""
    want = normalize(pkg.name, pkg.ecosystem)
    current = _version_key(pkg.ecosystem, pkg.version)
    candidates = []
    for aff in v.get("affected") or []:
        ap = aff.get("package") or {}
        if normalize(ap.get("name", ""), pkg.ecosystem) != want or \
                str(ap.get("ecosystem", "")).lower() != pkg.ecosystem.lower():
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    key = _version_key(pkg.ecosystem, ev["fixed"])
                    if key is not None:
                        candidates.append((key, ev["fixed"]))
    above = [c for c in candidates if current is None or c[0] > current]
    pool = above or candidates
    return min(pool)[1] if pool else None


def _group(ids: list[str], details: dict[str, dict]) -> list[list[str]]:
    """Merge IDs that are aliases of each other (GHSA-…, PYSEC-…, CVE-…)."""
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for i in ids:
        for alias in (details.get(i) or {}).get("aliases") or []:
            if alias in parent:
                parent[find(alias)] = find(i)
    groups: dict[str, list[str]] = {}
    for i in ids:
        groups.setdefault(find(i), []).append(i)
    return list(groups.values())


def _primary(group: list[str]) -> str:
    return sorted(group, key=lambda x: (not x.startswith("GHSA-"), not x.startswith("CVE-"), x))[0]


def cvss_of(v: dict) -> tuple[float | None, str | None]:
    for s in v.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss.base_score(s.get("score", ""))
            if score is not None:
                return score, s["score"]
    return None, None


def dependency_patch(root: Path | None, pkg: Package, target: str | None) -> dict | None:
    """Exact version bump on the manifest line, for direct dependencies only."""
    if not (root and target and pkg.line):
        return None
    text = read_text(root / pkg.file, root, max_bytes=MANIFEST_MAX_BYTES)
    if text is None:
        return None
    lines = text.splitlines()
    if pkg.line > len(lines):
        return None
    line = lines[pkg.line - 1]
    if pkg.file.endswith("package.json"):
        after = re.sub(r'("' + re.escape(pkg.name) + r'"\s*:\s*")v?' + re.escape(pkg.version) + '"',
                       lambda m: m.group(1) + target + '"', line, count=1)
    else:
        after = re.sub(r"(===?\s*)" + re.escape(pkg.version) + r"(?=\s|;|$|#)", lambda m: m.group(1) + target, line, count=1)
    if after == line:
        return None
    return {"start": pkg.line, "before": [line], "after": [after]}


def vuln_findings(packages: list[Package], client: OSVClient, root: Path | None = None,
                  should_stop=None) -> list[Finding]:
    ids_per_pkg = client.query(packages)
    if should_stop:
        should_stop()
    details = client.vulns({i for ids in ids_per_pkg for i in ids})
    findings = []
    for pkg, ids in zip(packages, ids_per_pkg):
        if not ids:
            continue
        rows, fixes, worst, unfixed, vulns = [], [], Severity.LOW, [], []
        for group in _group(list(dict.fromkeys(ids)), details):
            members = [details[i] for i in group if i in details]
            sevs = [s for s in (severity_of(m) for m in members) if s is not None]
            sev = max(sevs) if sevs else Severity.MEDIUM
            worst = max(worst, sev)
            primary = _primary(group)
            cves = sorted({a for m in members for a in (m.get("aliases") or []) + [m.get("id", "")]
                           if a.startswith("CVE-")})
            aliases = sorted({a for m in members for a in (m.get("aliases") or []) + [m.get("id", "")]} - {primary, ""})
            summary = next((m.get("summary") for m in sorted(members, key=lambda m: not m.get("id", "").startswith("GHSA-"))
                            if m.get("summary")), "") or "No summary available"
            fix = next((f for f in (fixed_version(m, pkg) for m in members) if f), None)
            scored = [cvss_of(m) for m in members]
            score, vector = max(scored, key=lambda x: x[0] if x[0] is not None else -1, default=(None, None))
            if fix:
                fixes.append(fix)
            else:
                unfixed.append(primary)
            label = primary + (f" ({', '.join(cves)})" if cves and primary not in cves else "")
            rows.append((sev, f"- [{sev.label}] {label}: {summary}" + (f" Fixed in {fix}." if fix else ""), primary))
            vulns.append({"id": primary, "aliases": aliases, "severity": sev.label, "cvss": score,
                          "vector": vector, "summary": summary, "fixed": fix,
                          "url": f"https://osv.dev/vulnerability/{primary}"})
        rows.sort(key=lambda r: -r[0])
        vulns.sort(key=lambda v: (-Severity.parse(v["severity"]), -(v["cvss"] or 0)))
        n = len(rows)
        valid = [f for f in fixes if _version_key(pkg.ecosystem, f) is not None]
        target = max(valid, key=lambda f: _version_key(pkg.ecosystem, f)) if valid else (fixes[0] if fixes else None)
        direct = len(pkg.path) == 1
        fix_text = f"Upgrade {pkg.name} to {target} or later" if target else f"No fixed version of {pkg.name} is listed yet"
        if target and unfixed:
            fix_text += f". {', '.join(unfixed)} has no fix yet, so check whether the vulnerable feature is used"
        if target and not direct and pkg.ecosystem == "npm" and len(pkg.path) > 1:
            fix_text += (f". It comes in through {pkg.path[0]}, so first try updating that "
                         f"(`npm update {pkg.path[0]}`); if it still pins {pkg.name}, add "
                         f'`"overrides": {{"{pkg.name}": "{target}"}}` to package.json')
        fix_text += f" (in {pkg.file}), then re-run the scan."
        findings.append(Finding(
            rule="dependency/vulnerable", category="dependencies", severity=worst,
            title=f"{pkg.name} {pkg.version} has {n} known vulnerabilit{'y' if n == 1 else 'ies'}",
            file=pkg.file, line=pkg.line,
            description=f"{pkg.ecosystem} package {pkg.name}=={pkg.version}:\n" + "\n".join(r[1] for r in rows),
            fix=fix_text, references=[f"https://osv.dev/vulnerability/{r[2]}" for r in rows],
            details={"package": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem, "manifest": pkg.file,
                     "path": list(pkg.path), "direct": direct, "dev": pkg.dev, "fixed_in": target, "vulns": vulns},
            patch=dependency_patch(root, pkg, target) if direct else None,
            fingerprint=f"dep-{pkg.ecosystem}-{normalize(pkg.name, pkg.ecosystem)}-{pkg.version}"))
    return findings


def unpinned_findings(unpinned: list[Unpinned]) -> list[Finding]:
    by_file: dict[str, list[Unpinned]] = {}
    for u in unpinned:
        by_file.setdefault(u.file, []).append(u)
    out = []
    for file, items in by_file.items():
        n = len(items)
        listed = ", ".join(f"{u.name} {u.spec}".strip() for u in items[:15]) + (" …" if n > 15 else "")
        example = items[0].name
        if file.endswith("package.json"):
            fix = ("Commit a lock file (run `npm install` and commit package-lock.json, then use `npm ci` in CI) "
                   "so every build installs the exact same, checkable versions.")
        else:
            fix = (f"Pin exact versions, e.g. `{example}==<version>`, or generate a lock file with "
                   "pip-tools (`pip-compile`) or Poetry. Then Dependabot can propose upgrades as PRs.")
        out.append(Finding(
            rule="dependency/unpinned", category="dependencies", severity=Severity.LOW,
            title=f"{n} unpinned dependenc{'y' if n == 1 else 'ies'} in {file}",
            file=file, line=items[0].line,
            description=(f"These don't specify an exact version: {listed}. Each install can pull a different "
                         "release, so builds aren't reproducible, a compromised new release would be "
                         "picked up automatically, and the exact versions can't be checked for vulnerabilities."),
            fix=fix, fingerprint=f"unpinned-{file}",
            details={"manifest": file, "packages": [{"name": u.name, "spec": u.spec, "line": u.line} for u in items]}))
    return out


def scan(root: Path, files: list[str], *, offline: bool = False,
         client: OSVClient | None = None) -> tuple[list[Finding], dict, list[str]]:
    manifests = find_manifests(root, files)
    packages, unpinned, notes = collect(root, manifests)
    findings = unpinned_findings(unpinned)
    stats = {"manifests": len(manifests), "packages_checked": 0}
    if packages and not offline:
        try:
            findings += vuln_findings(packages, client or OSVClient(), root)
            stats["packages_checked"] = len(packages)
        except OSVError as exc:
            notes.append(f"Dependency vulnerabilities weren't checked: {exc}.")
    elif packages and offline:
        notes.append("Dependency vulnerabilities weren't checked (offline mode).")
    return findings, stats, notes
