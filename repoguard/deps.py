"""Vulnerable and unpinned dependencies, checked against the OSV.dev database."""
from __future__ import annotations

import json
import re
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import cvss
from .files import SKIP_DIRS
from .models import Finding, Severity

OSV_API = "https://api.osv.dev/v1"
BATCH = 500
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")
OTHER_JS_LOCKS = ("yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock")


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str      # "PyPI" or "npm"
    file: str
    line: int | None = None


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
            pinned.append(Package(name, exact.group(1), "PyPI", file, start))
        else:
            unpinned.append(Unpinned(name, spec or "(any version)", file, start))
    return pinned, unpinned


def parse_npm_lock(text: str, file: str) -> list[Package]:
    data = json.loads(text)
    out: list[Package] = []
    if isinstance(data.get("packages"), dict):
        for key, info in data["packages"].items():
            if not key or not isinstance(info, dict) or info.get("link"):
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            if info.get("version"):
                out.append(Package(name, info["version"], "npm", file))
    else:
        def walk(deps: dict) -> None:
            for name, info in (deps or {}).items():
                if isinstance(info, dict):
                    if info.get("version") and not str(info["version"]).startswith(("file:", "git", "http")):
                        out.append(Package(name, info["version"], "npm", file))
                    walk(info.get("dependencies"))
        walk(data.get("dependencies"))
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
                pinned.append(Package(name, spec.lstrip("v"), "npm", file, line))
            else:
                unpinned.append(Unpinned(name, spec, file, line))
    return pinned, unpinned


def parse_poetry_lock(text: str, file: str) -> list[Package]:
    data = tomllib.loads(text)
    return [Package(p["name"], p["version"], "PyPI", file) for p in data.get("package", [])
            if p.get("name") and p.get("version")]


def parse_pipfile_lock(text: str, file: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            ver = str((info or {}).get("version", ""))
            if ver.startswith("=="):
                out.append(Package(name, ver[2:], "PyPI", file))
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
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
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
                packages += parse_poetry_lock(text, rel)
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


def vuln_findings(packages: list[Package], client: OSVClient) -> list[Finding]:
    ids_per_pkg = client.query(packages)
    details = client.vulns({i for ids in ids_per_pkg for i in ids})
    findings = []
    for pkg, ids in zip(packages, ids_per_pkg):
        if not ids:
            continue
        rows, fixes, worst, unfixed = [], [], Severity.LOW, []
        for group in _group(list(dict.fromkeys(ids)), details):
            members = [details[i] for i in group if i in details]
            sevs = [s for s in (severity_of(m) for m in members) if s is not None]
            sev = max(sevs) if sevs else Severity.MEDIUM
            worst = max(worst, sev)
            primary = _primary(group)
            cves = sorted({a for m in members for a in (m.get("aliases") or []) + [m.get("id", "")]
                           if a.startswith("CVE-")})
            summary = next((m.get("summary") for m in sorted(members, key=lambda m: not m.get("id", "").startswith("GHSA-"))
                            if m.get("summary")), "") or "No summary available"
            fix = next((f for f in (fixed_version(m, pkg) for m in members) if f), None)
            if fix:
                fixes.append(fix)
            else:
                unfixed.append(primary)
            label = primary + (f" ({', '.join(cves)})" if cves and primary not in cves else "")
            rows.append((sev, f"- [{sev.label}] {label}: {summary}" + (f" Fixed in {fix}." if fix else ""), primary))
        rows.sort(key=lambda r: -r[0])
        n = len(rows)
        valid = [f for f in fixes if _version_key(pkg.ecosystem, f) is not None]
        target = max(valid, key=lambda f: _version_key(pkg.ecosystem, f)) if valid else (fixes[0] if fixes else None)
        fix_text = f"Upgrade {pkg.name} to {target} or later" if target else f"No fixed version of {pkg.name} is listed yet"
        if target and unfixed:
            fix_text += f". {', '.join(unfixed)} has no fix yet, so check whether the vulnerable feature is used"
        fix_text += f" (in {pkg.file}), then re-run the scan."
        findings.append(Finding(
            rule="dependency/vulnerable", category="dependencies", severity=worst,
            title=f"{pkg.name} {pkg.version} has {n} known vulnerabilit{'y' if n == 1 else 'ies'}",
            file=pkg.file, line=pkg.line,
            description=f"{pkg.ecosystem} package {pkg.name}=={pkg.version}:\n" + "\n".join(r[1] for r in rows),
            fix=fix_text, references=[f"https://osv.dev/vulnerability/{r[2]}" for r in rows],
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
            fix=fix, fingerprint=f"unpinned-{file}"))
    return out


def scan(root: Path, files: list[str], *, offline: bool = False,
         client: OSVClient | None = None) -> tuple[list[Finding], dict, list[str]]:
    manifests = find_manifests(root, files)
    packages, unpinned, notes = collect(root, manifests)
    findings = unpinned_findings(unpinned)
    stats = {"manifests": len(manifests), "packages_checked": 0}
    if packages and not offline:
        try:
            findings += vuln_findings(packages, client or OSVClient())
            stats["packages_checked"] = len(packages)
        except OSVError as exc:
            notes.append(f"Dependency vulnerabilities weren't checked: {exc}.")
    elif packages and offline:
        notes.append("Dependency vulnerabilities weren't checked (offline mode).")
    return findings, stats, notes
