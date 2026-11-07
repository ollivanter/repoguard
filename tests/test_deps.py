import json

import pytest

from repoguard import cvss, deps
from repoguard.models import Severity


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss(vector, score):
    assert cvss.base_score(vector) == score


def test_cvss_bad_vectors():
    assert cvss.base_score("CVSS:4.0/AV:N/AC:L") is None
    assert cvss.base_score("CVSS:3.1/AV:N") is None


def test_parse_requirements():
    text = """
# comment
requests==2.31.0
Flask[async] == 2.0.1 ; python_version >= "3.8"
numpy>=1.24
django
pandas==2.*
-r other.txt
--index-url https://example.org
git+https://github.com/x/y.git
pyyaml==6.0.1 \\
    --hash=sha256:abc
"""
    pinned, unpinned = deps.parse_requirements(text, "requirements.txt")
    assert [(p.name, p.version, p.line) for p in pinned] == [
        ("requests", "2.31.0", 3), ("Flask", "2.0.1", 4), ("pyyaml", "6.0.1", 11)]
    assert [(u.name, u.spec) for u in unpinned] == [
        ("numpy", ">=1.24"), ("django", "(any version)"), ("pandas", "==2.*")]


def test_parse_npm_lock_v3_and_v1():
    v3 = {"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/a/node_modules/minimist": {"version": "1.2.0"},
        "node_modules/local": {"link": True, "resolved": "../local"}}}
    assert [(p.name, p.version) for p in deps.parse_npm_lock(json.dumps(v3), "package-lock.json")] == [
        ("lodash", "4.17.20"), ("minimist", "1.2.0")]
    v1 = {"lockfileVersion": 1, "dependencies": {
        "express": {"version": "4.17.1", "dependencies": {"qs": {"version": "6.7.0"}}}}}
    assert [(p.name, p.version) for p in deps.parse_npm_lock(json.dumps(v1), "x")] == [
        ("express", "4.17.1"), ("qs", "6.7.0")]


def test_parse_package_json():
    text = json.dumps({"dependencies": {"react": "18.2.0", "axios": "^1.6.0", "mine": "file:../mine"},
                       "devDependencies": {"vite": "~5.0.0"}}, indent=2)
    pinned, unpinned = deps.parse_package_json(text, "package.json")
    assert [(p.name, p.version) for p in pinned] == [("react", "18.2.0")]
    assert {u.name for u in unpinned} == {"axios", "vite"}
    assert pinned[0].line == 3


def test_poetry_and_pipfile_locks():
    poetry = '[[package]]\nname = "Jinja2"\nversion = "2.10"\n\n[[package]]\nname = "click"\nversion = "8.1.7"\n'
    assert [(p.name, p.version) for p in deps.parse_poetry_lock(poetry, "poetry.lock")] == [
        ("Jinja2", "2.10"), ("click", "8.1.7")]
    pip = json.dumps({"default": {"requests": {"version": "==2.19.0"}}, "develop": {"pytest": {"version": "==7.0.0"}}})
    assert [(p.name, p.version) for p in deps.parse_pipfile_lock(pip, "Pipfile.lock")] == [
        ("requests", "2.19.0"), ("pytest", "7.0.0")]


def test_package_json_skipped_when_lockfile_present(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"axios": "^1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/axios": {"version": "1.6.0"}}}))
    files = ["package.json", "package-lock.json"]
    packages, unpinned, notes = deps.collect(tmp_path, deps.find_manifests(tmp_path, files))
    assert [(p.name, p.version) for p in packages] == [("axios", "1.6.0")]
    assert unpinned == [] and notes == []


# ---------------------------------------------------------------- OSV fake
class Resp:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def json(self):
        return self._data


class FakeOSV:
    """Mimics api.osv.dev: querybatch returns only ids; /vulns/{id} returns details."""

    def __init__(self, db, fail=False):
        self.db, self.fail, self.calls = db, fail, []

    def post(self, url, json=None, timeout=None):
        self.calls.append(("POST", url))
        if self.fail:
            raise ConnectionError("blocked")
        results = []
        for q in json["queries"]:
            key = (q["package"]["ecosystem"], q["package"]["name"], q["version"])
            ids = [v["id"] for v in self.db.values() if key in v.get("_hits", [])]
            results.append({"vulns": [{"id": i, "modified": "2024-01-01T00:00:00Z"} for i in ids]} if ids else {})
        return Resp({"results": results})

    def get(self, url, timeout=None):
        self.calls.append(("GET", url))
        vid = url.rsplit("/", 1)[-1]
        return Resp({k: v for k, v in self.db[vid].items() if k != "_hits"})


def affected(eco, name, fixed):
    return [{"package": {"ecosystem": eco, "name": name},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}] + [{"fixed": f} for f in fixed]}]}]


DB = {
    "GHSA-aaaa-bbbb-cccc": {"id": "GHSA-aaaa-bbbb-cccc", "summary": "Sandbox escape in Jinja2",
                            "aliases": ["CVE-2019-10906", "PYSEC-2019-217"],
                            "database_specific": {"severity": "HIGH"},
                            "affected": affected("PyPI", "jinja2", ["2.10.1"]),
                            "_hits": [("PyPI", "Jinja2", "2.10")]},
    "PYSEC-2019-217": {"id": "PYSEC-2019-217", "aliases": ["CVE-2019-10906", "GHSA-aaaa-bbbb-cccc"],
                       "affected": affected("PyPI", "jinja2", ["2.10.1"]),
                       "_hits": [("PyPI", "Jinja2", "2.10")]},
    "GHSA-dddd-eeee-ffff": {"id": "GHSA-dddd-eeee-ffff", "summary": "XSS via xmlattr",
                            "aliases": ["CVE-2024-22195"],
                            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
                            "affected": affected("PyPI", "Jinja2", ["3.1.3"]),
                            "_hits": [("PyPI", "Jinja2", "2.10")]},
    "GHSA-gggg-hhhh-iiii": {"id": "GHSA-gggg-hhhh-iiii", "summary": "Prototype pollution",
                            "database_specific": {"severity": "CRITICAL"},
                            "affected": affected("npm", "lodash", ["4.17.12", "4.17.21"]),
                            "_hits": [("npm", "lodash", "4.17.20")]},
}


def test_vulnerable_packages_end_to_end():
    pkgs = [deps.Package("Jinja2", "2.10", "PyPI", "requirements.txt", 2),
            deps.Package("lodash", "4.17.20", "npm", "package-lock.json"),
            deps.Package("click", "8.1.7", "PyPI", "requirements.txt", 3)]
    findings = deps.vuln_findings(pkgs, deps.OSVClient(session=FakeOSV(DB)))
    assert len(findings) == 2
    jinja, lodash = findings
    # PYSEC + GHSA aliases of the same issue count once; the second GHSA is separate.
    assert jinja.title == "Jinja2 2.10 has 2 known vulnerabilities"
    assert jinja.severity == Severity.HIGH
    assert "CVE-2019-10906" in jinja.description and "PYSEC" not in jinja.description.split("\n")[1]
    assert "[medium] GHSA-dddd-eeee-ffff" in jinja.description          # CVSS 6.1 → medium
    assert jinja.fix.startswith("Upgrade Jinja2 to 3.1.3 or later")    # clears both issues
    assert jinja.line == 2
    assert lodash.severity == Severity.CRITICAL
    assert "Upgrade lodash to 4.17.21" in lodash.fix                   # 4.17.12 is below the installed version


def test_osv_unreachable_becomes_a_note(tmp_path):
    (tmp_path / "requirements.txt").write_text("Jinja2==2.10\nrequests\n")
    findings, stats, notes = deps.scan(tmp_path, ["requirements.txt"],
                                       client=deps.OSVClient(session=FakeOSV(DB, fail=True)))
    assert [f.rule for f in findings] == ["dependency/unpinned"]
    assert any("weren't checked" in n for n in notes)
    assert stats["packages_checked"] == 0


def test_offline_mode_makes_no_requests(tmp_path):
    (tmp_path / "requirements.txt").write_text("Jinja2==2.10\n")
    fake = FakeOSV(DB)
    deps.scan(tmp_path, ["requirements.txt"], offline=True, client=deps.OSVClient(session=fake))
    assert fake.calls == []


def test_unpinned_grouped_per_file():
    us = [deps.Unpinned("numpy", ">=1", "requirements.txt", 1), deps.Unpinned("django", "(any version)", "requirements.txt", 2),
          deps.Unpinned("axios", "^1.6.0", "web/package.json", 4)]
    findings = deps.unpinned_findings(us)
    assert [f.title for f in findings] == ["2 unpinned dependencies in requirements.txt",
                                           "1 unpinned dependency in web/package.json"]
    assert "lock file" in findings[1].fix
