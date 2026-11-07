"""Talks to the real OSV.dev API. Runs only when REPOGUARD_LIVE=1 (in CI)."""
import os

import pytest

from repoguard import deps
from repoguard.models import Severity

pytestmark = pytest.mark.skipif(os.environ.get("REPOGUARD_LIVE") != "1", reason="set REPOGUARD_LIVE=1")


def test_known_vulnerable_versions(tmp_path):
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\nrequests==2.19.0\n")
    findings, stats, notes = deps.scan(tmp_path, ["requirements.txt"])
    assert notes == [] and stats["packages_checked"] == 2
    by_name = {f.title.split()[0]: f for f in findings}
    jinja = by_name["jinja2"]
    assert "CVE-2019-10906" in jinja.description       # sandbox escape, fixed in 2.10.1
    assert jinja.severity >= Severity.HIGH
    assert jinja.fix.startswith("Upgrade jinja2 to ")
    assert "requests" in by_name


def test_clean_version_has_no_findings(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.34.2\n")
    findings, stats, notes = deps.scan(tmp_path, ["requirements.txt"])
    assert findings == [] and notes == [] and stats["packages_checked"] == 1
