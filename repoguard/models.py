"""Shared data types."""
from __future__ import annotations

import enum
import hashlib
from dataclasses import asdict, dataclass, field


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        text = str(value).strip().lower()
        text = {"moderate": "medium", "none": "info", "informational": "info"}.get(text, text)
        try:
            return cls[text.upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None

    def downgraded(self) -> "Severity":
        return Severity(max(self - 1, Severity.LOW))


CATEGORIES = ("secrets", "dependencies", "workflows", "containers")


@dataclass
class Finding:
    rule: str
    title: str
    severity: Severity
    category: str
    file: str | None = None
    line: int | None = None
    description: str = ""
    fix: str = ""
    evidence: str = ""
    commit: str | None = None
    references: list[str] = field(default_factory=list)
    fingerprint: str = ""
    details: dict = field(default_factory=dict)      # structured data for the UI (dependency path, CVSS…)
    patch: dict | None = None                        # {"start": line, "before": [...], "after": [...]}

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category {self.category!r}")
        if not self.fingerprint:
            raw = "|".join(str(x) for x in (self.rule, self.file, self.line, self.title, self.commit))
            self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def location(self) -> str:
        if not self.file:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    score: int = 100
    grade: str = "A"
    repo: str | None = None          # "owner/name" when known
    commit: str | None = None        # HEAD sha when known
    server_url: str = "https://github.com"
    scanned_at: str = ""
    meta: dict = field(default_factory=dict)         # repository metadata from the GitHub API
    categories: tuple[str, ...] = CATEGORIES

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.category, f.file or "", f.line or 0))

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict:
        from .scoring import breakdown
        return {
            "version": 2,
            "target": self.target,
            "repo": self.repo,
            "commit": self.commit,
            "scanned_at": self.scanned_at,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts(),
            "stats": self.stats,
            "notes": self.notes,
            "meta": self.meta,
            "server_url": self.server_url,
            "categories": list(self.categories),
            "breakdown": breakdown(self.findings),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
