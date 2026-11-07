"""Turn findings into a 0–100 score and a letter grade.

Each rule costs points by severity. Repeats of the same rule cost less each time
(1 + log2(n)), so 20 unpinned actions don't outweigh one leaked key.
"""
from __future__ import annotations

import math
from collections import defaultdict

from .models import Finding, Severity

WEIGHTS = {Severity.CRITICAL: 25, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 0}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def deductions(findings: list[Finding]) -> dict[tuple[str, Severity], float]:
    counts: dict[tuple[str, Severity], int] = defaultdict(int)
    for f in findings:
        counts[(f.rule, f.severity)] += 1
    return {k: WEIGHTS[k[1]] * (1 + math.log2(n)) for k, n in counts.items()}


def score(findings: list[Finding]) -> tuple[int, str]:
    total = sum(deductions(findings).values())
    value = max(0, round(100 - total))
    if any(f.severity == Severity.CRITICAL for f in findings):
        value = min(value, 59)           # a live critical issue is always a failing grade
    grade = next(g for cutoff, g in GRADES if value >= cutoff)
    return value, grade


def breakdown(findings: list[Finding]) -> list[dict]:
    """Points lost per rule, biggest first, for the score explanation."""
    counts: dict[tuple[str, Severity], int] = defaultdict(int)
    for f in findings:
        counts[(f.rule, f.severity)] += 1
    rows = [{"rule": rule, "severity": sev.label, "count": n, "points": round(pts, 1)}
            for (rule, sev), pts in deductions(findings).items() for n in [counts[(rule, sev)]]]
    return sorted(rows, key=lambda r: (-r["points"], r["rule"]))
