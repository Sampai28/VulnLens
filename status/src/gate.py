"""The security gate: turn a scan into a pass/fail decision for GitHub.

This is the policy layer of the Status Lambda, kept pure so it can be unit
tested with plain dicts and reused anywhere. It answers two questions:

* **Does this scan pass the gate?** - by default the gate fails a commit if the
  scan contains any finding at or above ``GATE_FAIL_SEVERITY`` (``HIGH`` by
  default). This matches the pipeline contract: "pass (no HIGH), fail (HIGH found)".
* **What do we tell the developer?** - a one-line commit-status ``description``
  (GitHub caps these at 140 chars) and a richer Markdown PR comment that surfaces
  the severity counts, the analytics risk summary, and the top findings to fix.

The functions here operate on the scan item as stored in DynamoDB
(``sast/src/aws.js`` shape) optionally enriched with an ``analysis`` block by the
analytics Lambda (``analytics/src/engine.py`` shape).
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any, Optional

# Severity ranking used to evaluate the gate threshold. Higher = worse.
_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

# Severity at or above which the gate fails the commit. Configurable so a team
# can tighten ("MEDIUM") or loosen ("HIGH") the bar without a code change.
FAIL_SEVERITY = os.environ.get("GATE_FAIL_SEVERITY", "HIGH").upper()

# Commit-status context string shown in the GitHub PR checks list.
STATUS_CONTEXT = os.environ.get("STATUS_CONTEXT", "vulnlens/security-gate")

# GitHub truncates commit-status descriptions at 140 characters.
_MAX_DESCRIPTION = 140


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings per severity band (always reports HIGH/MEDIUM/LOW)."""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _fails_gate(counts: dict[str, int]) -> bool:
    """True if any finding meets or exceeds the configured fail severity."""
    threshold = _SEVERITY_RANK.get(FAIL_SEVERITY, 3)
    return any(
        count > 0 and _SEVERITY_RANK.get(sev, 1) >= threshold
        for sev, count in counts.items()
    )


def evaluate(scan: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the gate for a scan item.

    Args:
        scan: the DynamoDB scan item - ``findings`` plus an optional ``analysis``
            block from the analytics Lambda.

    Returns:
        A decision dict with the GitHub commit-status ``state``
        (``success``/``failure``), the short ``description``, the ``context``,
        the per-severity ``counts``, and a Markdown ``comment`` body for the PR.
    """
    findings = scan.get("findings", [])
    counts = _severity_counts(findings)
    failed = _fails_gate(counts)

    return {
        "state": "failure" if failed else "success",
        "context": STATUS_CONTEXT,
        "description": _description(counts, failed),
        "counts": counts,
        "passed": not failed,
        "comment": _comment(scan, counts, failed),
    }


def _description(counts: dict[str, int], failed: bool) -> str:
    """One-line commit-status summary (kept under GitHub's 140-char cap)."""
    summary = f"{counts['HIGH']} HIGH / {counts['MEDIUM']} MEDIUM / {counts['LOW']} LOW"
    if failed:
        text = f"Security gate failed - {summary}. Fix {FAIL_SEVERITY}+ findings to merge."
    elif counts["HIGH"] + counts["MEDIUM"] + counts["LOW"] == 0:
        text = "Security gate passed - no vulnerabilities found."
    else:
        text = f"Security gate passed - {summary}."
    return text[:_MAX_DESCRIPTION]


def _comment(scan: dict[str, Any], counts: dict[str, int], failed: bool) -> str:
    """Render the Markdown PR comment: verdict, severity table, top findings."""
    verdict = "**Security gate: FAILED**" if failed else "**Security gate: PASSED**"
    lines = [
        "## VulnLens security scan",
        "",
        verdict,
        "",
        "| Severity | Count |",
        "| --- | --- |",
        f"| HIGH | {counts['HIGH']} |",
        f"| MEDIUM | {counts['MEDIUM']} |",
        f"| LOW | {counts['LOW']} |",
        "",
    ]

    analysis = scan.get("analysis") or {}
    risk = analysis.get("risk") or {}
    if risk:
        lines += [
            f"**Risk score:** {risk.get('max_risk_score', 0)} (max), "
            f"{risk.get('mean_risk_score', 0)} (mean) over "
            f"{risk.get('total_findings', 0)} findings.",
            "",
        ]

    top = _top_findings(scan)
    if top:
        lines.append("### Top findings")
        for f in top:
            loc = _format_location(f)
            score = f.get("risk_score")
            score_txt = f", risk {score}" if score is not None else ""
            name = f.get("name") or f.get("id") or f.get("type") or "Finding"
            lines.append(f"- **{f.get('severity', 'LOW')}** {name}{score_txt} - `{loc}`")
        lines.append("")

    lines.append("_Posted by the VulnLens analytics pipeline._")
    return "\n".join(lines)


def _top_findings(scan: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    """Pick the highest-priority findings to highlight.

    Prefers the analytics-scored findings (already sorted by ``risk_score``); if
    analytics didn't run, falls back to the raw findings sorted by severity.
    """
    analysis = scan.get("analysis") or {}
    scored = analysis.get("findings")
    if scored:
        return scored[:limit]

    raw = list(scan.get("findings", []))
    raw.sort(key=lambda f: _SEVERITY_RANK.get((f.get("severity") or "LOW").upper(), 1), reverse=True)
    return raw[:limit]


def _format_location(finding: dict[str, Any]) -> str:
    """Human-friendly ``file:line`` for a finding."""
    file = finding.get("file") or finding.get("filename") or "?"
    line = finding.get("line")
    return f"{file}:{line}" if line is not None else str(file)


def github_context(scan: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Extract and validate the GitHub context needed to post a status.

    The pipeline threads a ``github`` block onto the scan item so the gate can
    report back to the originating commit::

        {"github": {"owner": "...", "repo": "...", "sha": "...", "pr_number": 12}}

    Returns the block only if ``owner``, ``repo`` and ``sha`` are all present;
    otherwise ``None`` (the caller then logs and skips the GitHub post). This is
    what lets the pipeline run end-to-end before the GitHub wiring is in place.
    """
    gh = scan.get("github") or {}
    if gh.get("owner") and gh.get("repo") and gh.get("sha"):
        return gh
    return None
