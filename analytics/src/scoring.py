"""Weighted risk scoring for VulnLens findings.

Raw scanner output is just a flat list with a coarse HIGH/MEDIUM/LOW label.
This module turns each finding into a single, comparable risk score on a
0-100 scale so a developer knows what to fix first.

The score is a deterministic weighted product of three factors:

    risk = severity x confidence x exploitability

* **severity**       - how damaging the issue is if exploited (from the
                       scanner's HIGH/MEDIUM/LOW rating).
* **confidence**     - how reliable the regex-based detection is for this
                       vulnerability type (fewer false positives -> higher).
* **exploitability** - how easily an attacker can actually leverage it.

Each factor is in ``[0, 1]``; the product is scaled to ``[0, 100]``. No model,
no training data - just a transparent formula tuned per vulnerability type.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

# How damaging each severity band is (the multiplicative weight in the formula).
SEVERITY_WEIGHTS: dict[str, float] = {
    "HIGH": 1.0,
    "MEDIUM": 0.6,
    "LOW": 0.3,
}

# Detection confidence per vulnerability type: how precise the scanner's regex
# rules are. Highly specific patterns (AWS keys, MD5) score high; broad
# heuristics (hard-coded IPs, security TODOs) score lower.
CONFIDENCE_BY_TYPE: dict[str, float] = {
    "HARDCODED_SECRET": 0.85,
    "SQL_INJECTION": 0.70,
    "NOSQL_INJECTION": 0.70,
    "XSS": 0.75,
    "PATH_TRAVERSAL": 0.65,
    "INSECURE_FUNCTION": 0.80,
    "INSECURE_RANDOM": 0.60,
    "SENSITIVE_DATA_LOG": 0.70,
    "HARDCODED_IP": 0.60,
    "SECURITY_TODO": 0.50,
    "WEAK_CRYPTO": 0.85,
}

# Exploitability per vulnerability type: how readily an attacker can turn the
# weakness into real impact. Injection/secret exposure is high; informational
# findings like TODO comments are low.
EXPLOITABILITY_BY_TYPE: dict[str, float] = {
    "HARDCODED_SECRET": 0.90,
    "SQL_INJECTION": 0.95,
    "NOSQL_INJECTION": 0.90,
    "XSS": 0.85,
    "PATH_TRAVERSAL": 0.80,
    "INSECURE_FUNCTION": 0.95,
    "INSECURE_RANDOM": 0.50,
    "SENSITIVE_DATA_LOG": 0.40,
    "HARDCODED_IP": 0.30,
    "SECURITY_TODO": 0.20,
    "WEAK_CRYPTO": 0.60,
}

# Fallbacks for vulnerability types not in the tables above (e.g. a new scanner
# rule that analytics hasn't been tuned for yet) - neutral 0.5 each.
DEFAULT_CONFIDENCE = 0.5
DEFAULT_EXPLOITABILITY = 0.5

# Risk-level buckets keyed off the 0-100 score. Thresholds are tuned to the
# range the formula actually produces (max ~85 for a HIGH-severity injection).
RISK_LEVEL_THRESHOLDS: list[tuple[float, str]] = [
    (60.0, "CRITICAL"),
    (35.0, "HIGH"),
    (15.0, "MEDIUM"),
    (0.0, "LOW"),
]


def severity_weight(severity: str | None) -> float:
    """Return the multiplicative weight for a severity label (defaults to LOW)."""
    if not severity:
        return SEVERITY_WEIGHTS["LOW"]
    return SEVERITY_WEIGHTS.get(severity.upper(), SEVERITY_WEIGHTS["LOW"])


def confidence_for(vuln_type: str | None) -> float:
    """Detection confidence for a vulnerability type (``DEFAULT_CONFIDENCE`` if unknown)."""
    return CONFIDENCE_BY_TYPE.get(vuln_type, DEFAULT_CONFIDENCE)


def exploitability_for(vuln_type: str | None) -> float:
    """Exploitability for a vulnerability type (``DEFAULT_EXPLOITABILITY`` if unknown)."""
    return EXPLOITABILITY_BY_TYPE.get(vuln_type, DEFAULT_EXPLOITABILITY)


def risk_score(finding: dict[str, Any]) -> float:
    """Compute the 0-100 weighted risk score for a single finding.

    Uses the finding's ``severity`` and its ``id``/``type`` to look up the
    factors. A finding may override the per-type defaults by supplying its own
    ``confidence`` or ``exploitability`` keys (both expected in ``[0, 1]``).
    """
    vuln_type = finding.get("id") or finding.get("type")

    sev = severity_weight(finding.get("severity"))
    conf = float(finding.get("confidence", confidence_for(vuln_type)))
    expl = float(finding.get("exploitability", exploitability_for(vuln_type)))

    # Clamp overrides into the valid range so a bad input can't blow past 100.
    conf = min(max(conf, 0.0), 1.0)
    expl = min(max(expl, 0.0), 1.0)

    return round(sev * conf * expl * 100.0, 1)


def risk_level(score: float) -> str:
    """Map a numeric risk score to a CRITICAL/HIGH/MEDIUM/LOW band."""
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "LOW"


def score_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``finding`` annotated with its risk score and components."""
    vuln_type = finding.get("id") or finding.get("type")
    scored = deepcopy(finding)

    score = risk_score(finding)
    scored["risk_score"] = score
    scored["risk_level"] = risk_level(score)
    scored["risk_factors"] = {
        "severity_weight": severity_weight(finding.get("severity")),
        "confidence": min(max(float(finding.get("confidence", confidence_for(vuln_type))), 0.0), 1.0),
        "exploitability": min(max(float(finding.get("exploitability", exploitability_for(vuln_type))), 0.0), 1.0),
    }
    return scored


def score_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Score every finding and return them sorted by risk, highest first."""
    scored = [score_finding(f) for f in findings]
    scored.sort(key=lambda f: f["risk_score"], reverse=True)
    return scored


def aggregate_risk(scored_findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarise a scored finding list into an overall risk picture.

    Returns the highest single score, the mean score, a count per risk level,
    and the top finding - the headline a developer should act on first.
    """
    if not scored_findings:
        return {
            "total_findings": 0,
            "max_risk_score": 0.0,
            "mean_risk_score": 0.0,
            "level_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "top_finding": None,
        }

    scores = [f["risk_score"] for f in scored_findings]
    level_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in scored_findings:
        level_counts[f.get("risk_level", risk_level(f["risk_score"]))] += 1

    top = max(scored_findings, key=lambda f: f["risk_score"])

    return {
        "total_findings": len(scored_findings),
        "max_risk_score": max(scores),
        "mean_risk_score": round(sum(scores) / len(scores), 1),
        "level_counts": level_counts,
        "top_finding": top,
    }
