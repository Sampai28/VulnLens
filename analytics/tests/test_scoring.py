"""Tests for the weighted risk scoring formula."""

import pytest

from src.scoring import (
    aggregate_risk,
    confidence_for,
    exploitability_for,
    risk_level,
    risk_score,
    score_finding,
    score_findings,
    severity_weight,
)


def test_severity_weight_ordering():
    assert severity_weight("HIGH") > severity_weight("MEDIUM") > severity_weight("LOW")


def test_severity_weight_is_case_insensitive():
    assert severity_weight("high") == severity_weight("HIGH")


def test_severity_weight_unknown_defaults_to_low():
    assert severity_weight("BOGUS") == severity_weight("LOW")
    assert severity_weight(None) == severity_weight("LOW")


def test_risk_score_is_product_scaled_to_100():
    finding = {"id": "SQL_INJECTION", "severity": "HIGH"}
    expected = severity_weight("HIGH") * confidence_for("SQL_INJECTION") * exploitability_for("SQL_INJECTION") * 100
    assert risk_score(finding) == pytest.approx(round(expected, 1))


def test_risk_score_in_range():
    for vuln_type in ("HARDCODED_SECRET", "SQL_INJECTION", "SECURITY_TODO", "HARDCODED_IP"):
        for sev in ("HIGH", "MEDIUM", "LOW"):
            score = risk_score({"id": vuln_type, "severity": sev})
            assert 0.0 <= score <= 100.0


def test_high_severity_injection_outranks_low_severity_todo():
    inj = risk_score({"id": "SQL_INJECTION", "severity": "HIGH"})
    todo = risk_score({"id": "SECURITY_TODO", "severity": "LOW"})
    assert inj > todo


def test_unknown_type_uses_neutral_defaults():
    score = risk_score({"id": "BRAND_NEW_RULE", "severity": "HIGH"})
    # severity_weight(HIGH)=1.0 * 0.5 * 0.5 * 100 = 25.0
    assert score == pytest.approx(25.0)


def test_finding_can_override_factors():
    base = risk_score({"id": "SECURITY_TODO", "severity": "LOW"})
    boosted = risk_score(
        {"id": "SECURITY_TODO", "severity": "LOW", "confidence": 1.0, "exploitability": 1.0}
    )
    assert boosted > base


def test_override_factors_are_clamped():
    # An out-of-range override must not push the score past the severity ceiling.
    score = risk_score(
        {"id": "SQL_INJECTION", "severity": "HIGH", "confidence": 5.0, "exploitability": 9.0}
    )
    assert score == pytest.approx(100.0)


@pytest.mark.parametrize(
    "score,expected",
    [(80.0, "CRITICAL"), (60.0, "CRITICAL"), (40.0, "HIGH"), (20.0, "MEDIUM"), (5.0, "LOW"), (0.0, "LOW")],
)
def test_risk_level_buckets(score, expected):
    assert risk_level(score) == expected


def test_score_finding_annotates_without_mutating():
    finding = {"id": "XSS", "severity": "HIGH"}
    scored = score_finding(finding)
    assert "risk_score" not in finding  # original untouched
    assert scored["risk_score"] == risk_score(finding)
    assert scored["risk_level"] == risk_level(scored["risk_score"])
    assert set(scored["risk_factors"]) == {"severity_weight", "confidence", "exploitability"}


def test_score_findings_sorted_descending(sample_findings):
    scored = score_findings(sample_findings)
    scores = [f["risk_score"] for f in scored]
    assert scores == sorted(scores, reverse=True)


def test_aggregate_risk_empty():
    agg = aggregate_risk([])
    assert agg["total_findings"] == 0
    assert agg["top_finding"] is None
    assert agg["max_risk_score"] == 0.0


def test_aggregate_risk_summary(sample_findings):
    scored = score_findings(sample_findings)
    agg = aggregate_risk(scored)
    assert agg["total_findings"] == len(sample_findings)
    assert agg["max_risk_score"] == max(f["risk_score"] for f in scored)
    assert sum(agg["level_counts"].values()) == len(sample_findings)
    assert agg["top_finding"]["risk_score"] == agg["max_risk_score"]
