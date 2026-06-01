"""Tests for the end-to-end analytics engine orchestration."""

from src.engine import analyze_scan


def test_analyze_scan_report_shape(current_scan):
    report = analyze_scan(current_scan)
    assert set(report) >= {"scanId", "filename", "scannedAt", "risk", "findings", "themes", "trends"}
    assert report["scanId"] == "scan-current"
    assert report["filename"] == "app.js"


def test_analyze_scan_findings_scored_and_enriched(current_scan):
    report = analyze_scan(current_scan)
    findings = report["findings"]
    assert len(findings) == len(current_scan["findings"])
    # Every finding is both CWE-enriched and risk-scored, sorted by risk.
    assert all("cwe" in f and "risk_score" in f for f in findings)
    scores = [f["risk_score"] for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_analyze_scan_themes_cover_all_findings(current_scan):
    report = analyze_scan(current_scan)
    assert sum(t["count"] for t in report["themes"]) == len(current_scan["findings"])


def test_analyze_scan_first_scan_trends(current_scan):
    report = analyze_scan(current_scan)
    assert report["trends"]["is_first_scan"] is True


def test_analyze_scan_with_history(current_scan, previous_scan):
    report = analyze_scan(current_scan, history=[previous_scan])
    assert report["trends"]["comparison"]["direction"] == "worsening"


def test_analyze_scan_empty_findings():
    scan = {"scanId": "empty", "filename": "x.js", "scannedAt": "2026-06-01T00:00:00Z", "findings": []}
    report = analyze_scan(scan)
    assert report["risk"]["total_findings"] == 0
    assert report["themes"] == []
    assert report["findings"] == []


def test_analyze_scan_does_not_mutate_input(current_scan):
    original_count = len(current_scan["findings"])
    analyze_scan(current_scan)
    assert len(current_scan["findings"]) == original_count
    assert "risk_score" not in current_scan["findings"][0]
