"""Tests for the pure trend-analysis functions."""

from src.trends import compare_scans, compute_trends, summarize_scan


def test_summarize_scan_counts(current_scan):
    summary = summarize_scan(current_scan)
    assert summary["total"] == 7
    assert summary["by_severity"] == {"HIGH": 5, "MEDIUM": 1, "LOW": 1}
    assert summary["by_type"]["HARDCODED_SECRET"] == 3
    assert summary["by_type"]["SQL_INJECTION"] == 2


def test_summarize_weighted_risk():
    scan = {"findings": [{"id": "X", "severity": "HIGH"}, {"id": "Y", "severity": "LOW"}]}
    # 3 (HIGH) + 1 (LOW) = 4
    assert summarize_scan(scan)["weighted_risk"] == 4


def test_compare_scans_detects_new_and_resolved(current_scan, previous_scan):
    diff = compare_scans(current_scan, previous_scan)
    # SQL_INJECTION and WEAK_CRYPTO are new this scan; XSS was resolved.
    assert "SQL_INJECTION" in diff["new_types"]
    assert "WEAK_CRYPTO" in diff["new_types"]
    assert "XSS" in diff["resolved_types"]


def test_compare_scans_deltas(current_scan, previous_scan):
    diff = compare_scans(current_scan, previous_scan)
    assert diff["total_delta"] == 7 - 3
    assert diff["severity_deltas"]["HIGH"] == 5 - 2


def test_compare_scans_direction_worsening(current_scan, previous_scan):
    # More HIGH findings -> weighted risk up -> worsening.
    assert compare_scans(current_scan, previous_scan)["direction"] == "worsening"


def test_direction_improving():
    worse = {"scanId": "a", "findings": [{"id": "X", "severity": "HIGH"}, {"id": "Y", "severity": "HIGH"}]}
    better = {"scanId": "b", "findings": [{"id": "X", "severity": "LOW"}]}
    assert compare_scans(better, worse)["direction"] == "improving"


def test_direction_stable():
    a = {"scanId": "a", "findings": [{"id": "X", "severity": "HIGH"}]}
    b = {"scanId": "b", "findings": [{"id": "Y", "severity": "HIGH"}]}
    assert compare_scans(a, b)["direction"] == "stable"


def test_compute_trends_first_scan(current_scan):
    trends = compute_trends(current_scan, history=None)
    assert trends["is_first_scan"] is True
    assert trends["scan_count"] == 1
    assert trends["comparison"] is None
    assert len(trends["series"]) == 1


def test_compute_trends_with_history(current_scan, previous_scan):
    trends = compute_trends(current_scan, history=[previous_scan])
    assert trends["is_first_scan"] is False
    assert trends["scan_count"] == 2
    assert trends["comparison"]["direction"] == "worsening"
    # Series is oldest -> newest.
    assert trends["series"][0]["scanId"] == "scan-previous"
    assert trends["series"][-1]["scanId"] == "scan-current"


def test_compute_trends_excludes_current_from_history(current_scan):
    # Passing the current scan inside history must not double-count it.
    trends = compute_trends(current_scan, history=[current_scan])
    assert trends["scan_count"] == 1
    assert trends["is_first_scan"] is True


def test_compute_trends_orders_unsorted_history(current_scan, previous_scan):
    older = {
        "scanId": "scan-oldest",
        "filename": "app.js",
        "scannedAt": "2026-04-01T00:00:00Z",
        "findings": [],
    }
    # Deliberately pass history out of order.
    trends = compute_trends(current_scan, history=[previous_scan, older])
    series_ids = [p["scanId"] for p in trends["series"]]
    assert series_ids == ["scan-oldest", "scan-previous", "scan-current"]
