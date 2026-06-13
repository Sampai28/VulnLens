"""Tests for the pure gate logic (no AWS, no network)."""

from src.gate import evaluate, github_context


def test_high_finding_fails_gate(failing_scan):
    decision = evaluate(failing_scan)
    assert decision["state"] == "failure"
    assert decision["passed"] is False
    assert decision["counts"] == {"HIGH": 2, "MEDIUM": 1, "LOW": 0}


def test_no_high_passes_gate(passing_scan):
    decision = evaluate(passing_scan)
    assert decision["state"] == "success"
    assert decision["passed"] is True
    assert decision["counts"]["HIGH"] == 0


def test_clean_scan_passes_with_clean_message(clean_scan):
    decision = evaluate(clean_scan)
    assert decision["passed"] is True
    assert "no vulnerabilities" in decision["description"].lower()


def test_description_stays_within_github_limit(failing_scan):
    decision = evaluate(failing_scan)
    assert len(decision["description"]) <= 140


def test_comment_includes_severity_table_and_top_findings(failing_scan):
    decision = evaluate(failing_scan)
    comment = decision["comment"]
    assert "FAILED" in comment
    assert "| HIGH | 2 |" in comment
    # Top finding from the analysis block should be surfaced.
    assert "SQL Injection Risk" in comment
    # Risk summary from the analytics block should be included.
    assert "Risk score" in comment


def test_comment_falls_back_to_raw_findings_without_analysis(passing_scan):
    # passing_scan has no analysis block; comment should still list findings.
    decision = evaluate(passing_scan)
    assert "Weak Cryptography" in decision["comment"]


def test_github_context_extracted_when_complete(failing_scan):
    gh = github_context(failing_scan)
    assert gh is not None
    assert gh["owner"] == "Sampai28"
    assert gh["sha"] == "abc123def456"


def test_github_context_none_when_missing(scan_without_github):
    assert github_context(scan_without_github) is None


def test_github_context_none_when_partial():
    assert github_context({"github": {"owner": "x", "repo": "y"}}) is None


def test_github_context_strips_whitespace():
    # Upstream S3-metadata parsing can leave stray spaces/newlines; a space in
    # the URL path is a control character and crashes the request.
    gh = github_context({"github": {
        "owner": "sagarkaistha ", "repo": " example-voting-app",
        "sha": "66f5aec\n", "pr_number": " 7 ",
    }})
    assert gh == {
        "owner": "sagarkaistha", "repo": "example-voting-app",
        "sha": "66f5aec", "pr_number": "7",
    }


def test_github_context_drops_empty_pr_number():
    gh = github_context({"github": {"owner": "o", "repo": "r", "sha": "s", "pr_number": ""}})
    assert "pr_number" not in gh
