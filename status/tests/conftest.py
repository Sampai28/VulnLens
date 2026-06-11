"""Shared pytest fixtures for the status gate.

Scan shapes mirror what the SAST scanner stores in DynamoDB
(``sast/src/aws.js``), optionally enriched with an ``analysis`` block by the
analytics Lambda and a ``github`` block threaded through by the pipeline.
"""

import pytest


def _finding(vuln_id, name, severity, file, line):
    return {
        "id": vuln_id,
        "name": name,
        "severity": severity,
        "file": file,
        "line": line,
    }


@pytest.fixture
def github_block():
    return {"owner": "Sampai28", "repo": "VulnLens", "sha": "abc123def456", "pr_number": 42}


@pytest.fixture
def failing_scan(github_block):
    """A scan with HIGH findings - should fail the gate."""
    return {
        "scanId": "scan-fail",
        "filename": "app.js",
        "summary": {"total": 3, "high": 2, "medium": 1, "low": 0},
        "findings": [
            _finding("SQL_INJECTION", "SQL Injection Risk", "HIGH", "db.js", 20),
            _finding("HARDCODED_SECRET", "Hardcoded Secret", "HIGH", "config.js", 3),
            _finding("WEAK_CRYPTO", "Weak Cryptography", "MEDIUM", "auth.js", 40),
        ],
        "analysis": {
            "risk": {"total_findings": 3, "max_risk_score": 66.5, "mean_risk_score": 40.0},
            "findings": [
                {"id": "SQL_INJECTION", "name": "SQL Injection Risk", "severity": "HIGH",
                 "file": "db.js", "line": 20, "risk_score": 66.5},
                {"id": "HARDCODED_SECRET", "name": "Hardcoded Secret", "severity": "HIGH",
                 "file": "config.js", "line": 3, "risk_score": 65.0},
            ],
        },
        "github": github_block,
    }


@pytest.fixture
def passing_scan(github_block):
    """A scan with only MEDIUM/LOW findings - should pass the gate."""
    return {
        "scanId": "scan-pass",
        "filename": "app.js",
        "summary": {"total": 2, "high": 0, "medium": 1, "low": 1},
        "findings": [
            _finding("WEAK_CRYPTO", "Weak Cryptography", "MEDIUM", "auth.js", 40),
            _finding("SECURITY_TODO", "Security TODO/FIXME", "LOW", "notes.js", 1),
        ],
        "github": github_block,
    }


@pytest.fixture
def clean_scan(github_block):
    """A scan with no findings - should pass with the clean message."""
    return {
        "scanId": "scan-clean",
        "filename": "app.js",
        "summary": {"total": 0, "high": 0, "medium": 0, "low": 0},
        "findings": [],
        "github": github_block,
    }


@pytest.fixture
def scan_without_github(failing_scan):
    """A failing scan with no github block - gate evaluates, post is skipped."""
    scan = dict(failing_scan)
    scan.pop("github")
    scan["scanId"] = "scan-no-gh"
    return scan
