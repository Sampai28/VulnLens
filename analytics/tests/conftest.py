"""Shared pytest fixtures: representative findings and scans.

The shapes here mirror exactly what the SAST scanner emits
(``sast/src/scanner.js``) and what gets stored in DynamoDB
(``sast/src/aws.js``), so the tests exercise the analytics engine against
realistic data.
"""

import pytest


def _finding(vuln_id, name, severity, file, line):
    return {
        "id": vuln_id,
        "name": name,
        "severity": severity,
        "description": f"{name} detected",
        "message": f"{name} message",
        "file": file,
        "line": line,
        "column": 1,
        "evidence": "<code>",
    }


@pytest.fixture
def sample_findings():
    """A mixed bag of findings: repeated types across files + one-offs."""
    return [
        _finding("HARDCODED_SECRET", "Hardcoded Secret", "HIGH", "config.js", 3),
        _finding("HARDCODED_SECRET", "Hardcoded Secret", "HIGH", "config.js", 7),
        _finding("HARDCODED_SECRET", "Hardcoded Secret", "HIGH", "db.js", 12),
        _finding("SQL_INJECTION", "SQL Injection Risk", "HIGH", "db.js", 20),
        _finding("SQL_INJECTION", "SQL Injection Risk", "HIGH", "db.js", 25),
        _finding("WEAK_CRYPTO", "Weak Cryptography", "MEDIUM", "auth.js", 40),
        _finding("SECURITY_TODO", "Security TODO/FIXME", "LOW", "notes.js", 1),
    ]


@pytest.fixture
def current_scan(sample_findings):
    return {
        "scanId": "scan-current",
        "filename": "app.js",
        "scannedAt": "2026-06-01T12:00:00Z",
        "summary": {"total": len(sample_findings), "high": 5, "medium": 1, "low": 1},
        "findings": sample_findings,
    }


@pytest.fixture
def previous_scan():
    """An older scan of the same file - fewer HIGH issues, a now-resolved XSS."""
    findings = [
        {"id": "XSS", "name": "Cross-Site Scripting (XSS)", "severity": "HIGH", "file": "app.js", "line": 5},
        {"id": "HARDCODED_SECRET", "name": "Hardcoded Secret", "severity": "HIGH", "file": "config.js", "line": 3},
        {"id": "SECURITY_TODO", "name": "Security TODO/FIXME", "severity": "LOW", "file": "notes.js", "line": 1},
    ]
    return {
        "scanId": "scan-previous",
        "filename": "app.js",
        "scannedAt": "2026-05-01T12:00:00Z",
        "summary": {"total": 3, "high": 2, "medium": 0, "low": 1},
        "findings": findings,
    }
