"""Tests for the Status Lambda handler (inline-scan path, GitHub mocked)."""

import pytest

from src import github, handler, secrets


@pytest.fixture
def captured_github(monkeypatch):
    """Stub Secrets Manager + GitHub calls and capture what would be posted."""
    calls = {"status": [], "comment": []}

    monkeypatch.setattr(secrets, "get_github_token", lambda *a, **k: "test-token")
    # handler imported get_github_token by name, so patch it there too.
    monkeypatch.setattr(handler, "get_github_token", lambda *a, **k: "test-token")

    def fake_status(**kwargs):
        calls["status"].append(kwargs)
        return {"id": 1}

    def fake_comment(**kwargs):
        calls["comment"].append(kwargs)
        return {"id": 2}

    monkeypatch.setattr(github, "post_commit_status", fake_status)
    monkeypatch.setattr(github, "post_pr_comment", fake_comment)
    return calls


def test_inline_failing_scan_posts_failure_status(failing_scan, captured_github):
    response = handler.lambda_handler({"scan": failing_scan})
    assert response["statusCode"] == 200
    assert response["body"]["state"] == "failure"

    assert len(captured_github["status"]) == 1
    posted = captured_github["status"][0]
    assert posted["state"] == "failure"
    assert posted["sha"] == "abc123def456"
    assert posted["context"] == "vulnlens/security-gate"
    # PR comment posted because pr_number is present.
    assert len(captured_github["comment"]) == 1


def test_inline_passing_scan_posts_success_status(passing_scan, captured_github):
    response = handler.lambda_handler({"scan": passing_scan})
    assert response["body"]["state"] == "success"
    assert captured_github["status"][0]["state"] == "success"


def test_missing_github_block_skips_post(scan_without_github, captured_github):
    response = handler.lambda_handler({"scan": scan_without_github})
    # Gate still evaluates (failure), but nothing is posted.
    assert response["body"]["state"] == "failure"
    assert response["body"]["github"] == {"posted": False, "reason": "no-github-context"}
    assert captured_github["status"] == []
    assert captured_github["comment"] == []


def test_missing_identifier_returns_400():
    response = handler.lambda_handler({})
    assert response["statusCode"] == 400
    assert "error" in response["body"]


def test_no_pr_number_skips_comment_but_posts_status(failing_scan, captured_github):
    failing_scan["github"].pop("pr_number")
    handler.lambda_handler({"scan": failing_scan})
    assert len(captured_github["status"]) == 1
    assert captured_github["comment"] == []
