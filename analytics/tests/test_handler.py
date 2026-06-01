"""Tests for the Lambda handler (inline-scan path, no AWS needed)."""

import json

from src.handler import lambda_handler


def test_handler_inline_scan(current_scan):
    response = lambda_handler({"scan": current_scan})
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["scanId"] == "scan-current"
    assert len(body["findings"]) == len(current_scan["findings"])
    assert body["themes"]


def test_handler_inline_scan_with_history(current_scan, previous_scan):
    response = lambda_handler({"scan": current_scan, "history": [previous_scan]})
    body = json.loads(response["body"])
    assert body["trends"]["comparison"]["direction"] == "worsening"


def test_handler_missing_identifier_returns_400():
    response = lambda_handler({})
    assert response["statusCode"] == 400
    assert "error" in json.loads(response["body"])


def test_handler_body_is_json_serializable(current_scan):
    # default=str must let the whole report serialize without raising.
    response = lambda_handler({"scan": current_scan})
    assert isinstance(response["body"], str)
    json.loads(response["body"])  # round-trips cleanly
