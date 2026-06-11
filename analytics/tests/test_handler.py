"""Tests for the Lambda handler (inline-scan path + SQS path, no AWS needed)."""

import json

from src import handler
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


# --------------------------------------------------------------------------- #
# SQS trigger path (DynamoDB + status hand-off mocked)
# --------------------------------------------------------------------------- #
def _sqs_event(*scan_ids):
    return {
        "Records": [
            {"messageId": f"msg-{sid}", "body": json.dumps({"scanId": sid, "filename": "app.js"})}
            for sid in scan_ids
        ]
    }


def _mock_pipeline(monkeypatch, current_scan):
    """Stub the DynamoDB load/persist + status hand-off; capture side effects."""
    captured = {"persisted": [], "invoked": []}

    monkeypatch.setattr(handler, "get_scan", lambda scan_id, table: current_scan)
    monkeypatch.setattr(handler, "fetch_scan_history", lambda filename, table: [])
    monkeypatch.setattr(
        handler, "_persist_analysis",
        lambda scan_id, analysis, table: captured["persisted"].append(scan_id),
    )
    monkeypatch.setattr(
        handler, "_invoke_status_lambda",
        lambda scan_id: captured["invoked"].append(scan_id),
    )
    return captured


def test_sqs_record_analyzes_persists_and_hands_off(monkeypatch, current_scan):
    captured = _mock_pipeline(monkeypatch, current_scan)
    response = lambda_handler(_sqs_event("scan-current"))

    assert response == {"batchItemFailures": []}
    assert captured["persisted"] == ["scan-current"]
    assert captured["invoked"] == ["scan-current"]


def test_sqs_missing_scan_is_reported_as_batch_failure(monkeypatch):
    monkeypatch.setattr(handler, "get_scan", lambda scan_id, table: None)
    response = lambda_handler(_sqs_event("ghost"))
    assert response["batchItemFailures"] == [{"itemIdentifier": "msg-ghost"}]


def test_sqs_malformed_record_is_dropped_not_failed(monkeypatch, current_scan):
    _mock_pipeline(monkeypatch, current_scan)
    event = {"Records": [{"messageId": "bad", "body": json.dumps({"filename": "x"})}]}
    response = lambda_handler(event)
    # No scanId -> dropped (not redriven), so no batch failure reported.
    assert response["batchItemFailures"] == []


def test_sqs_failure_is_isolated_per_record(monkeypatch, current_scan):
    captured = _mock_pipeline(monkeypatch, current_scan)

    def flaky_get_scan(scan_id, table):
        return None if scan_id == "ghost" else current_scan

    monkeypatch.setattr(handler, "get_scan", flaky_get_scan)
    response = lambda_handler(_sqs_event("scan-current", "ghost"))

    # Good record processed; only the bad one is redriven.
    assert captured["persisted"] == ["scan-current"]
    assert response["batchItemFailures"] == [{"itemIdentifier": "msg-ghost"}]
