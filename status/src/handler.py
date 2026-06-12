"""AWS Lambda entrypoint for the VulnLens status gate.

Deploy as a Lambda (handler = ``src.handler.lambda_handler``, ``src/`` at the
root of the zip). This is the final phase of the pipeline: it turns an analyzed
scan into a pass/fail commit status on the originating GitHub PR.

Invocation: the analytics Lambda invokes this asynchronously with the scan id::

    {"scanId": "abc-123"}

The handler then:

1. Loads the scan item (with its analytics ``analysis`` block) from DynamoDB.
2. Evaluates the security gate (:func:`src.gate.evaluate`) - fail on HIGH.
3. Reads the ``github`` block threaded through the pipeline. If absent it logs
   and stops gracefully (nothing to post back to), so the pipeline still runs
   end-to-end before the GitHub wiring is live.
4. Fetches the GitHub token from Secrets Manager and posts the commit status
   (plus a best-effort PR comment with the detail).
5. Persists the decision back onto the scan item under a ``status`` attribute.

For local testing the scan can be embedded inline (``{"scan": {...}}``) and the
GitHub/Secrets calls are skipped automatically when no ``github`` block is
present.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from src import github
from src.gate import evaluate, github_context
from src.secrets import get_github_token

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

DEFAULT_TABLE = os.environ.get("DYNAMO_TABLE", "vulnlens-scans")

# Optional link shown on the GitHub status (e.g. a dashboard URL).
STATUS_TARGET_URL = os.environ.get("STATUS_TARGET_URL", "")


def _table(table_name: str):
    """Return a boto3 DynamoDB Table resource (boto3 imported lazily)."""
    import boto3

    region = os.environ.get("AWS_REGION", "us-east-1")
    return boto3.resource("dynamodb", region_name=region).Table(table_name)


def _get_scan(scan_id: str, table_name: str) -> Optional[dict[str, Any]]:
    """Fetch a scan item by id from DynamoDB."""
    response = _table(table_name).get_item(Key={"scanId": scan_id})
    return response.get("Item")


def _persist_status(scan_id: str, decision: dict[str, Any], table_name: str) -> None:
    """Record the gate decision back onto the scan item for traceability."""
    record = {
        "state": decision["state"],
        "passed": decision["passed"],
        "counts": decision["counts"],
        "description": decision["description"],
    }
    _table(table_name).update_item(
        Key={"scanId": scan_id},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": record},
    )


def _post_to_github(scan: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
    """Post the gate result to GitHub when context is available.

    Returns a small dict describing what happened (``posted`` / ``skipped``) so
    the response is useful both in tests and CloudWatch.
    """
    gh = github_context(scan)
    if gh is None:
        logger.warning(
            "Scan %s has no github context - skipping status post (gate=%s)",
            scan.get("scanId"),
            decision["state"],
        )
        return {"posted": False, "reason": "no-github-context"}

    token = get_github_token()
    github.post_commit_status(
        token=token,
        owner=gh["owner"],
        repo=gh["repo"],
        sha=gh["sha"],
        state=decision["state"],
        context=decision["context"],
        description=decision["description"],
        target_url=STATUS_TARGET_URL or None,
    )

    pr_number = gh.get("pr_number")
    if pr_number:
        github.post_pr_comment(
            token=token,
            owner=gh["owner"],
            repo=gh["repo"],
            pr_number=int(pr_number),
            body=decision["comment"],
        )

    return {"posted": True, "state": decision["state"], "sha": gh["sha"]}


def _process_scan(scan: dict[str, Any], table_name: str, persist: bool) -> dict[str, Any]:
    """Evaluate the gate for a scan, post to GitHub, and optionally persist."""
    decision = evaluate(scan)
    outcome = _post_to_github(scan, decision)

    scan_id = scan.get("scanId")
    if persist and scan_id:
        _persist_status(scan_id, decision, table_name)

    return {
        "scanId": scan_id,
        "state": decision["state"],
        "passed": decision["passed"],
        "counts": decision["counts"],
        "github": outcome,
    }


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Entrypoint: gate a scan referenced by id (pipeline) or embedded inline (test)."""
    event = event or {}
    table_name = event.get("table") or DEFAULT_TABLE

    # Inline scan (local testing): no DynamoDB read, don't persist by default.
    inline_scan = event.get("scan")
    if inline_scan is not None:
        result = _process_scan(inline_scan, table_name, persist=bool(event.get("persist")))
        return {"statusCode": 200, "body": result}

    scan_id = event.get("scanId")
    if not scan_id:
        return {"statusCode": 400, "body": {"error": "Provide 'scanId' or 'scan'"}}

    scan = _get_scan(scan_id, table_name)
    if scan is None:
        return {"statusCode": 404, "body": {"error": f"No scan found: {scan_id}"}}

    result = _process_scan(scan, table_name, persist=True)
    return {"statusCode": 200, "body": result}
