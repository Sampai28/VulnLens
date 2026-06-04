"""AWS Lambda entrypoint for the VulnLens analytics engine.

Deploy this as a Lambda function (handler = ``src.handler.lambda_handler``,
with the ``src/`` package at the root of the deployment zip). It bridges
DynamoDB to the pure :func:`src.engine.analyze_scan` pipeline.

Invocation contract - the event may either:

* reference a stored scan by id::

      {"scanId": "abc-123"}

  The handler loads that scan and its file history from the ``vulnlens-scans``
  table, analyzes it, and returns the report.

* embed a scan inline (handy for the API layer or local testing)::

      {"scan": {"scanId": "...", "filename": "...", "findings": [...]}}

  No DynamoDB read is performed; history is taken from ``event["history"]`` if
  present.

When ``persist`` is truthy and a real scan id is available, the analysis is
written back to the scan item under an ``analysis`` attribute.
"""

from __future__ import annotations

import json
import os
from typing import Any

from src.engine import analyze_scan
from src.trends import DEFAULT_TABLE, fetch_scan_history, get_scan


def _persist_analysis(scan_id: str, analysis: dict[str, Any], table_name: str) -> None:
    """Write the analysis back onto the scan item in DynamoDB."""
    import boto3  # local import: only needed on the AWS path

    region = os.environ.get("AWS_REGION", "us-east-1")
    table = boto3.resource("dynamodb", region_name=region).Table(table_name)
    table.update_item(
        Key={"scanId": scan_id},
        UpdateExpression="SET analysis = :a",
        ExpressionAttributeValues={":a": analysis},
    )


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Lambda handler: analyze a scan referenced by id or embedded inline."""
    event = event or {}
    table_name = event.get("table") or DEFAULT_TABLE

    inline_scan = event.get("scan")
    if inline_scan is not None:
        scan = inline_scan
        history = event.get("history")
    else:
        scan_id = event.get("scanId")
        if not scan_id:
            return {"statusCode": 400, "body": json.dumps({"error": "Provide 'scanId' or 'scan'"})}

        scan = get_scan(scan_id, table_name)
        if scan is None:
            return {"statusCode": 404, "body": json.dumps({"error": f"No scan found: {scan_id}"})}

        filename = scan.get("filename")
        history = fetch_scan_history(filename, table_name) if filename else None

    analysis = analyze_scan(scan, history)

    if event.get("persist") and analysis.get("scanId"):
        _persist_analysis(analysis["scanId"], analysis, table_name)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(analysis, default=str),
    }
