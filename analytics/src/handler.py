"""AWS Lambda entrypoint for the VulnLens analytics engine.

Deploy this as a Lambda function (handler = ``src.handler.lambda_handler``,
with the ``src/`` package at the root of the deployment zip). It bridges
DynamoDB to the pure :func:`src.engine.analyze_scan` pipeline and hands the
result off to the status phase.

This handler serves two invocation styles:

**1. SQS trigger (the pipeline path).**
   The scanner publishes ``{"scanId", "filename", "publishedAt"}`` to the
   ``vulnlens-scan-queue``; Lambda delivers a batch::

       {"Records": [{"body": "{\\"scanId\\": \\"abc-123\\", ...}", ...}, ...]}

   Each record is loaded from ``vulnlens-scans``, analyzed, the enriched report
   is persisted back onto the scan item under an ``analysis`` attribute, and the
   Status Lambda is invoked asynchronously with ``{"scanId": ...}`` so it can
   post the result back to GitHub. Records that fail are reported via
   ``batchItemFailures`` so SQS only redrives the ones that errored.

**2. Direct invocation (API / local testing).**
   The event may reference a stored scan by id::

       {"scanId": "abc-123"}

   or embed a scan inline (no DynamoDB read; history from ``event["history"]``)::

       {"scan": {"scanId": "...", "filename": "...", "findings": [...]}}

   This path returns an API-Gateway-style ``{"statusCode", "body"}`` response
   and, when ``persist`` is truthy, writes the analysis back to DynamoDB.
"""

from __future__ import annotations

import json
import logging
import os
from decimal import Decimal
from typing import Any, Optional

from src.engine import analyze_scan
from src.trends import DEFAULT_TABLE, fetch_scan_history, get_scan

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Name of the Status Lambda to hand off to after analytics persists. When unset
# (local dev / direct invocation), the hand-off is skipped silently.
STATUS_FUNCTION_NAME = os.environ.get("STATUS_FUNCTION_NAME", "")


def _to_dynamo_compatible(obj: Any) -> Any:
    """Convert a value into something boto3 can write to DynamoDB.

    The DynamoDB document client rejects Python ``float`` (it requires
    ``Decimal``), and our scoring produces plenty of floats. Round-tripping
    through JSON with ``parse_float=Decimal`` converts every float to a Decimal
    in one pass, using the string form so we don't inherit binary-float noise.
    ``default=str`` keeps any stray non-JSON value (e.g. a datetime) writable.
    """
    return json.loads(json.dumps(obj, default=str), parse_float=Decimal)


def _persist_analysis(scan_id: str, analysis: dict[str, Any], table_name: str) -> None:
    """Write the analysis back onto the scan item in DynamoDB."""
    import boto3  # local import: only needed on the AWS path

    region = os.environ.get("AWS_REGION", "us-east-1")
    table = boto3.resource("dynamodb", region_name=region).Table(table_name)
    table.update_item(
        Key={"scanId": scan_id},
        UpdateExpression="SET analysis = :a",
        ExpressionAttributeValues={":a": _to_dynamo_compatible(analysis)},
    )


def _invoke_status_lambda(scan_id: str) -> None:
    """Asynchronously invoke the Status Lambda for ``scan_id``.

    Uses event (fire-and-forget) invocation so analytics doesn't block on the
    GitHub round-trip. If ``STATUS_FUNCTION_NAME`` isn't configured we skip the
    hand-off - the enriched analysis is already safely persisted, so the status
    step can always be re-run against it later.
    """
    if not STATUS_FUNCTION_NAME:
        logger.info("STATUS_FUNCTION_NAME not set - skipping status hand-off for %s", scan_id)
        return

    import boto3  # local import: only needed on the AWS path

    region = os.environ.get("AWS_REGION", "us-east-1")
    client = boto3.client("lambda", region_name=region)
    client.invoke(
        FunctionName=STATUS_FUNCTION_NAME,
        InvocationType="Event",  # async fire-and-forget
        Payload=json.dumps({"scanId": scan_id}).encode("utf-8"),
    )
    logger.info("Invoked status lambda %s for scan %s", STATUS_FUNCTION_NAME, scan_id)


def _analyze_stored_scan(scan_id: str, table_name: str) -> Optional[dict[str, Any]]:
    """Load a scan by id, analyze it against its file history, and return the report.

    Returns ``None`` if no scan exists for ``scan_id``.
    """
    scan = get_scan(scan_id, table_name)
    if scan is None:
        return None

    filename = scan.get("filename")
    history = fetch_scan_history(filename, table_name) if filename else None
    return analyze_scan(scan, history)


def _process_record(scan_id: str, table_name: str) -> None:
    """Full pipeline step for one queued scan: analyze, persist, hand off.

    Raises if the scan can't be found or persisted so the caller can mark the
    SQS record as failed (and let SQS redrive / DLQ it).
    """
    analysis = _analyze_stored_scan(scan_id, table_name)
    if analysis is None:
        raise KeyError(f"No scan found for scanId={scan_id}")

    _persist_analysis(scan_id, analysis, table_name)
    logger.info(
        "Analyzed scan %s: %s findings, max risk %s",
        scan_id,
        analysis["risk"]["total_findings"],
        analysis["risk"]["max_risk_score"],
    )
    _invoke_status_lambda(scan_id)


def _handle_sqs_event(event: dict[str, Any], table_name: str) -> dict[str, Any]:
    """Process an SQS batch, returning partial-batch-failure ids for redrive.

    See the AWS "ReportBatchItemFailures" contract: any record id returned in
    ``batchItemFailures`` is made visible again on the queue; everything else is
    deleted. This means a single poison message can't block the whole batch.
    """
    failures: list[dict[str, str]] = []

    for record in event.get("Records", []):
        message_id = record.get("messageId", "")
        try:
            body = json.loads(record.get("body") or "{}")
            scan_id = body.get("scanId")
            if not scan_id:
                # Malformed message: log and drop it (no point redriving) so it
                # doesn't bounce until it hits the DLQ on a permanent error.
                logger.error("SQS record %s has no scanId; dropping: %s", message_id, body)
                continue
            _process_record(scan_id, table_name)
        except Exception:  # noqa: BLE001 - record-level isolation is intentional
            logger.exception("Failed to process SQS record %s", message_id)
            failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": failures}


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Entrypoint: SQS batch (pipeline) or direct scan analysis (API/testing)."""
    event = event or {}
    table_name = event.get("table") or DEFAULT_TABLE

    # SQS trigger: a batch of records, each referencing a stored scan.
    if "Records" in event:
        return _handle_sqs_event(event, table_name)

    # Direct invocation: inline scan or scanId reference, API-style response.
    inline_scan = event.get("scan")
    if inline_scan is not None:
        scan = inline_scan
        history = event.get("history")
        analysis = analyze_scan(scan, history)
    else:
        scan_id = event.get("scanId")
        if not scan_id:
            return {"statusCode": 400, "body": json.dumps({"error": "Provide 'scanId' or 'scan'"})}

        analysis = _analyze_stored_scan(scan_id, table_name)
        if analysis is None:
            return {"statusCode": 404, "body": json.dumps({"error": f"No scan found: {scan_id}"})}

    if event.get("persist") and analysis.get("scanId"):
        _persist_analysis(analysis["scanId"], analysis, table_name)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(analysis, default=str),
    }
