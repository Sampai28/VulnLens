"""Track security trends across scans.

A single scan is a snapshot. The interesting question for a developer is
*"am I getting better or worse?"* - which is only answerable by comparing the
current scan against the history of past scans for the same file.

This module has two layers, deliberately separated:

* **Pure functions** (:func:`summarize_scan`, :func:`compare_scans`,
  :func:`compute_trends`) operate on plain scan dicts. They have no AWS
  dependency and are fully unit-testable with in-memory data.
* **DynamoDB loaders** (:func:`fetch_scan_history`, :func:`get_scan`) pull that
  history from the ``vulnlens-scans`` table. ``boto3`` is imported lazily so
  the pure path never requires AWS credentials or the SDK.

A scan item matches the shape written by ``sast/src/aws.js``::

    {"scanId", "filename", "scannedAt", "summary": {...}, "findings": [...]}
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any, Optional

DEFAULT_TABLE = os.environ.get("DYNAMO_TABLE", "vulnlens-scans")

# Severity-weighted risk used to decide whether a scan is improving overall, so
# trading three LOW findings for one HIGH still reads as "worse".
_SEVERITY_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def summarize_scan(scan: dict[str, Any]) -> dict[str, Any]:
    """Reduce a scan to comparable counters: totals, by severity, by type."""
    findings = scan.get("findings", [])

    by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_type: Counter[str] = Counter()
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_type[f.get("id") or f.get("type") or "UNKNOWN"] += 1

    weighted = sum(_SEVERITY_WEIGHT.get(s, 1) * n for s, n in by_severity.items())

    return {
        "scanId": scan.get("scanId"),
        "scannedAt": scan.get("scannedAt"),
        "total": len(findings),
        "by_severity": by_severity,
        "by_type": dict(by_type),
        "weighted_risk": weighted,
    }


def _direction(current_weight: int, previous_weight: int) -> str:
    """Classify movement in weighted risk between two scans."""
    if current_weight < previous_weight:
        return "improving"
    if current_weight > previous_weight:
        return "worsening"
    return "stable"


def compare_scans(current: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    """Diff the current scan against an immediately-previous one.

    Reports the change in totals and per-severity counts, which vulnerability
    types are newly introduced vs. resolved, and an overall direction based on
    severity-weighted risk.
    """
    cur = summarize_scan(current)
    prev = summarize_scan(previous)

    severity_deltas = {
        sev: cur["by_severity"].get(sev, 0) - prev["by_severity"].get(sev, 0)
        for sev in ("HIGH", "MEDIUM", "LOW")
    }

    cur_types = set(cur["by_type"])
    prev_types = set(prev["by_type"])

    return {
        "previous_scanId": prev["scanId"],
        "current_scanId": cur["scanId"],
        "total_delta": cur["total"] - prev["total"],
        "severity_deltas": severity_deltas,
        "weighted_risk_delta": cur["weighted_risk"] - prev["weighted_risk"],
        "new_types": sorted(cur_types - prev_types),
        "resolved_types": sorted(prev_types - cur_types),
        "direction": _direction(cur["weighted_risk"], prev["weighted_risk"]),
    }


def compute_trends(
    current: dict[str, Any],
    history: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Compute the full trend picture for ``current`` against past scans.

    Args:
        current: the scan just produced.
        history: prior scans for the same file, oldest first. The current scan
            may or may not be included; it is excluded by ``scanId`` so callers
            can pass the raw table history without de-duping.

    Returns:
        A dict with the current summary, a chronological time series of
        ``(scannedAt, total, weighted_risk)`` points, the most-recent
        comparison, and whether this is the first scan on record.
    """
    history = history or []
    current_id = current.get("scanId")

    # Drop the current scan if it already appears in history, then order oldest
    # -> newest so the series reads left to right.
    prior = [s for s in history if s.get("scanId") != current_id]
    prior.sort(key=lambda s: s.get("scannedAt") or "")

    series = [
        {
            "scanId": s.get("scanId"),
            "scannedAt": s.get("scannedAt"),
            "total": summarize_scan(s)["total"],
            "weighted_risk": summarize_scan(s)["weighted_risk"],
        }
        for s in (prior + [current])
    ]

    result: dict[str, Any] = {
        "current": summarize_scan(current),
        "scan_count": len(prior) + 1,
        "is_first_scan": len(prior) == 0,
        "series": series,
        "comparison": None,
    }

    if prior:
        result["comparison"] = compare_scans(current, prior[-1])

    return result


# --------------------------------------------------------------------------- #
# DynamoDB loaders (boto3 imported lazily so the pure path stays dependency-free)
# --------------------------------------------------------------------------- #
def _table(table_name: str):
    """Return a boto3 DynamoDB Table resource."""
    import boto3  # local import: only needed when actually hitting AWS

    region = os.environ.get("AWS_REGION", "us-east-1")
    return boto3.resource("dynamodb", region_name=region).Table(table_name)


def get_scan(scan_id: str, table_name: str = DEFAULT_TABLE) -> Optional[dict[str, Any]]:
    """Fetch a single scan item by ``scanId`` from DynamoDB."""
    response = _table(table_name).get_item(Key={"scanId": scan_id})
    return response.get("Item")


def fetch_scan_history(
    filename: str,
    table_name: str = DEFAULT_TABLE,
    limit: Optional[int] = None,
) -> list[dict[str, Any]]:
    """Fetch all past scans for a filename, oldest first.

    The table is keyed only by ``scanId``, so this scans with a filter on
    ``filename``. Fine for a course-scale dataset; a production system would add
    a GSI on ``filename``. Results are sorted by ``scannedAt`` ascending.
    """
    from boto3.dynamodb.conditions import Attr

    table = _table(table_name)
    items: list[dict[str, Any]] = []
    scan_kwargs: dict[str, Any] = {"FilterExpression": Attr("filename").eq(filename)}

    while True:
        response = table.scan(**scan_kwargs)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break
        scan_kwargs["ExclusiveStartKey"] = last_key

    items.sort(key=lambda s: s.get("scannedAt") or "")
    if limit is not None:
        items = items[-limit:]
    return items
