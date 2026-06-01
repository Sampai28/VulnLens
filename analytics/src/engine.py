"""Analytics engine orchestration.

Ties the four analytics stages together into one pass over a scan:

    1. CWE enrichment  - attach MITRE context to every finding
    2. Risk scoring    - compute a 0-100 weighted score per finding
    3. Clustering      - group findings into themes with DBSCAN
    4. Trends          - compare against the file's scan history (optional)

:func:`analyze_scan` is pure: give it a scan dict (and optionally its history)
and it returns the enriched analytics report. It performs no I/O, so it is
trivially testable and can be reused by the FastAPI layer or the Lambda
handler alike.
"""

from __future__ import annotations

from typing import Any, Optional

from src.clustering import cluster_findings
from src.cwe_mapping import enrich_findings
from src.scoring import aggregate_risk, score_findings
from src.trends import compute_trends


def analyze_scan(
    scan: dict[str, Any],
    history: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Run the full analytics pipeline over a single scan.

    Args:
        scan: a scan item (``scanId``, ``filename``, ``findings``, ...) as
            written by the SAST scanner / stored in DynamoDB.
        history: optional prior scans for the same file, used for trend
            analysis. When omitted, the ``trends`` block reflects a first scan.

    Returns:
        An enriched report: scored + CWE-tagged findings (highest risk first),
        DBSCAN themes, an aggregate risk summary, and trends.
    """
    findings = scan.get("findings", [])

    # 1 + 2: enrich with CWE context, then score. Scoring sorts by risk.
    enriched = enrich_findings(findings)
    scored = score_findings(enriched)

    # 3: cluster the scored findings so themes carry risk totals.
    themes = cluster_findings(scored)

    # 4: trend analysis against history (compute_trends handles the empty case).
    trends = compute_trends(scan, history)

    return {
        "scanId": scan.get("scanId"),
        "filename": scan.get("filename"),
        "scannedAt": scan.get("scannedAt"),
        "risk": aggregate_risk(scored),
        "findings": scored,
        "themes": themes,
        "trends": trends,
    }
