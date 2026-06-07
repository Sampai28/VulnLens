"""Benchmark DBSCAN clustering at realistic finding volumes.

Why this exists
---------------
Clustering runs inside the analytics Lambda (``src.handler.lambda_handler``),
and Lambda hard-stops at 15 minutes. Our DBSCAN (:func:`src.clustering`) is a
pure-Python implementation whose neighbour search is O(n^2), so we need to know
how it behaves on real scan sizes *before* the full analytics pipeline is built
around it. If medium scans clear comfortably under 30s, clustering stays in
Lambda; if it creeps toward minutes, clustering moves to Fargate.

This module is dual-purpose:

* **Locally**  -- ``python -m benchmarks.benchmark_dbscan`` (run from
  ``analytics/``) prints timings for small / medium / large / stress inputs.
* **In Lambda** -- deploy with handler ``benchmarks.benchmark_dbscan.handler``;
  it runs the same sizes and emits one JSON line per size into CloudWatch so
  you can read the real in-Lambda timings (which depend on the function's
  memory / CPU allotment).

The synthetic findings mirror the scanner's output shape (see
``analytics/tests/conftest.py``) so the clustering work is representative.
"""

from __future__ import annotations

import json
import random
import time
from statistics import mean
from typing import Any

# Allow running both as ``python -m benchmarks.benchmark_dbscan`` and as a
# Lambda handler where ``src/`` sits at the deployment-package root.
try:
    from src.clustering import cluster_findings
except ModuleNotFoundError:  # pragma: no cover - import shim for local runs
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.clustering import cluster_findings

# Vulnerability types the scanner can emit, used to give synthetic findings a
# realistic spread of clusterable types (a handful of recurring types is what
# DBSCAN actually groups on - see src/clustering._feature_matrix).
_VULN_TYPES = [
    ("HARDCODED_SECRET", "Hardcoded Secret", "HIGH"),
    ("SQL_INJECTION", "SQL Injection Risk", "HIGH"),
    ("XSS", "Cross-Site Scripting (XSS)", "HIGH"),
    ("WEAK_CRYPTO", "Weak Cryptography", "MEDIUM"),
    ("INSECURE_RANDOM", "Insecure Randomness", "MEDIUM"),
    ("PATH_TRAVERSAL", "Path Traversal", "HIGH"),
    ("COMMAND_INJECTION", "Command Injection", "HIGH"),
    ("SECURITY_TODO", "Security TODO/FIXME", "LOW"),
]

# (label, finding count) - the realistic input sizes from the benchmark plan.
SIZES: list[tuple[str, int]] = [
    ("small", 15),    # typical small scan (10-20 findings)
    ("medium", 65),   # typical real scan (50-80 findings)
    ("large", 220),   # stress test (200+ findings)
    ("xlarge", 500),  # extra stress: pessimistic worst case
]


def make_findings(n: int, seed: int = 1234) -> list[dict[str, Any]]:
    """Generate ``n`` synthetic findings shaped like real scanner output."""
    rng = random.Random(seed)
    findings: list[dict[str, Any]] = []
    for i in range(n):
        vuln_id, name, severity = rng.choice(_VULN_TYPES)
        findings.append(
            {
                "id": vuln_id,
                "name": name,
                "severity": severity,
                "description": f"{name} detected",
                "message": f"{name} message",
                "file": f"src/module_{i % 25}.js",
                "line": rng.randint(1, 400),
                "column": 1,
                "evidence": "<code>",
            }
        )
    return findings


def benchmark_size(label: str, n: int, repeats: int = 3) -> dict[str, Any]:
    """Time :func:`cluster_findings` on ``n`` findings, ``repeats`` times."""
    findings = make_findings(n)
    timings_ms: list[float] = []
    theme_count = 0
    for _ in range(repeats):
        start = time.perf_counter()
        themes = cluster_findings(findings)
        timings_ms.append((time.perf_counter() - start) * 1000.0)
        theme_count = len(themes)

    return {
        "label": label,
        "findings": n,
        "themes": theme_count,
        "repeats": repeats,
        "min_ms": round(min(timings_ms), 2),
        "mean_ms": round(mean(timings_ms), 2),
        "max_ms": round(max(timings_ms), 2),
    }


def run(sizes: list[tuple[str, int]] = SIZES) -> list[dict[str, Any]]:
    """Run the benchmark for every size and return one result dict per size."""
    return [benchmark_size(label, n) for label, n in sizes]


def handler(event: dict[str, Any] | None = None, context: Any = None) -> dict[str, Any]:
    """Lambda entrypoint: benchmark in-Lambda and log results to CloudWatch.

    Each result is emitted as its own JSON line prefixed with ``DBSCAN_BENCH``
    so it is trivially greppable in CloudWatch Logs Insights. Override the
    sizes by passing ``{"sizes": [[label, n], ...]}`` in the event.
    """
    event = event or {}
    sizes = [tuple(s) for s in event["sizes"]] if event.get("sizes") else SIZES

    results = run(sizes)  # type: ignore[arg-type]
    for r in results:
        print(f"DBSCAN_BENCH {json.dumps(r)}")

    return {"statusCode": 200, "body": json.dumps({"results": results})}


def _print_table(results: list[dict[str, Any]]) -> None:
    print(f"\n{'input':<8}{'findings':>10}{'themes':>9}{'mean (ms)':>14}{'max (ms)':>12}")
    print("-" * 53)
    for r in results:
        print(
            f"{r['label']:<8}{r['findings']:>10}{r['themes']:>9}"
            f"{r['mean_ms']:>14}{r['max_ms']:>12}"
        )
    # The 30s / minutes decision thresholds from the benchmark plan.
    medium = next((r for r in results if r["label"] == "medium"), None)
    if medium:
        verdict = "KEEP in Lambda" if medium["mean_ms"] < 30_000 else "MOVE to Fargate"
        print(f"\nmedium input mean = {medium['mean_ms']} ms -> {verdict}")


if __name__ == "__main__":
    _print_table(run())
