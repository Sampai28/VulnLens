"""Cluster related findings into themes with DBSCAN.

A scan of a real codebase can produce dozens of findings. Reading them one by
one is hopeless; what a developer actually wants is *"you have 5 recurring
problems"*. This module groups findings into **themes** using DBSCAN
(density-based clustering), so eight hard-coded secrets across three files
collapse into a single "Hard-coded Credentials" theme with a root cause.

Why DBSCAN: it discovers how many groups exist at runtime (no ``k`` to guess)
and marks low-density points as noise. Here findings are embedded in a small
numeric feature space dominated by their vulnerability type, so density
clustering recovers the natural vuln-type groupings. Findings DBSCAN flags as
noise (a one-off type) become their own singleton theme - we never hide a
finding, we just stop burying the patterns.

The DBSCAN itself is a small pure-Python implementation (:func:`_dbscan_labels`)
with the same label semantics as scikit-learn's ``DBSCAN.fit_predict`` - core
points anchor clusters, density-reachable points join them, and isolated points
get label ``-1``. Keeping it dependency-free means the Lambda package stays
tiny (no scikit-learn / numpy layer) and the engine runs anywhere.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from typing import Any

from src.cwe_mapping import get_cwe
from src.scoring import risk_score

# Internal label sentinels for the DBSCAN state machine.
_UNVISITED = -2
_NOISE = -1


def _euclidean(a: list[float], b: list[float]) -> float:
    """Euclidean distance between two equal-length feature vectors."""
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def _dbscan_labels(points: list[list[float]], eps: float, min_samples: int) -> list[int]:
    """Cluster ``points`` with DBSCAN, returning a label per point.

    Labels match scikit-learn's convention: ``0..k`` for clusters (in order of
    discovery) and ``-1`` for noise. A point is *core* when at least
    ``min_samples`` points (including itself) lie within ``eps``; clusters grow
    by following density-reachability from core points.
    """
    n = len(points)
    labels = [_UNVISITED] * n

    def neighbors(i: int) -> list[int]:
        # The eps-neighbourhood includes the point itself (distance 0), so a
        # core point needs min_samples-1 *other* points nearby - same as sklearn.
        return [j for j in range(n) if _euclidean(points[i], points[j]) <= eps]

    cluster_id = 0
    for i in range(n):
        if labels[i] != _UNVISITED:
            continue

        nbrs = neighbors(i)
        if len(nbrs) < min_samples:
            labels[i] = _NOISE  # not a core point (may be reclaimed as a border)
            continue

        # Seed a new cluster and grow it breadth-first from this core point.
        labels[i] = cluster_id
        seeds = deque(j for j in nbrs if j != i)
        while seeds:
            j = seeds.popleft()
            if labels[j] == _NOISE:
                labels[j] = cluster_id  # previously-noise point is a border point
            if labels[j] != _UNVISITED:
                continue
            labels[j] = cluster_id
            j_nbrs = neighbors(j)
            if len(j_nbrs) >= min_samples:  # j is itself a core point -> expand
                seeds.extend(x for x in j_nbrs if labels[x] in (_UNVISITED, _NOISE))
        cluster_id += 1

    return labels


def _feature_matrix(findings: list[dict[str, Any]]) -> list[list[float]]:
    """Embed findings in a numeric space for clustering.

    The dominant axis is the vulnerability type (stable integer code per
    distinct ``id``), so findings of the same type sit on top of each other and
    cluster together regardless of which file or line they came from. That is
    exactly the "theme" we want to surface.
    """
    types = sorted({(f.get("id") or f.get("type") or "UNKNOWN") for f in findings})
    type_index = {t: i for i, t in enumerate(types)}

    matrix: list[list[float]] = []
    for f in findings:
        vuln_type = f.get("id") or f.get("type") or "UNKNOWN"
        matrix.append([float(type_index[vuln_type])])
    return matrix


def _summarize_theme(theme_id: int, members: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the human-facing summary for one cluster of findings."""
    types = [(f.get("id") or f.get("type") or "UNKNOWN") for f in members]
    dominant_type = Counter(types).most_common(1)[0][0]

    severities = [f.get("severity", "LOW") for f in members]
    dominant_severity = Counter(severities).most_common(1)[0][0]

    name = next(
        (f.get("name") for f in members if (f.get("id") or f.get("type")) == dominant_type and f.get("name")),
        dominant_type,
    )

    files = sorted({f.get("file") for f in members if f.get("file")})
    scores = [
        f["risk_score"] if "risk_score" in f else risk_score(f)
        for f in members
    ]

    return {
        "theme_id": theme_id,
        "vuln_type": dominant_type,
        "name": name,
        "cwe": get_cwe(dominant_type),
        "severity": dominant_severity,
        "count": len(members),
        "files": files,
        "file_count": len(files),
        "max_risk_score": max(scores) if scores else 0.0,
        "total_risk_score": round(sum(scores), 1),
        "findings": members,
    }


def cluster_findings(
    findings: list[dict[str, Any]],
    eps: float = 0.5,
    min_samples: int = 2,
) -> list[dict[str, Any]]:
    """Group findings into themes and return them ordered by total risk.

    Args:
        findings: raw or already-scored finding dicts.
        eps: DBSCAN neighbourhood radius. With the type-dominant embedding,
            the default of ``0.5`` keeps each distinct vulnerability type in its
            own dense region.
        min_samples: minimum points to form a dense cluster. Findings below the
            threshold are treated as noise and emitted as singleton themes.

    Returns:
        A list of theme dicts (see :func:`_summarize_theme`), sorted by
        ``total_risk_score`` descending so the worst pattern leads.
    """
    if not findings:
        return []

    matrix = _feature_matrix(findings)
    labels = _dbscan_labels(matrix, eps=eps, min_samples=min_samples)

    # Collect dense clusters by label; every noise point (-1) becomes its own
    # theme so nothing is dropped from the report.
    clusters: dict[int, list[dict[str, Any]]] = {}
    singletons: list[list[dict[str, Any]]] = []
    for label, finding in zip(labels, findings):
        if label == -1:
            singletons.append([finding])
        else:
            clusters.setdefault(label, []).append(finding)

    grouped = list(clusters.values()) + singletons

    themes = [_summarize_theme(i, members) for i, members in enumerate(grouped)]
    themes.sort(key=lambda t: t["total_risk_score"], reverse=True)

    # Reassign theme ids so they reflect the final (risk-sorted) order.
    for i, theme in enumerate(themes):
        theme["theme_id"] = i
    return themes
