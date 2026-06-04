"""Tests for DBSCAN theme clustering."""

from src.clustering import cluster_findings


def test_empty_input_returns_no_themes():
    assert cluster_findings([]) == []


def test_same_type_findings_collapse_into_one_theme(sample_findings):
    themes = cluster_findings(sample_findings)
    by_type = {t["vuln_type"]: t for t in themes}

    # The 3 hard-coded secrets (across two files) form a single theme.
    assert by_type["HARDCODED_SECRET"]["count"] == 3
    assert by_type["HARDCODED_SECRET"]["file_count"] == 2
    assert set(by_type["HARDCODED_SECRET"]["files"]) == {"config.js", "db.js"}

    # The 2 SQL injections form their own theme.
    assert by_type["SQL_INJECTION"]["count"] == 2


def test_every_finding_lands_in_exactly_one_theme(sample_findings):
    themes = cluster_findings(sample_findings)
    clustered = sum(t["count"] for t in themes)
    assert clustered == len(sample_findings)


def test_one_off_types_become_singleton_themes(sample_findings):
    # WEAK_CRYPTO and SECURITY_TODO each appear once -> DBSCAN noise -> singletons.
    themes = cluster_findings(sample_findings)
    by_type = {t["vuln_type"]: t for t in themes}
    assert by_type["WEAK_CRYPTO"]["count"] == 1
    assert by_type["SECURITY_TODO"]["count"] == 1


def test_themes_sorted_by_total_risk_descending(sample_findings):
    themes = cluster_findings(sample_findings)
    totals = [t["total_risk_score"] for t in themes]
    assert totals == sorted(totals, reverse=True)
    # theme_ids reflect the sorted order.
    assert [t["theme_id"] for t in themes] == list(range(len(themes)))


def test_theme_carries_cwe_context(sample_findings):
    themes = cluster_findings(sample_findings)
    secret_theme = next(t for t in themes if t["vuln_type"] == "HARDCODED_SECRET")
    assert secret_theme["cwe"]["cwe"] == "CWE-798"
    assert secret_theme["name"] == "Hardcoded Secret"


def test_theme_count_matches_distinct_types(sample_findings):
    # Each distinct vuln type yields exactly one theme here.
    themes = cluster_findings(sample_findings)
    distinct_types = {f["id"] for f in sample_findings}
    assert len(themes) == len(distinct_types)
