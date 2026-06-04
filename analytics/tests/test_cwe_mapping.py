"""Tests for CWE enrichment."""

from src.cwe_mapping import CWE_MAP, enrich_finding, enrich_findings, get_cwe, mitre_url

# The 11 vulnerability types the SAST scanner emits - all must be mapped.
SCANNER_VULN_TYPES = {
    "HARDCODED_SECRET",
    "SQL_INJECTION",
    "NOSQL_INJECTION",
    "XSS",
    "PATH_TRAVERSAL",
    "INSECURE_FUNCTION",
    "INSECURE_RANDOM",
    "SENSITIVE_DATA_LOG",
    "HARDCODED_IP",
    "SECURITY_TODO",
    "WEAK_CRYPTO",
}


def test_every_scanner_type_is_mapped():
    assert SCANNER_VULN_TYPES <= set(CWE_MAP)


def test_mitre_url_format():
    assert mitre_url(79) == "https://cwe.mitre.org/data/definitions/79.html"


def test_get_cwe_shape():
    cwe = get_cwe("SQL_INJECTION")
    assert cwe["cwe"] == "CWE-89"
    assert cwe["cwe_id"] == 89
    assert "SQL" in cwe["name"]
    assert cwe["url"].endswith("/89.html")
    assert cwe["description"]


def test_get_cwe_unknown_returns_none():
    assert get_cwe("NOT_A_RULE") is None


def test_all_cwe_ids_are_positive_ints():
    for entry in CWE_MAP.values():
        assert isinstance(entry["cwe_id"], int)
        assert entry["cwe_id"] > 0
        assert entry["name"]
        assert entry["description"]


def test_enrich_finding_attaches_cwe_without_mutating():
    finding = {"id": "XSS", "severity": "HIGH"}
    enriched = enrich_finding(finding)
    assert "cwe" not in finding
    assert enriched["cwe"]["cwe"] == "CWE-79"


def test_enrich_finding_unknown_type_sets_none():
    enriched = enrich_finding({"id": "MYSTERY", "severity": "LOW"})
    assert enriched["cwe"] is None


def test_enrich_finding_supports_type_alias():
    enriched = enrich_finding({"type": "WEAK_CRYPTO", "severity": "MEDIUM"})
    assert enriched["cwe"]["cwe_id"] == 327


def test_enrich_findings_preserves_count(sample_findings):
    enriched = enrich_findings(sample_findings)
    assert len(enriched) == len(sample_findings)
    assert all("cwe" in f for f in enriched)
