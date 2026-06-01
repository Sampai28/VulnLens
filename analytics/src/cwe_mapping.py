"""CWE enrichment for VulnLens findings.

Maps each SAST scanner vulnerability type (the ``id`` field on a finding) to
its corresponding `MITRE CWE <https://cwe.mitre.org/>`_ entry: the CWE ID, the
official weakness name, a short description, and a link into the MITRE CWE
database.

The scanner (``sast/src/scanner.js``) emits 11 vulnerability types. Every one
of them is mapped here so that no finding is left without context.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Optional

# Base URL for an individual CWE definition on the MITRE site.
MITRE_BASE_URL = "https://cwe.mitre.org/data/definitions"


def mitre_url(cwe_id: int) -> str:
    """Build the canonical MITRE link for a numeric CWE id (e.g. ``79``)."""
    return f"{MITRE_BASE_URL}/{cwe_id}.html"


# Vulnerability-type id (from the scanner) -> CWE metadata.
#
# ``cwe_id`` is the integer CWE number; ``cwe`` is the conventional "CWE-79"
# string form used in reports and APIs.
CWE_MAP: dict[str, dict[str, Any]] = {
    "HARDCODED_SECRET": {
        "cwe_id": 798,
        "name": "Use of Hard-coded Credentials",
        "description": (
            "Secrets such as API keys, passwords, or tokens embedded directly "
            "in source code can be extracted by anyone with read access to the "
            "code and cannot be rotated without a redeploy."
        ),
    },
    "SQL_INJECTION": {
        "cwe_id": 89,
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": (
            "Building SQL queries by concatenating untrusted input lets an "
            "attacker alter the query, reading or modifying data they should "
            "not be able to reach."
        ),
    },
    "NOSQL_INJECTION": {
        "cwe_id": 943,
        "name": "Improper Neutralization of Special Elements in Data Query Logic",
        "description": (
            "Passing unsanitized user input into NoSQL/MongoDB query objects "
            "allows operator injection (e.g. $where, $regex), bypassing "
            "authentication or exfiltrating data."
        ),
    },
    "XSS": {
        "cwe_id": 79,
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "description": (
            "Writing untrusted data into the DOM (innerHTML, document.write, "
            "dangerouslySetInnerHTML) lets an attacker run arbitrary script in "
            "a victim's browser."
        ),
    },
    "PATH_TRAVERSAL": {
        "cwe_id": 22,
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "description": (
            "Using untrusted input in filesystem paths allows '../' sequences "
            "to escape the intended directory and read or write arbitrary files."
        ),
    },
    "INSECURE_FUNCTION": {
        "cwe_id": 94,
        "name": "Improper Control of Generation of Code ('Code Injection')",
        "description": (
            "Dynamic code execution primitives such as eval(), new Function(), "
            "and child_process exec/spawn can run attacker-controlled code if "
            "fed untrusted input."
        ),
    },
    "INSECURE_RANDOM": {
        "cwe_id": 338,
        "name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "description": (
            "Math.random() is predictable and unsuitable for security-sensitive "
            "values like tokens, session ids, or password resets."
        ),
    },
    "SENSITIVE_DATA_LOG": {
        "cwe_id": 532,
        "name": "Insertion of Sensitive Information into Log File",
        "description": (
            "Logging passwords, tokens, or personal data exposes those secrets "
            "to anyone with access to the logs."
        ),
    },
    "HARDCODED_IP": {
        "cwe_id": 547,
        "name": "Use of Hard-coded, Security-relevant Constants",
        "description": (
            "Hard-coded IP addresses tie the code to a fixed environment and "
            "can leak internal network topology; they should be configurable."
        ),
    },
    "SECURITY_TODO": {
        "cwe_id": 546,
        "name": "Suspicious Comment",
        "description": (
            "TODO/FIXME/HACK comments referencing security concerns often mark "
            "known-but-unaddressed weaknesses left in the code."
        ),
    },
    "WEAK_CRYPTO": {
        "cwe_id": 327,
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "description": (
            "Algorithms like MD5, SHA1, DES, and RC4 are broken or weakened and "
            "should be replaced with modern primitives such as SHA-256 or AES-256."
        ),
    },
}


def get_cwe(vuln_type: str) -> Optional[dict[str, Any]]:
    """Return the full CWE record for a vulnerability type, or ``None``.

    The returned dict contains ``cwe`` (e.g. ``"CWE-79"``), ``cwe_id``,
    ``name``, ``description``, and ``url``.
    """
    entry = CWE_MAP.get(vuln_type)
    if entry is None:
        return None
    cwe_id = entry["cwe_id"]
    return {
        "cwe": f"CWE-{cwe_id}",
        "cwe_id": cwe_id,
        "name": entry["name"],
        "description": entry["description"],
        "url": mitre_url(cwe_id),
    }


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``finding`` with a ``cwe`` block attached.

    Looks up the finding's ``id`` (falling back to ``type``). Unknown types
    get ``cwe = None`` rather than raising, so the pipeline never drops a
    finding it cannot classify.
    """
    enriched = deepcopy(finding)
    vuln_type = finding.get("id") or finding.get("type")
    enriched["cwe"] = get_cwe(vuln_type) if vuln_type else None
    return enriched


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrich a list of findings with CWE context (see :func:`enrich_finding`)."""
    return [enrich_finding(f) for f in findings]
