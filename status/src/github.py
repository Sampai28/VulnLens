"""Minimal GitHub REST client for posting the security gate result.

Implemented with the standard library (``urllib``) so the Lambda needs no extra
dependencies beyond what the Python runtime provides - the deployment zip stays
tiny and there's nothing to ``pip install``.

Two operations are used by the Status Lambda:

* :func:`post_commit_status` - the gate itself. Sets a commit status on the PR
  head SHA so the ``vulnlens/security-gate`` check shows pass/fail in the PR.
* :func:`post_pr_comment` - the human-readable detail. Posts (best-effort) the
  Markdown summary as an issue comment on the PR.

See https://docs.github.com/en/rest/commits/statuses and
https://docs.github.com/en/rest/issues/comments.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Optional

logger = logging.getLogger(__name__)

_API_ROOT = "https://api.github.com"
_TIMEOUT_SECONDS = 10


def _request(method: str, url: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Make an authenticated GitHub API request and return the parsed JSON body."""
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "vulnlens-status-lambda")

    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else {}


def post_commit_status(
    token: str,
    owner: str,
    repo: str,
    sha: str,
    state: str,
    context: str,
    description: str,
    target_url: Optional[str] = None,
) -> dict[str, Any]:
    """Set a commit status (``success``/``failure``/``pending``/``error``) on a SHA.

    This is the gate: GitHub branch protection can require the ``context`` check
    to be ``success`` before the PR is mergeable.
    """
    url = f"{_API_ROOT}/repos/{owner}/{repo}/statuses/{sha}"
    payload: dict[str, Any] = {
        "state": state,
        "context": context,
        "description": description[:140],  # GitHub caps descriptions at 140 chars
    }
    if target_url:
        payload["target_url"] = target_url

    result = _request("POST", url, token, payload)
    logger.info("Posted commit status %s=%s on %s/%s@%s", context, state, owner, repo, sha[:8])
    return result


def post_pr_comment(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    body: str,
) -> Optional[dict[str, Any]]:
    """Post a Markdown comment on a PR (best-effort).

    A failed comment must never fail the gate - the commit status is the source
    of truth - so this swallows errors and returns ``None`` on failure.
    """
    url = f"{_API_ROOT}/repos/{owner}/{repo}/issues/{pr_number}/comments"
    try:
        result = _request("POST", url, token, {"body": body})
        logger.info("Posted PR comment on %s/%s#%s", owner, repo, pr_number)
        return result
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as exc:
        logger.warning("Failed to post PR comment on %s/%s#%s: %s", owner, repo, pr_number, exc)
        return None
