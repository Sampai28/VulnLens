"""Fetch the GitHub token from AWS Secrets Manager.

The Status Lambda needs a GitHub token with ``repo:status`` (and, for PR
comments, ``pull_request``) scope to write a commit status back to the PR. We
keep it in Secrets Manager rather than a Lambda env var so it never appears in
the function configuration or CloudWatch logs.

``boto3`` is imported lazily so the pure gate logic and unit tests don't need
AWS credentials or the SDK. The fetched secret is cached on the module for the
lifetime of the warm Lambda container to avoid a Secrets Manager call per
invocation.
"""

from __future__ import annotations

import json
import os
from typing import Optional

# Secrets Manager id (name or ARN) holding the GitHub token.
GITHUB_SECRET_ID = os.environ.get("GITHUB_SECRET_ID", "vulnlens/github-token")

# JSON key to read when the secret is stored as a JSON blob (the common shape).
# If the secret is a bare string, we use it directly.
_SECRET_JSON_KEY = os.environ.get("GITHUB_SECRET_JSON_KEY", "token")

_cached_token: Optional[str] = None


def get_github_token(secret_id: str = GITHUB_SECRET_ID) -> str:
    """Return the GitHub token, caching it across warm invocations.

    Accepts either a bare-string secret or a JSON secret of the form
    ``{"token": "ghp_..."}``. Raises ``RuntimeError`` if the secret can't be
    resolved so the caller fails loudly rather than posting with no auth.
    """
    global _cached_token
    if _cached_token:
        return _cached_token

    import boto3  # local import: only needed on the AWS path

    region = os.environ.get("AWS_REGION", "us-east-1")
    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_id)
    raw = response.get("SecretString")
    if not raw:
        raise RuntimeError(f"Secret {secret_id} has no SecretString value")

    token = _extract_token(raw)
    if not token:
        raise RuntimeError(f"Secret {secret_id} did not contain a usable token")

    _cached_token = token
    return token


def _extract_token(raw: str) -> Optional[str]:
    """Pull the token out of a bare string or a ``{"token": ...}`` JSON blob."""
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return raw.strip()

    if isinstance(parsed, dict):
        return parsed.get(_SECRET_JSON_KEY) or parsed.get("GITHUB_TOKEN")
    return raw.strip()


def _reset_cache_for_tests() -> None:
    """Clear the module-level token cache (used by unit tests)."""
    global _cached_token
    _cached_token = None
