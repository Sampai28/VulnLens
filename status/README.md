# VulnLens Status Gate

The final phase of the pipeline. It turns an analyzed scan into a **pass/fail
commit status** on the originating GitHub PR, so a reviewer (or branch
protection) can block a merge when HIGH-severity vulnerabilities are introduced.

```
SQS ──► Analytics Lambda ──► DynamoDB (analysis) ──► Status Lambda ──► GitHub commit status
                                                                  └──► GitHub PR comment
```

## What it does

For a given `scanId` the Status Lambda:

1. Loads the scan item (with its `analysis` block) from DynamoDB.
2. Evaluates the gate (`src/gate.py`): **fails if any finding is `HIGH`**
   (configurable via `GATE_FAIL_SEVERITY`).
3. Reads the `github` block threaded through the pipeline.
4. Fetches the GitHub token from Secrets Manager and posts:
   - a **commit status** (`vulnlens/security-gate` → `success`/`failure`) on the head SHA, and
   - a **PR comment** with the severity table, risk summary, and top findings.
5. Writes the decision back onto the scan item under a `status` attribute.

If the `github` block is missing, the gate is still evaluated and persisted, but
the GitHub post is **skipped gracefully** — so the pipeline runs end-to-end even
before the GitHub wiring is live.

## Integration contract — the `github` block  ⚠️ teammates read this

For the gate to report back to a commit, the scan item in DynamoDB must carry a
`github` block. The status Lambda only needs `owner`, `repo`, and `sha`
(`pr_number` is optional — it enables the PR comment):

```jsonc
{
  "scanId": "abc-123",
  "filename": "app.js",
  "findings": [ ... ],
  "analysis": { ... },        // added by the analytics Lambda
  "github": {                 // ← must be populated upstream
    "owner": "Sampai28",
    "repo": "VulnLens",
    "sha": "9f3e5e6...",       // PR head commit SHA — the status target
    "pr_number": 42            // optional; enables the PR comment
  }
}
```

This context originates in GitHub Actions and is currently **lost** before it
reaches analytics ([sast/src/server.js](../sast/src/server.js) mints a fresh
`scanId` and keeps only the filename). To close the loop, the upstream side
needs two small additions:

1. **GitHub Actions** (the S3-upload job) should pass the commit context to the
   scan — e.g. upload a `s3://vulnlens-uploads/<scanId>/_meta.json` containing
   `{ "github": { "owner", "repo", "sha", "pr_number" } }`, using
   `github.repository`, `github.event.pull_request.head.sha`, and
   `github.event.pull_request.number`.
2. **The scanner** ([sast/src/aws.js](../sast/src/aws.js) `saveResultsToDynamo`)
   should accept that `github` block and store it on the scan item.

The SQS message contract (`{scanId, filename, publishedAt}`) is unchanged — the
GitHub context rides on the DynamoDB item, not the queue message.

## Configuration (Lambda env vars)

| Variable | Default | Purpose |
|----------|---------|---------|
| `DYNAMO_TABLE` | `vulnlens-scans` | Scan results table. |
| `GITHUB_SECRET_ID` | `vulnlens/github-token` | Secrets Manager id of the GitHub token. |
| `GITHUB_SECRET_JSON_KEY` | `token` | JSON key inside the secret (bare-string secrets also work). |
| `GATE_FAIL_SEVERITY` | `HIGH` | Severity at/above which the gate fails (`HIGH`/`MEDIUM`/`LOW`). |
| `STATUS_CONTEXT` | `vulnlens/security-gate` | Commit-status context shown in the PR checks list. |
| `STATUS_TARGET_URL` | _(unset)_ | Optional link attached to the commit status. |

## Local testing

The gate logic is pure and the handler accepts an inline scan, so no AWS is
needed:

```bash
just status-install
just status-test
```

```python
from src.handler import lambda_handler

# Inline scan with no `github` block → gate runs, GitHub post is skipped.
lambda_handler({"scan": {"scanId": "t1", "findings": [
    {"id": "SQL_INJECTION", "severity": "HIGH", "file": "db.js", "line": 20},
]}})
```

## Deploy

Provisioned by [terraform/lambda.tf](../terraform/lambda.tf) alongside the
analytics Lambda, the SQS event-source mapping, and the Secrets Manager secret:

```bash
cd terraform
terraform apply -var="aws_account_id=<id>" -var="github_token=<ghp_...>"
```
