# VulnLens

**A cloud-hosted SAST platform that turns raw scan findings into prioritized, contextualized security insights using data science.**

## About

VulnLens is a cloud-hosted SAST scanning platform built on AWS that goes beyond finding vulnerabilities — it helps developers understand them. Users upload source code through a public web interface, VulnLens runs the provided SAST scanner against it, and then an analytics engine kicks in to make the results actually useful.

The analytics layer enriches each finding with CWE context from the MITRE hierarchy, computes a weighted risk score to prioritize what matters most, clusters related findings into actionable themes using unsupervised learning, and tracks security trends across multiple scans over time. Instead of reading through 80 individual issues, a developer sees 5 clear patterns with root causes.

No pre-trained models, no external datasets. The scans themselves generate the data — every finding becomes an input to the analytics engine. The risk scoring is a deterministic weighted formula, clustering uses DBSCAN to discover groupings at runtime, and trend tracking is computed from scan history stored in DynamoDB. The platform generates its own data through usage.

The entire system runs serverless on AWS — Lambda, S3, DynamoDB, API Gateway, Fargate, CloudFront, CloudWatch — keeping costs low when idle and scaling when needed. Built as a semester project for CS6620 Cloud Computing.

## Tech Stack

| Component | Language | Framework |
|-----------|----------|-----------|
| SAST Scanner | JavaScript | Node.js / Express |
| Analytics Engine | Python 3.11 | pure-Python (stdlib DBSCAN), boto3 |
| API Layer | Python 3.11 | FastAPI |
| Frontend | JavaScript | React |
| Cloud | AWS | S3, Lambda, DynamoDB, API Gateway, Fargate, CloudFront, CloudWatch |

## Repo Structure

    vulnlens/
    ├── .github/
    │   └── workflows/
    │       └── ci.yml                # Lint + test on every PR
    │
    ├── sast/                          # SAST Scanner (Node.js)
    │   ├── Dockerfile                 # Node 18 Alpine container
    │   ├── src/
    │   │   ├── scanner.js             # Core scanning logic (11 vuln types)
    │   │   ├── server.js              # Express API (port 3000)
    │   │   ├── aws.js                 # S3 + DynamoDB integration
    │   │   ├── cli.js                 # Human-readable scan report
    │   │   └── compare.js             # Ground truth comparison
    │   ├── tests/
    │   │   ├── scanner.test.js        # 31 tests (Node built-in test runner)
    │   │   └── fixtures/
    │   │       ├── test-vulnerable.js # All 11 vuln types (professor-provided)
    │   │       ├── test-clean.js      # Safe code — zero findings
    │   │       ├── test-edge-cases.js # False-positive bait + real vulns
    │   │       ├── ground-truth.json  # Expected findings for vulnerable file
    │   │       ├── ground-truth-clean.json
    │   │       └── ground-truth-edge-cases.json
    │   └── package.json
    │
    ├── analytics/                     # Analytics Engine (Python)
    │   ├── pyproject.toml
    │   ├── requirements.txt           # boto3 (Lambda runtime provides it; scoring/clustering are pure Python)
    │   ├── src/
    │   │   ├── cwe_mapping.py         # CWE lookup table (11 vuln types -> MITRE)
    │   │   ├── scoring.py             # Weighted risk score (severity x confidence x exploitability)
    │   │   ├── clustering.py          # DBSCAN grouping of findings into themes
    │   │   ├── trends.py              # Scan-over-scan comparison (DynamoDB history)
    │   │   ├── engine.py              # Orchestration: analyze_scan()
    │   │   └── handler.py             # AWS Lambda entrypoint
    │   └── tests/                     # pytest suite (57 tests)
    │
    ├── api/                           # API Layer (Python/FastAPI)
    │   ├── pyproject.toml
    │   └── src/
    │       └── main.py                # FastAPI app
    │
    ├── frontend/                      # Dashboard (React)
    │   └── src/
    │
    ├── justfile                       # Command runner (single entry point)
    ├── .gitignore
    └── README.md
## Quick Start

### Prerequisites

- Node.js 18+
- Python 3.11+ with [uv](https://docs.astral.sh/uv/)
- [just](https://github.com/casey/just) command runner

### Run individual services

```bash
just sast-start       # SAST scanner on http://localhost:3000
just api-start        # FastAPI on http://localhost:8000
```

## Just Commands

[just](https://github.com/casey/just) is a command runner (like `make` but simpler). It reads the `justfile` in the repo root and runs the recipe you ask for. Think of it as shortcuts for project commands — instead of remembering `cd sast && npm test`, you just run `just sast-test`.

**Install:** `winget install Casey.Just` (Windows) · `brew install just` (Mac) · `sudo apt install just` (Ubuntu)

After installing, restart your terminal. Run `just --list` to see all available commands.

All commands run through `just` — no direct `npm` or `pip` needed.

| Command | What it does |
|---------|-------------|
| `just check` | Lint + test + ground truth validation (mirrors CI) |
| `just install` | Install all dependencies |
| `just lint` | Lint all code |
| `just test` | Run all tests |
| `just sast-start` | Start the SAST scanner on http://localhost:3000 |
| `just sast-test` | Run 31 scanner unit tests |
| `just sast-lint` | ESLint check on scanner source |
| `just sast-scan <file>` | Scan a file/directory with colored report |
| `just sast-compare` | Validate scanner against ground truth |
| `just sast-docker-build` | Build the scanner Docker image |
| `just sast-docker-run` | Run scanner container on port 3000 |
| `just sast-docker-stop` | Stop and remove scanner container |
| `just analytics-install` | Install analytics Python dependencies |
| `just analytics-test` | Run analytics engine tests (57 tests) |

## Working on Features

```bash
git checkout -b feature/your-feature-name   # create branch
# make changes
just check                                   # lint + test locally
git add .
git commit -m "feat: describe what you did"
git push origin feature/your-feature-name    # push and open PR on GitHub
```

Branch prefixes: `feature/`, `fix/`, `docs/`, `test/`

## SAST Scanner

The scanner detects 11 vulnerability types in JavaScript/Node.js code via regex pattern matching:

| Severity | Types |
|----------|-------|
| HIGH | Hardcoded Secrets, SQL Injection, NoSQL Injection, XSS, Path Traversal, Insecure Functions |
| MEDIUM | Hardcoded IPs, Insecure Randomness, Weak Crypto, Sensitive Data Logging |
| LOW | Security TODOs/FIXMEs |

Validated against 3 test fixtures:

| Fixture | Purpose | Expected findings |
|---------|---------|-------------------|
| `test-vulnerable.js` | All 11 vuln types (professor-provided) | 36 (100% precision/recall) |
| `test-clean.js` | Safe code — zero false positives | 0 |
| `test-edge-cases.js` | Tricky bait + real vulns mixed | 10 (bait triggers nothing) |

**31 tests total, all passing.**

## Analytics Engine

The analytics engine turns the scanner's flat list of findings into prioritized, contextualized insight. It runs four stages over a scan — all deterministic, no pre-trained models, no external datasets.

| Stage | Module | What it produces |
|-------|--------|------------------|
| CWE enrichment | `cwe_mapping.py` | Every finding tagged with its MITRE CWE id, name, description, and link |
| Risk scoring | `scoring.py` | A 0–100 score per finding so the worst issues sort to the top |
| Clustering | `clustering.py` | Findings grouped into **themes** via DBSCAN (e.g. "8 hard-coded secrets across 3 files") |
| Trends | `trends.py` | Current scan compared against history — new/resolved issues, improving vs. worsening |

### Risk score formula

Each finding gets a deterministic, explainable score:

```
risk = severity × confidence × exploitability   →   scaled to 0–100
```

- **severity** — damage if exploited (HIGH / MEDIUM / LOW, from the scanner)
- **confidence** — how reliable the detection is, tuned per vulnerability type
- **exploitability** — how easily an attacker can leverage it, tuned per type

Scores bucket into `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`. An SQL injection (HIGH) lands ~66 (CRITICAL); a security TODO (LOW) lands ~3 (LOW).

### Clustering into themes

`clustering.py` embeds findings in a feature space dominated by vulnerability type and runs **DBSCAN** to discover groupings at runtime — no `k` to pick. Dense groups become themes; one-off findings DBSCAN flags as noise become singleton themes, so nothing is ever dropped. Each theme carries its CWE context, affected files, and total risk.

DBSCAN is a small **pure-Python** implementation with the same label semantics as scikit-learn (`0..k` clusters, `-1` noise) — no scikit-learn/numpy dependency, so the Lambda package stays tiny and the engine runs anywhere.

### Orchestration & deployment

`engine.analyze_scan(scan, history)` is a **pure function** that runs all four stages and returns the enriched report — so it's fully unit-testable and reusable by both the API and Lambda. `handler.lambda_handler` is the AWS Lambda entrypoint: it accepts either a `scanId` (loads the scan + file history from the `vulnlens-scans` DynamoDB table) or an inline `scan`, then returns the analysis as JSON.

```bash
just analytics-install   # boto3 + pytest (scoring/clustering need no third-party deps)
just analytics-test      # 57 tests
```

**Deploying the Lambda** — zip the `analytics/src/` package and set the handler to `src.handler.lambda_handler`. No dependency layer is needed: scoring, CWE enrichment, and DBSCAN clustering are pure Python, and the `boto3` SDK is already provided by the Lambda runtime.

## CI/CD Pipeline

GitHub Actions runs automatically on every pull request to `main` and on every push to `main`.

### What CI runs

| Step | Command | What it checks |
|------|---------|----------------|
| Install SAST dependencies | `just sast-install` | Node.js packages install cleanly |
| Lint SAST code | `just sast-lint` | ESLint passes on all source files |
| Run SAST tests | `just sast-test` | 31 unit tests pass (all 11 vuln types) |
| Validate ground truth | `just sast-compare` | Scanner output matches expected findings (precision/recall) |
| Install analytics deps | `just analytics-install` | Python packages install cleanly |
| Run analytics tests | `just analytics-test` | 57 analytics tests pass (scoring, CWE, clustering, trends) |

A final **CI Gate** job runs after all checks pass — PRs cannot merge until CI Gate is green.

### Branch protection

- `main` is protected — direct pushes are blocked
- All PRs require CI Gate to pass before merging
- Run `just check` locally before pushing to catch issues early

### How CI works

```
PR opened / push to main
  └─ ci-checks (ubuntu-latest)
       ├─ Setup Node.js 18, Python 3.11, just
       ├─ just sast-install
       ├─ just sast-lint
       ├─ just sast-test
       ├─ just sast-compare
       ├─ just analytics-install
       └─ just analytics-test
  └─ ci-gate (waits for ci-checks)
       └─ All checks passed ✓
```

### Adding new checks

When analytics and API services are built, add steps to the `ci-checks` job:

```yaml
- name: Install analytics dependencies
  run: just analytics-install

- name: Run analytics tests
  run: just analytics-test
```

All CI commands use `just` — same commands you run locally.