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
| Analytics Engine | Python 3.11 | scikit-learn, pandas |
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
    │   ├── src/
    │   │   ├── scanner.js             # Core scanning logic (11 vuln types)
    │   │   ├── server.js              # Express API (port 3000)
    │   │   ├── cli.js                 # Human-readable scan report
    │   │   └── compare.js             # Ground truth comparison
    │   ├── tests/
    │   │   ├── scanner.test.js        # 29 tests (Node built-in test runner)
    │   │   └── fixtures/
    │   │       ├── test-vulnerable.js # Intentionally vulnerable sample
    │   │       └── ground-truth.json  # Expected findings for validation
    │   └── package.json
    │
    ├── analytics/                     # Analytics Engine (Python)
    │   ├── pyproject.toml
    │   └── src/
    │       ├── cwe_mapping.py         # CWE lookup table (10 vuln types)
    │       └── scoring.py             # Risk scoring formula
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

All commands run through `just` — no direct `npm` or `pip` needed.

| Command | What it does |
|---------|-------------|
| `just install` | Install dependencies for all services |
| `just lint` | Lint all services (ESLint + Ruff) |
| `just test` | Run all tests |
| `just check` | Lint + test everything (mirrors CI) |
| `just sast-start` | Start the SAST scanner locally |
| `just sast-test` | Run scanner unit tests (29 tests) |
| `just sast-scan <file>` | Scan a file/directory with colored report |
| `just sast-compare` | Validate scanner against ground truth |
| `just api-start` | Start the FastAPI server locally |
| `just analytics-format` | Auto-format Python analytics code |
| `just api-format` | Auto-format Python API code |

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

Validated against a professor-provided test file: **36/36 findings detected, 100% precision and recall.**

## CI Pipeline

Every pull request to `main` triggers a GitHub Actions workflow that runs three parallel jobs:

1. **SAST Scanner** — installs Node.js 18 dependencies, runs scanner tests
2. **Analytics Engine** — installs Python 3.11 dependencies, runs Ruff linter + format check, runs Pytest
3. **API Layer** — installs Python 3.11 dependencies, runs Ruff linter + format check, runs Pytest

All three jobs must pass before a PR can be merged. A final **CI Gate** job confirms everything is green. Run `just check` locally before pushing to catch issues early.