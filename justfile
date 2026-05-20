# List all available commands
default:
    @just --list

# ──────────────────────────────
# SAST Scanner (Node.js)
# ──────────────────────────────
sast-install:
    cd sast && npm install

sast-lint:
    cd sast && npm run lint

sast-test:
    cd sast && npm test

sast-start:
    cd sast && npm start

# ──────────────────────────────
# Analytics Engine (Python)
# ──────────────────────────────
analytics-install:
    cd analytics && pip install -r requirements.txt -r requirements-dev.txt

analytics-lint:
    cd analytics && ruff check src/ tests/

analytics-format:
    cd analytics && ruff format src/ tests/

analytics-test:
    cd analytics && pytest tests/ -v

# ──────────────────────────────
# API Layer (Python)
# ──────────────────────────────
api-install:
    cd api && pip install -r requirements.txt -r requirements-dev.txt

api-lint:
    cd api && ruff check src/ tests/

api-format:
    cd api && ruff format src/ tests/

api-test:
    cd api && pytest tests/ -v

api-start:
    cd api && uvicorn src.main:app --reload

# ──────────────────────────────
# Run everything
# ──────────────────────────────
install: sast-install analytics-install api-install

lint: sast-lint analytics-lint api-lint

test: sast-test analytics-test api-test

check: lint test