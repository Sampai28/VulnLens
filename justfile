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

sast-scan file:
    cd sast && node src/cli.js {{file}}

sast-compare:
    cd sast && node src/compare.js

sast-docker-build:
    docker build -t vulnlens-sast ./sast

sast-docker-run:
    docker run -d --name vulnlens-sast -p 3000:3000 vulnlens-sast

sast-docker-stop:
    docker stop vulnlens-sast && docker rm vulnlens-sast

# ──────────────────────────────
# Analytics Engine (Python)
# ──────────────────────────────
analytics-install:
    cd analytics && pip install -r requirements-dev.txt

analytics-test:
    cd analytics && python -m pytest -q

# ──────────────────────────────
# Run everything
# ──────────────────────────────
install: sast-install analytics-install

lint: sast-lint

test: sast-test analytics-test

check: lint test sast-compare
