# SAST Scanner

A Static Application Security Testing (SAST) scanner. It detects common security
vulnerabilities in **JavaScript/TypeScript, Python, and Jupyter notebooks** by
matching regex rules against source code. The language is chosen from the file
extension (`src/detect-language.js`) and the matching rule set
(`src/rules-js.js` or `src/rules-python.js`) is applied; `.ipynb` files are
parsed cell-by-cell (`src/ipynb.js`).

Supported extensions: `.js` `.jsx` `.mjs` `.cjs` `.ts` `.tsx` → JavaScript ·
`.py` → Python · `.ipynb` → Jupyter.

## Vulnerabilities Detected

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| HARDCODED_SECRET | Hardcoded Secret | HIGH | API keys, passwords, tokens in source code |
| SQL_INJECTION | SQL Injection Risk | HIGH | String concatenation / interpolation in SQL queries |
| NOSQL_INJECTION | NoSQL Injection Risk | HIGH | Direct user input in MongoDB queries |
| XSS | Cross-Site Scripting (XSS) | HIGH | Dynamic `innerHTML`, `document.write()`, etc. |
| PATH_TRAVERSAL | Path Traversal | HIGH | User input flowing into file paths |
| INSECURE_FUNCTION | Insecure Function Usage | HIGH | Dangerous functions like `eval()`, `exec()`, `pickle.load()` |
| HARDCODED_IP | Hardcoded IP Address | MEDIUM | IP addresses that should be configurable |
| INSECURE_RANDOM | Insecure Randomness | MEDIUM | `Math.random()` / `random.random()` for security values |
| WEAK_CRYPTO | Weak Cryptography | MEDIUM | MD5, SHA1, or deprecated crypto functions |
| SENSITIVE_DATA_LOG | Sensitive Data Logging | MEDIUM | Logging/printing passwords, tokens, or keys |
| SECURITY_TODO | Security TODO/FIXME | LOW | Security-related comments needing attention |

## Setup

```bash
# Install dependencies
npm install

# Start the server
npm start          # or: node src/server.js
```

The server will start on port 3000 (or the `PORT` environment variable).

## API Endpoints

### Health Check
```
GET /health
```
Returns server status.

### List Vulnerability Types
```
GET /vulnerabilities
```
Returns all supported vulnerability checks.

### Scan Code Snippet
```
POST /scan/code
Content-Type: application/json

{
  "code": "const password = 'secret123';",
  "filename": "app.js"
}
```

### Scan a File
```
POST /scan/file
Content-Type: application/json

{
  "filepath": "./tests/fixtures/test-vulnerable.js"
}
```

### Scan a Directory
```
POST /scan/directory
Content-Type: application/json

{
  "dirpath": "./src"
}
```

### Scan from S3
```
POST /scan/s3
Content-Type: application/json

{
  "bucket": "vulnlens-uploads",
  "key": "<scanId>/path/to/file.js"
}
```
Downloads the object, scans it, and persists the result to DynamoDB.

### Fetch a Stored Result
```
GET /results/:scanId
```
Returns a previously stored scan result from DynamoDB.

## Example Response

```json
{
  "success": true,
  "filename": "app.js",
  "scannedAt": "2026-01-15T10:30:00.000Z",
  "summary": {
    "totalVulnerabilities": 3,
    "high": 2,
    "medium": 1,
    "low": 0
  },
  "vulnerabilities": [
    {
      "id": "HARDCODED_SECRET",
      "name": "Hardcoded Secret",
      "severity": "HIGH",
      "description": "Hardcoded password",
      "message": "Hardcoded secret detected. Move secrets to environment variables.",
      "file": "app.js",
      "line": 5,
      "column": 7,
      "evidence": "const password = 'secret123';"
    }
  ]
}
```

## Testing

```bash
npm test            # 72 unit tests (Node built-in test runner)
npm run lint        # ESLint over src/
node src/compare.js # validate scanner output against ground truth
```

Or via the repo `justfile`: `just sast-test`, `just sast-lint`, `just sast-compare`.

Fixtures live in `tests/fixtures/` — `vulnerable` / `clean` / `edge-cases`
variants for each language (`.js`, `.py`, `.ipynb`), each paired with a
`ground-truth-*.json` of expected findings.

## Project Structure

```
sast/
├── src/
│   ├── scanner.js           # Core scanning logic
│   ├── detect-language.js   # Pick rules by file extension
│   ├── rules-js.js          # JavaScript/TypeScript rule set
│   ├── rules-python.js      # Python rule set
│   ├── ipynb.js             # Jupyter notebook parsing
│   ├── server.js            # Express server with API endpoints
│   ├── aws.js               # S3 + DynamoDB integration
│   ├── cli.js               # Human-readable scan report
│   └── compare.js           # Ground truth comparison
├── tests/
│   ├── scanner.test.js      # Unit tests
│   └── fixtures/            # Per-language fixtures + ground truth
├── Dockerfile               # Node 18 Alpine container
├── package.json
└── README.md                # This file
```
