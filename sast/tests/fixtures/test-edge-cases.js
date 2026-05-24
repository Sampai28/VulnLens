// EDGE CASE FILE: Mix of tricky patterns that test scanner accuracy
// Some lines LOOK suspicious but are safe. Some are actually vulnerable.

// ─── FALSE POSITIVE BAIT (should NOT trigger) ───

// Variable named "password" but no assignment with string literal
let password;
password = getUserInput();

// String contains "api_key" but inside a comment, not an assignment
// This documents the api_key format for reference

// eval is a property name, not a function call
const config = { eval: true, mode: 'strict' };

// innerHTML on a string variable, not a DOM element
const innerHTML = 'some text content';

// "SELECT" in a string but not in a query() call
const message = "SELECT a plan that works for you";

// console.log without sensitive keywords
console.log('Application started successfully');
console.log('Processing request', requestId);

// Math.random used for non-security (UI jitter) — but scanner flags ALL Math.random
// so we skip this bait since it would be a known, expected detection

// Path traversal in a comment (no quotes around the path, so scanner skips it)

// MD5 in a variable name, not a crypto call
const md5Hash = lookupPrecomputedHash(data);

// Version string that doesn't look like an IP
const version = '2.1.0';

// run() on a custom object (not exec)
const queryBuilder = { run: () => {} };
queryBuilder.run();

// ─── ACTUAL VULNERABILITIES (should trigger) ───

// Hardcoded secret buried in a longer line
const config2 = { debug: false, api_key: 'ABCDEFGHIJKLMNOP1234', timeout: 30 };

// SQL injection with extra whitespace
function searchUsers(db, term) {
  return db.query("SELECT * FROM users WHERE name LIKE '%" +
    term + "%'");
}

// eval called through a variable reference pattern
function processTemplate(template) {
  return eval(template);
}

// document.write called conditionally
function renderLegacy(content) {
  if (typeof document !== 'undefined') {
    document.write(content);
  }
}

// Weak crypto in a helper function
import crypto from 'crypto';
function quickHash(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

// Hardcoded IP in a config object
const dbConfig = {
  host: '10.0.1.50',
  port: 5432,
  database: 'vulnlens'
};

// Sensitive data logged with string interpolation
function debugAuth(token) {
  console.log('auth token received:', token);
}

// Path traversal in nested function
function serveFile(req, res) {
  const filePath = path.join('/public', req.params.filename);
  return res.sendFile(filePath);
}

// FIXME: security — need to add rate limiting
function loginHandler(req, res) {
  return authenticate(req.body);
}

// new Function used for dynamic template compilation
function compileTemplate(src) {
  return new Function('data', src);
}

export {
  password, config, innerHTML, message, jitter, md5Hash, version,
  queryBuilder, config2, searchUsers, processTemplate, renderLegacy,
  quickHash, dbConfig, debugAuth, serveFile, loginHandler, compileTemplate
};
