import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

// Safe: password from environment variable, not hardcoded
const password = process.env.DB_PASSWORD;

// Safe: cryptographically secure random
const token = crypto.randomUUID();
const sessionId = crypto.randomBytes(32).toString('hex');

// Safe: strong hashing
const hash = crypto.createHash('sha256').update('data').digest('hex');

// Safe: parameterized query (no string concatenation)
function findUser(db, userId) {
  return db.query('SELECT * FROM users WHERE id = $1', [userId]);
}

// Safe: sanitized input before MongoDB query
function findUsers(collection, name) {
  const sanitized = String(name).replace(/[$]/g, '');
  return collection.find({ name: sanitized });
}

// Safe: textContent instead of innerHTML
function renderName(element, name) {
  element.textContent = name;
}

// Safe: validated file path
function readFile(baseDir, filename) {
  const resolved = path.resolve(baseDir, filename);
  if (!resolved.startsWith(path.resolve(baseDir))) {
    throw new Error('Path traversal detected');
  }
  return fs.readFileSync(resolved, 'utf8');
}

// Safe: host from config, not hardcoded
const dbHost = process.env.DB_HOST || 'localhost';

// Safe: no sensitive data in logs
console.log('Server started');
console.info('Ready to accept connections');

// Regular TODO (not security-related)
// TODO: add pagination to user list

export { password, token, sessionId, hash, findUser, findUsers, renderName, readFile, dbHost };
