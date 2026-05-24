import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanCode, scanFile } from '../src/scanner.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-vulnerable.js');
const CLEAN_FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-clean.js');
const EDGE_FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-edge-cases.js');

describe('scanCode', () => {
  it('returns empty array for clean code', () => {
    const results = scanCode('const x = 1;', 'clean.js');
    assert.equal(results.length, 0);
  });

  it('detects hardcoded passwords', () => {
    const code = `const password = 'supersecret123';`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'HARDCODED_SECRET');
    assert.ok(match, 'should detect hardcoded password');
    assert.equal(match.severity, 'HIGH');
  });

  it('detects hardcoded API keys', () => {
    const code = `const api_key = 'ABCDEFGHIJKLMNOP';`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'HARDCODED_SECRET');
    assert.ok(match, 'should detect hardcoded API key');
  });

  it('detects AWS access key ID', () => {
    const code = `const aws_access_key_id = 'AKIA1234567890ABCDEF';`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'HARDCODED_SECRET' && v.description.includes('AWS'));
    assert.ok(match, 'should detect AWS access key');
  });

  it('detects GitHub personal access token', () => {
    const code = `const token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'HARDCODED_SECRET' && v.description.includes('GitHub'));
    assert.ok(match, 'should detect GitHub PAT');
  });

  it('detects SQL injection via string concatenation', () => {
    const code = `db.query("SELECT * FROM users WHERE id = '" + userId + "')";`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'SQL_INJECTION');
    assert.ok(match, 'should detect SQL injection');
    assert.equal(match.severity, 'HIGH');
  });

  it('detects SQL injection via template literals', () => {
    const code = 'db.query(`DELETE FROM orders WHERE id = ${orderId}`);';
    const results = scanCode(code);
    const match = results.find(v => v.id === 'SQL_INJECTION');
    assert.ok(match, 'should detect template literal SQL injection');
  });

  it('detects NoSQL injection with direct req.body in find()', () => {
    const code = `users.find(req.body);`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'NOSQL_INJECTION');
    assert.ok(match, 'should detect NoSQL injection');
    assert.equal(match.severity, 'HIGH');
  });

  it('detects NoSQL injection with req.query in findOne()', () => {
    const code = `collection.findOne(req.query);`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'NOSQL_INJECTION');
    assert.ok(match, 'should detect NoSQL findOne injection');
  });

  it('detects XSS via innerHTML', () => {
    const code = `element.innerHTML = userInput;`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'XSS');
    assert.ok(match, 'should detect innerHTML XSS');
    assert.equal(match.severity, 'HIGH');
  });

  it('detects XSS via document.write', () => {
    const code = `document.write(data);`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'XSS');
    assert.ok(match, 'should detect document.write XSS');
  });

  it('detects path traversal with req input in fs calls', () => {
    const code = `fs.readFileSync(req.query.file);`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'PATH_TRAVERSAL');
    assert.ok(match, 'should detect path traversal');
    assert.equal(match.severity, 'HIGH');
  });

  it('detects path traversal sequences', () => {
    const code = `const p = '../../etc/passwd';`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'PATH_TRAVERSAL');
    assert.ok(match, 'should detect ../ traversal pattern');
  });

  it('detects insecure Math.random()', () => {
    const code = `const token = Math.random().toString(36);`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'INSECURE_RANDOM');
    assert.ok(match, 'should detect Math.random()');
    assert.equal(match.severity, 'MEDIUM');
  });

  it('detects sensitive data logging', () => {
    const code = `console.log('password', userPassword);`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'SENSITIVE_DATA_LOG');
    assert.ok(match, 'should detect password logging');
    assert.equal(match.severity, 'MEDIUM');
  });

  it('detects eval() usage', () => {
    const code = `eval(userInput);`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'INSECURE_FUNCTION');
    assert.ok(match, 'should detect eval()');
    assert.equal(match.severity, 'HIGH');
  });

  it('detects new Function() usage', () => {
    const code = `const fn = new Function(code);`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'INSECURE_FUNCTION');
    assert.ok(match, 'should detect new Function()');
  });

  it('detects hardcoded IP addresses', () => {
    const code = `const host = '192.168.1.100';`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'HARDCODED_IP');
    assert.ok(match, 'should detect hardcoded IP');
    assert.equal(match.severity, 'MEDIUM');
  });

  it('detects weak crypto (MD5)', () => {
    const code = `crypto.createHash('md5').update(data).digest('hex');`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'WEAK_CRYPTO');
    assert.ok(match, 'should detect MD5 usage');
    assert.equal(match.severity, 'MEDIUM');
  });

  it('detects weak crypto (SHA1)', () => {
    const code = `crypto.createHash('sha1').update(data).digest('hex');`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'WEAK_CRYPTO');
    assert.ok(match, 'should detect SHA1 usage');
  });

  it('detects security TODO comments', () => {
    const code = `// TODO: security fix auth bypass`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'SECURITY_TODO');
    assert.ok(match, 'should detect security TODO');
    assert.equal(match.severity, 'LOW');
  });

  it('reports correct line numbers', () => {
    const code = `const x = 1;\nconst y = 2;\nconst password = 'secret123';\n`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'HARDCODED_SECRET');
    assert.ok(match);
    assert.equal(match.line, 3);
  });

  it('includes evidence in results', () => {
    const code = `const password = 'hunter2';`;
    const results = scanCode(code);
    const match = results.find(v => v.id === 'HARDCODED_SECRET');
    assert.ok(match);
    assert.ok(match.evidence.length > 0, 'evidence should not be empty');
  });

  it('sorts results by severity then line number', () => {
    const code = [
      `const token = Math.random();`,
      `eval(input);`,
      `// TODO: security fix this`,
    ].join('\n');
    const results = scanCode(code);
    assert.ok(results.length >= 3);
    const severities = results.map(v => v.severity);
    const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    for (let i = 1; i < severities.length; i++) {
      assert.ok(
        order[severities[i]] >= order[severities[i - 1]],
        `severity ordering: ${severities[i - 1]} should come before or equal ${severities[i]}`
      );
    }
  });

  it('uses provided filename in results', () => {
    const code = `const password = 'test123';`;
    const results = scanCode(code, 'myapp.js');
    assert.ok(results.length > 0);
    assert.equal(results[0].file, 'myapp.js');
  });
});

describe('scanFile', () => {
  it('scans the test-vulnerable fixture and finds all 11 vuln types', () => {
    const results = scanFile(FIXTURE_PATH);
    const vulnTypes = new Set(results.map(v => v.id));

    assert.ok(vulnTypes.has('HARDCODED_SECRET'));
    assert.ok(vulnTypes.has('SQL_INJECTION'));
    assert.ok(vulnTypes.has('NOSQL_INJECTION'));
    assert.ok(vulnTypes.has('XSS'));
    assert.ok(vulnTypes.has('PATH_TRAVERSAL'));
    assert.ok(vulnTypes.has('INSECURE_RANDOM'));
    assert.ok(vulnTypes.has('SENSITIVE_DATA_LOG'));
    assert.ok(vulnTypes.has('INSECURE_FUNCTION'));
    assert.ok(vulnTypes.has('HARDCODED_IP'));
    assert.ok(vulnTypes.has('WEAK_CRYPTO'));
    assert.ok(vulnTypes.has('SECURITY_TODO'));
    assert.equal(vulnTypes.size, 11);
  });

  it('finds at least 30 total vulnerabilities in fixture', () => {
    const results = scanFile(FIXTURE_PATH);
    assert.ok(results.length >= 30, `expected >= 30 vulns, got ${results.length}`);
  });

  it('throws for nonexistent file', () => {
    assert.throws(
      () => scanFile('/nonexistent/file.js'),
      { message: /File not found/ }
    );
  });

  it('reports correct file path in results', () => {
    const results = scanFile(FIXTURE_PATH);
    assert.ok(results.length > 0);
    assert.equal(results[0].file, FIXTURE_PATH);
  });

  it('returns zero findings for clean code', () => {
    const results = scanFile(CLEAN_FIXTURE_PATH);
    assert.equal(results.length, 0, `expected 0 vulns in clean file, got ${results.length}`);
  });

  it('finds only real vulns in edge case file (no false positives from bait)', () => {
    const results = scanFile(EDGE_FIXTURE_PATH);
    assert.equal(results.length, 10, `expected 10 vulns in edge case file, got ${results.length}`);
    const vulnTypes = new Set(results.map(v => v.id));
    assert.ok(vulnTypes.has('HARDCODED_SECRET'));
    assert.ok(vulnTypes.has('SQL_INJECTION'));
    assert.ok(vulnTypes.has('INSECURE_FUNCTION'));
    assert.ok(vulnTypes.has('XSS'));
    assert.ok(vulnTypes.has('WEAK_CRYPTO'));
    assert.ok(vulnTypes.has('HARDCODED_IP'));
    assert.ok(vulnTypes.has('SENSITIVE_DATA_LOG'));
    assert.ok(vulnTypes.has('PATH_TRAVERSAL'));
    assert.ok(vulnTypes.has('SECURITY_TODO'));
    assert.ok(!vulnTypes.has('NOSQL_INJECTION'), 'should not detect NoSQL injection in edge case file');
    assert.ok(!vulnTypes.has('INSECURE_RANDOM'), 'should not detect insecure random in edge case file');
  });
});
