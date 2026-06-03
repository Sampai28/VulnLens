import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanCode, scanFile } from '../src/scanner.js';
import { detectLanguage } from '../src/detect-language.js';
import { parseNotebook, mapLineToCell } from '../src/ipynb.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-vulnerable.js');
const CLEAN_FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-clean.js');
const EDGE_FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-edge-cases.js');
const PY_FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-vulnerable.py');
const PY_CLEAN_FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-clean.py');
const PY_EDGE_FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-edge-cases.py');

// ──────────────────────────────────────────────────────────────────────
// EXISTING JS TESTS (unchanged from before the refactor)
// ──────────────────────────────────────────────────────────────────────

describe('scanCode (JavaScript)', () => {
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

describe('scanFile (JavaScript)', () => {
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

// ──────────────────────────────────────────────────────────────────────
// NEW: PYTHON TESTS
// ──────────────────────────────────────────────────────────────────────

describe('scanCode (Python)', () => {
  it('detects hardcoded passwords in Python assignment', () => {
    const results = scanCode(`password = 'supersecret123'`, 'app.py');
    const match = results.find(v => v.id === 'HARDCODED_SECRET');
    assert.ok(match, 'should detect hardcoded password');
    assert.equal(match.severity, 'HIGH');
  });

  it('detects hardcoded secrets in dict literals', () => {
    const results = scanCode(`config = {'api_key': 'ABCDEFGHIJKLMNOP1234'}`, 'app.py');
    const match = results.find(v => v.id === 'HARDCODED_SECRET');
    assert.ok(match, 'should detect dict-literal secret');
  });

  it('detects SQL injection via f-string in execute()', () => {
    const results = scanCode(`cursor.execute(f"SELECT * FROM users WHERE id = {uid}")`, 'app.py');
    const match = results.find(v => v.id === 'SQL_INJECTION');
    assert.ok(match, 'should detect f-string SQL injection');
    assert.equal(match.severity, 'HIGH');
  });

  it('detects SQL injection via string concatenation', () => {
    const results = scanCode(`cursor.execute("SELECT * FROM users WHERE id = '" + uid + "'")`, 'app.py');
    const match = results.find(v => v.id === 'SQL_INJECTION');
    assert.ok(match, 'should detect concat SQL injection');
  });

  it('detects NoSQL injection with request.json in find_one()', () => {
    const results = scanCode(`users.find_one(request.json)`, 'app.py');
    const match = results.find(v => v.id === 'NOSQL_INJECTION');
    assert.ok(match, 'should detect Python NoSQL injection');
  });

  it('detects XSS via render_template_string', () => {
    const results = scanCode(`return render_template_string('<h1>' + name + '</h1>')`, 'app.py');
    const match = results.find(v => v.id === 'XSS');
    assert.ok(match, 'should detect render_template_string XSS');
  });

  it('detects XSS via Django mark_safe', () => {
    const results = scanCode(`return mark_safe(request.GET['bio'])`, 'app.py');
    const match = results.find(v => v.id === 'XSS');
    assert.ok(match, 'should detect mark_safe XSS');
  });

  it('detects path traversal via open(request.args[...])', () => {
    const results = scanCode(`open(request.args['file'])`, 'app.py');
    const match = results.find(v => v.id === 'PATH_TRAVERSAL');
    assert.ok(match, 'should detect open() path traversal');
  });

  it('detects insecure randomness via random.random()', () => {
    const results = scanCode(`token = random.random()`, 'app.py');
    const match = results.find(v => v.id === 'INSECURE_RANDOM');
    assert.ok(match, 'should detect random.random()');
    assert.equal(match.severity, 'MEDIUM');
  });

  it('detects sensitive data logging via print(password)', () => {
    const results = scanCode(`print('password', user_password)`, 'app.py');
    const match = results.find(v => v.id === 'SENSITIVE_DATA_LOG');
    assert.ok(match, 'should detect print(password)');
  });

  it('detects eval() in Python', () => {
    const results = scanCode(`result = eval(user_expr)`, 'app.py');
    const match = results.find(v => v.id === 'INSECURE_FUNCTION');
    assert.ok(match, 'should detect Python eval()');
    assert.equal(match.severity, 'HIGH');
  });

  it('detects os.system() command execution', () => {
    const results = scanCode(`os.system(user_cmd)`, 'app.py');
    const match = results.find(v => v.id === 'INSECURE_FUNCTION');
    assert.ok(match, 'should detect os.system()');
  });

  it('detects subprocess with shell=True', () => {
    const results = scanCode(`subprocess.run(cmd, shell=True)`, 'app.py');
    const match = results.find(v => v.id === 'INSECURE_FUNCTION');
    assert.ok(match, 'should detect shell=True');
  });

  it('detects pickle.loads (unsafe deserialization)', () => {
    const results = scanCode(`obj = pickle.loads(blob)`, 'app.py');
    const match = results.find(v => v.id === 'INSECURE_FUNCTION');
    assert.ok(match, 'should detect pickle.loads');
  });

  it('detects yaml.load without SafeLoader', () => {
    const results = scanCode(`data = yaml.load(stream)`, 'app.py');
    const match = results.find(v => v.id === 'INSECURE_FUNCTION');
    assert.ok(match, 'should detect yaml.load');
  });

  it('does not flag yaml.load WITH SafeLoader', () => {
    const results = scanCode(`data = yaml.load(stream, Loader=yaml.SafeLoader)`, 'app.py');
    const match = results.find(v => v.id === 'INSECURE_FUNCTION' && v.description.includes('yaml'));
    assert.ok(!match, 'safe yaml.load(Loader=SafeLoader) should not flag');
  });

  it('detects hashlib.md5 weak crypto', () => {
    const results = scanCode(`digest = hashlib.md5(data).hexdigest()`, 'app.py');
    const match = results.find(v => v.id === 'WEAK_CRYPTO');
    assert.ok(match, 'should detect hashlib.md5');
  });

  it('detects hashlib.sha1 weak crypto', () => {
    const results = scanCode(`digest = hashlib.sha1(data).hexdigest()`, 'app.py');
    const match = results.find(v => v.id === 'WEAK_CRYPTO');
    assert.ok(match, 'should detect hashlib.sha1');
  });

  it('detects hardcoded IP in Python string', () => {
    const results = scanCode(`db_host = '192.168.1.100'`, 'app.py');
    const match = results.find(v => v.id === 'HARDCODED_IP');
    assert.ok(match);
  });

  it('detects Python-style security TODO (# comment)', () => {
    const results = scanCode(`# TODO: security fix auth bypass`, 'app.py');
    const match = results.find(v => v.id === 'SECURITY_TODO');
    assert.ok(match, 'should detect # TODO security comment');
  });

  it('does not flag JS-style // comment as Python TODO', () => {
    const results = scanCode(`// TODO: security fix`, 'app.py');
    const match = results.find(v => v.id === 'SECURITY_TODO');
    assert.ok(!match, 'JS-style comment should not trigger in .py file');
  });

  it('does not apply JS rules to Python code', () => {
    // Math.random() is JS-only — should not flag in a .py file
    const results = scanCode(`token = Math.random()`, 'app.py');
    const match = results.find(v => v.id === 'INSECURE_RANDOM');
    assert.ok(!match, 'Math.random() should not flag as Python INSECURE_RANDOM');
  });

  it('does not apply Python rules to JS code', () => {
    // hashlib.md5 is Python-only — should not flag in a .js file
    const results = scanCode(`const x = hashlib.md5(data)`, 'app.js');
    const match = results.find(v => v.id === 'WEAK_CRYPTO');
    assert.ok(!match, 'hashlib.md5 should not flag as JS WEAK_CRYPTO');
  });
});

describe('scanFile (Python)', () => {
  it('scans test-vulnerable.py and finds all 11 vuln types', () => {
    const results = scanFile(PY_FIXTURE_PATH);
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

  it('finds at least 30 vulnerabilities in Python fixture', () => {
    const results = scanFile(PY_FIXTURE_PATH);
    assert.ok(results.length >= 30, `expected >= 30 vulns, got ${results.length}`);
  });

  it('returns zero findings for clean Python code', () => {
    const results = scanFile(PY_CLEAN_FIXTURE_PATH);
    assert.equal(results.length, 0, `expected 0 vulns in clean file, got ${results.length}`);
  });

  it('finds only real vulns in Python edge case file (no bait triggers)', () => {
    const results = scanFile(PY_EDGE_FIXTURE_PATH);
    assert.equal(results.length, 10, `expected 10 vulns, got ${results.length}`);
    const vulnTypes = new Set(results.map(v => v.id));
    assert.ok(!vulnTypes.has('NOSQL_INJECTION'), 'no NoSQL injection in edge case file');
    assert.ok(!vulnTypes.has('XSS'), 'no XSS in edge case file');
    assert.ok(!vulnTypes.has('INSECURE_RANDOM'), 'no insecure random in edge case file');
  });
});

// ──────────────────────────────────────────────────────────────────────
// NEW: JUPYTER NOTEBOOK TESTS
// ──────────────────────────────────────────────────────────────────────

describe('parseNotebook', () => {
  it('flattens code cells and skips markdown cells', () => {
    const nb = {
      cells: [
        { cell_type: 'markdown', source: ['# Title'] },
        { cell_type: 'code', source: ['x = 1\n', 'y = 2'] },
        { cell_type: 'markdown', source: ['## Section'] },
        { cell_type: 'code', source: ['z = 3'] },
      ],
    };
    const { source, cellOffsets } = parseNotebook(nb);
    assert.equal(cellOffsets.length, 2, 'should have 2 code cells');
    assert.equal(cellOffsets[0].cell, 1);
    assert.equal(cellOffsets[1].cell, 2);
    assert.ok(source.includes('x = 1'));
    assert.ok(source.includes('z = 3'));
  });

  it('handles source as a single string or array', () => {
    const nb1 = { cells: [{ cell_type: 'code', source: 'a = 1\nb = 2\n' }] };
    const nb2 = { cells: [{ cell_type: 'code', source: ['a = 1\n', 'b = 2\n'] }] };
    assert.equal(parseNotebook(nb1).source, parseNotebook(nb2).source);
  });

  it('throws on invalid notebook JSON', () => {
    assert.throws(() => parseNotebook('not json at all'), /Invalid .ipynb/);
  });

  it('throws on missing cells array', () => {
    assert.throws(() => parseNotebook('{"nbformat": 4}'), /missing cells array/);
  });
});

describe('mapLineToCell', () => {
  it('maps absolute lines to (cell, lineInCell)', () => {
    const offsets = [
      { cell: 1, startLine: 1, endLine: 3 },
      { cell: 2, startLine: 4, endLine: 5 },
    ];
    assert.deepEqual(mapLineToCell(1, offsets), { cell: 1, lineInCell: 1 });
    assert.deepEqual(mapLineToCell(3, offsets), { cell: 1, lineInCell: 3 });
    assert.deepEqual(mapLineToCell(4, offsets), { cell: 2, lineInCell: 1 });
    assert.deepEqual(mapLineToCell(5, offsets), { cell: 2, lineInCell: 2 });
  });

  it('returns null for out-of-range lines', () => {
    const offsets = [{ cell: 1, startLine: 1, endLine: 3 }];
    assert.equal(mapLineToCell(99, offsets), null);
  });
});

// Notebook tests use INLINE content rather than reading test-vulnerable.ipynb
// from disk. This keeps the tests robust against download/encoding/editor issues
// with .ipynb files (which can be flaky on Windows, in browsers, or when opened
// in editors that auto-format them). The .ipynb fixture still exists on disk
// for `just sast-scan sast/tests/fixtures/test-vulnerable.ipynb` demos.
describe('Jupyter notebook scanning', () => {
  const notebookContent = JSON.stringify({
    cells: [
      {
        cell_type: 'markdown',
        metadata: {},
        source: ['# Data Analysis Notebook\n', 'Markdown should be ignored.'],
      },
      {
        cell_type: 'code',
        execution_count: null,
        metadata: {},
        outputs: [],
        source: [
          'import hashlib\n',
          'import random\n',
          '\n',
          '# Cell 1: hardcoded credentials\n',
          "password = 'admin1234'\n",
          "api_key = 'ABCDEFGHIJKLMNOP'",
        ],
      },
      {
        cell_type: 'markdown',
        metadata: {},
        source: ['## Section 2'],
      },
      {
        cell_type: 'code',
        execution_count: null,
        metadata: {},
        outputs: [],
        source: [
          '# Cell 2: weak crypto and insecure random\n',
          'digest = hashlib.md5(password.encode()).hexdigest()\n',
          'token = random.random()',
        ],
      },
      {
        cell_type: 'code',
        execution_count: null,
        metadata: {},
        outputs: [],
        source: [
          '# Cell 3: SQL injection and eval\n',
          'def query(cursor, name):\n',
          '    return cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n',
          '\n',
          "user_input = ''  # stub for fixture; this file is a pattern target, not executable\n",
          'result = eval(user_input)',
        ],
      },
    ],
    metadata: {
      kernelspec: { display_name: 'Python 3', language: 'python', name: 'python3' },
    },
    nbformat: 4,
    nbformat_minor: 5,
  });

  it('produces findings with cell + line fields', () => {
    const results = scanCode(notebookContent, 'test.ipynb');
    assert.ok(results.length > 0, 'should produce findings');
    for (const f of results) {
      assert.ok(typeof f.cell === 'number', `every finding should have a cell number: ${JSON.stringify(f)}`);
      assert.ok(f.line >= 1, 'line should be 1-indexed within the cell');
    }
  });

  it('finds expected vulnerabilities across cells', () => {
    const results = scanCode(notebookContent, 'test.ipynb');
    const vulnTypes = new Set(results.map(v => v.id));
    assert.ok(vulnTypes.has('HARDCODED_SECRET'));
    assert.ok(vulnTypes.has('SQL_INJECTION'));
    assert.ok(vulnTypes.has('INSECURE_FUNCTION'));
    assert.ok(vulnTypes.has('WEAK_CRYPTO'));
    assert.ok(vulnTypes.has('INSECURE_RANDOM'));
  });

  it('cell numbering counts only code cells (markdown is skipped)', () => {
    const results = scanCode(notebookContent, 'test.ipynb');
    const cells = new Set(results.map(v => v.cell));
    // 3 code cells in fixture → findings should reference cells in [1, 2, 3] only
    for (const c of cells) {
      assert.ok(c >= 1 && c <= 3, `cell number ${c} out of expected range 1-3`);
    }
  });
});

// ──────────────────────────────────────────────────────────────────────
// LANGUAGE DETECTION
// ──────────────────────────────────────────────────────────────────────

describe('detectLanguage', () => {
  it('identifies JavaScript variants', () => {
    assert.equal(detectLanguage('app.js'), 'js');
    assert.equal(detectLanguage('app.mjs'), 'js');
    assert.equal(detectLanguage('app.cjs'), 'js');
    assert.equal(detectLanguage('app.ts'), 'js');
    assert.equal(detectLanguage('Component.jsx'), 'js');
    assert.equal(detectLanguage('Component.tsx'), 'js');
  });

  it('identifies Python', () => {
    assert.equal(detectLanguage('app.py'), 'python');
    assert.equal(detectLanguage('/path/to/script.py'), 'python');
  });

  it('identifies Jupyter notebooks', () => {
    assert.equal(detectLanguage('notebook.ipynb'), 'ipynb');
  });

  it('returns "unknown" for unsupported extensions', () => {
    assert.equal(detectLanguage('README.md'), 'unknown');
    assert.equal(detectLanguage('config.yaml'), 'unknown');
    assert.equal(detectLanguage('noext'), 'unknown');
  });

  it('is case-insensitive', () => {
    assert.equal(detectLanguage('App.PY'), 'python');
    assert.equal(detectLanguage('NOTEBOOK.IPYNB'), 'ipynb');
  });
});