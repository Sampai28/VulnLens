import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanFile } from './scanner.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.join(__dirname, '..', 'tests', 'fixtures');
const FIXTURE_PATH = path.join(FIXTURE_DIR, 'test-vulnerable.js');
const GROUND_TRUTH_PATH = path.join(FIXTURE_DIR, 'ground-truth.json');

const C = {
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', bold: '\x1b[1m', dim: '\x1b[2m', reset: '\x1b[0m',
};

const groundTruth = JSON.parse(fs.readFileSync(GROUND_TRUTH_PATH, 'utf-8'));
const expected = groundTruth.expectedFindings;
const actual = scanFile(FIXTURE_PATH);

const key = (v) => `${v.id}|${v.line}|${v.description}`;

const expectedSet = new Map();
for (const e of expected) expectedSet.set(key(e), e);

const actualSet = new Map();
for (const a of actual) actualSet.set(key(a), a);

const truePositives = [];
const falseNegatives = [];
const falsePositives = [];

for (const [k, e] of expectedSet) {
  if (actualSet.has(k)) truePositives.push(e);
  else falseNegatives.push(e);
}

for (const [k, a] of actualSet) {
  if (!expectedSet.has(k)) falsePositives.push(a);
}

const precision = truePositives.length / (truePositives.length + falsePositives.length);
const recall = truePositives.length / (truePositives.length + falseNegatives.length);
const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

console.log();
console.log(`${C.bold}${'='.repeat(70)}${C.reset}`);
console.log(`${C.bold}  SAST Scanner — Ground Truth Comparison${C.reset}`);
console.log(`${C.bold}${'='.repeat(70)}${C.reset}`);
console.log();
console.log(`  Expected findings:  ${expected.length}`);
console.log(`  Actual findings:    ${actual.length}`);
console.log();
console.log(`  ${C.green}True Positives:   ${truePositives.length}${C.reset}  (correctly detected)`);
console.log(`  ${C.red}False Negatives:  ${falseNegatives.length}${C.reset}  (missed)`);
console.log(`  ${C.yellow}False Positives:  ${falsePositives.length}${C.reset}  (extra/unexpected)`);
console.log();
console.log(`${C.bold}  Metrics${C.reset}`);
console.log(`  ${'-'.repeat(40)}`);
console.log(`  Precision:  ${(precision * 100).toFixed(1)}%  (of what it found, how much was correct)`);
console.log(`  Recall:     ${(recall * 100).toFixed(1)}%  (of what exists, how much it found)`);
console.log(`  F1 Score:   ${(f1 * 100).toFixed(1)}%`);

if (falseNegatives.length > 0) {
  console.log();
  console.log(`${C.red}${C.bold}  Missed (False Negatives)${C.reset}`);
  for (const v of falseNegatives) {
    console.log(`    ${C.red}line ${String(v.line).padStart(4)}  ${v.id.padEnd(20)} ${v.description}${C.reset}`);
  }
}

if (falsePositives.length > 0) {
  console.log();
  console.log(`${C.yellow}${C.bold}  Extra (False Positives)${C.reset}`);
  for (const v of falsePositives) {
    console.log(`    ${C.yellow}line ${String(v.line).padStart(4)}  ${v.id.padEnd(20)} ${v.description}${C.reset}`);
  }
}

console.log();

// Per-type breakdown
console.log(`${C.bold}  Per-Type Breakdown${C.reset}`);
console.log(`  ${'-'.repeat(60)}`);
console.log(`  ${'Type'.padEnd(22)} ${'Expected'.padStart(8)} ${'Found'.padStart(8)} ${'Status'.padStart(10)}`);
console.log(`  ${'-'.repeat(60)}`);

const expectedByType = groundTruth.expectedSummary.byType;
const actualByType = {};
for (const a of actual) actualByType[a.id] = (actualByType[a.id] || 0) + 1;

const allTypes = new Set([...Object.keys(expectedByType), ...Object.keys(actualByType)]);
for (const type of [...allTypes].sort()) {
  const exp = expectedByType[type] || 0;
  const act = actualByType[type] || 0;
  let status;
  if (act === exp) status = `${C.green}  MATCH${C.reset}`;
  else if (act > exp) status = `${C.yellow} +${act - exp} extra${C.reset}`;
  else status = `${C.red} -${exp - act} missed${C.reset}`;
  console.log(`  ${type.padEnd(22)} ${String(exp).padStart(8)} ${String(act).padStart(8)} ${status}`);
}

console.log();
console.log(`${C.bold}${'='.repeat(70)}${C.reset}`);
console.log();

process.exit(falseNegatives.length + falsePositives.length > 0 ? 1 : 0);
