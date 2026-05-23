import { scanFile, scanDirectory } from './scanner.js';
import path from 'node:path';

const COLORS = {
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  green: '\x1b[32m',
  gray: '\x1b[90m',
  white: '\x1b[37m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  reset: '\x1b[0m',
};

const SEVERITY_STYLE = {
  HIGH: { color: COLORS.red, icon: '!!' },
  MEDIUM: { color: COLORS.yellow, icon: ' !' },
  LOW: { color: COLORS.blue, icon: ' i' },
};

function severityBadge(severity) {
  const s = SEVERITY_STYLE[severity] || SEVERITY_STYLE.LOW;
  return `${s.color}${COLORS.bold}[${s.icon}] ${severity.padEnd(6)}${COLORS.reset}`;
}

function printReport(results, filePath) {
  const high = results.filter(v => v.severity === 'HIGH');
  const medium = results.filter(v => v.severity === 'MEDIUM');
  const low = results.filter(v => v.severity === 'LOW');

  console.log();
  console.log(`${COLORS.bold}${'='.repeat(70)}${COLORS.reset}`);
  console.log(`${COLORS.bold}  SAST Scan Report${COLORS.reset}`);
  console.log(`${COLORS.bold}${'='.repeat(70)}${COLORS.reset}`);
  console.log();
  console.log(`  File:    ${COLORS.white}${filePath}${COLORS.reset}`);
  console.log(`  Date:    ${new Date().toLocaleString()}`);
  console.log();
  console.log(`${COLORS.bold}  Summary${COLORS.reset}`);
  console.log(`  ${'-'.repeat(40)}`);
  console.log(`  Total findings:  ${COLORS.bold}${results.length}${COLORS.reset}`);
  console.log(`  ${COLORS.red}HIGH:   ${high.length}${COLORS.reset}   ${COLORS.yellow}MEDIUM: ${medium.length}${COLORS.reset}   ${COLORS.blue}LOW:    ${low.length}${COLORS.reset}`);
  console.log();

  if (results.length === 0) {
    console.log(`  ${COLORS.green}No vulnerabilities found.${COLORS.reset}`);
    console.log();
    return;
  }

  const grouped = {};
  for (const v of results) {
    if (!grouped[v.id]) grouped[v.id] = [];
    grouped[v.id].push(v);
  }

  for (const [id, findings] of Object.entries(grouped)) {
    const first = findings[0];
    console.log(`${severityBadge(first.severity)}  ${COLORS.bold}${first.name}${COLORS.reset} ${COLORS.dim}(${id})${COLORS.reset}`);
    console.log(`${COLORS.gray}  ${first.message}${COLORS.reset}`);
    console.log();

    for (const f of findings) {
      const loc = `${COLORS.dim}line ${String(f.line).padStart(4)}:${String(f.column).padStart(3)}${COLORS.reset}`;
      console.log(`    ${loc}  ${f.description}`);
      console.log(`    ${COLORS.gray}         ${f.evidence}${COLORS.reset}`);
    }
    console.log();
  }

  console.log(`${COLORS.bold}${'='.repeat(70)}${COLORS.reset}`);
  console.log();
}

function printDirectoryReport(results) {
  const files = Object.keys(results);
  const allVulns = Object.values(results).flat();

  console.log();
  console.log(`${COLORS.bold}${'='.repeat(70)}${COLORS.reset}`);
  console.log(`${COLORS.bold}  SAST Directory Scan Report${COLORS.reset}`);
  console.log(`${COLORS.bold}${'='.repeat(70)}${COLORS.reset}`);
  console.log();
  console.log(`  Files with findings: ${files.length}`);
  console.log(`  Total findings:      ${allVulns.length}`);
  console.log();

  for (const [file, vulns] of Object.entries(results)) {
    printReport(vulns, file);
  }
}

const target = process.argv[2];

if (!target) {
  console.log(`
  Usage:
    node src/cli.js <file>          Scan a single file
    node src/cli.js <directory>     Scan a directory

  Examples:
    node src/cli.js tests/fixtures/test-vulnerable.js
    node src/cli.js ../frontend/src
  `);
  process.exit(1);
}

const resolved = path.resolve(target);

try {
  const stat = (await import('node:fs')).default.statSync(resolved);

  if (stat.isDirectory()) {
    const results = scanDirectory(resolved);
    printDirectoryReport(results);
  } else {
    const results = scanFile(resolved);
    printReport(results, resolved);
  }
} catch (err) {
  console.error(`${COLORS.red}Error: ${err.message}${COLORS.reset}`);
  process.exit(1);
}
