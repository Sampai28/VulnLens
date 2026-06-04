import fs from 'node:fs';
import path from 'node:path';
import { jsRules } from './rules-js.js';
import { pythonRules } from './rules-python.js';
import { detectLanguage, SUPPORTED_EXTENSIONS } from './detect-language.js';
import { parseNotebook, mapLineToCell } from './ipynb.js';

const RULES_BY_LANGUAGE = {
  js: jsRules,
  python: pythonRules,
};

const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2 };

// 1-indexed line number for a character offset
const getLineNumber = (code, index) =>
  code.substring(0, index).split('\n').length;

// Trimmed text of a given 1-indexed line
const getLineContent = (code, lineNumber) => {
  const lines = code.split('\n');
  return lines[lineNumber - 1]?.trim() || '';
};

// Run a rule set against a code string. Returns raw findings with absolute
// line numbers in `code`. If cellOffsets is provided (only for .ipynb), each
// finding additionally gets { cell, line } translated to within-cell coords.
const runRules = (code, filename, rules, cellOffsets = null) => {
  const findings = [];

  for (const rule of rules) {
    for (const pattern of rule.patterns) {
      // Fresh regex per scan to reset lastIndex (regex objects are stateful with /g)
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;

      while ((match = regex.exec(code)) !== null) {
        const absoluteLine = getLineNumber(code, match.index);
        const lineContent = getLineContent(code, absoluteLine);
        const column = match.index - code.lastIndexOf('\n', match.index - 1);

        const finding = {
          id: rule.id,
          name: rule.name,
          severity: rule.severity,
          description: pattern.desc,
          message: rule.message,
          file: filename,
          line: absoluteLine,
          column,
          evidence:
            lineContent.length > 100
              ? lineContent.substring(0, 100) + '...'
              : lineContent,
        };

        // For notebooks, translate absolute line → cell + line within cell.
        // We overwrite `line` with the in-cell value and add a `cell` field;
        // this keeps simple findings consumers (line-only) working while
        // giving cell-aware consumers the extra context.
        if (cellOffsets) {
          const mapping = mapLineToCell(absoluteLine, cellOffsets);
          if (mapping) {
            finding.cell = mapping.cell;
            finding.line = mapping.lineInCell;
          }
        }

        findings.push(finding);
      }
    }
  }

  return findings;
};

// Stable sort: severity first, then cell (if present), then line.
const sortFindings = (findings) => {
  findings.sort((a, b) => {
    if (SEVERITY_ORDER[a.severity] !== SEVERITY_ORDER[b.severity]) {
      return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    }
    const aCell = a.cell || 0;
    const bCell = b.cell || 0;
    if (aCell !== bCell) return aCell - bCell;
    return a.line - b.line;
  });
  return findings;
};

// Scan a code string. Language is inferred from `filename` extension.
// - .js/.ts/.mjs/etc → JS rules
// - .py → Python rules
// - .ipynb → parse notebook JSON, run Python rules with cell offset mapping
// - anything else → empty result (unknown language)
export const scanCode = (code, filename = 'untitled.js') => {
  const language = detectLanguage(filename);

  if (language === 'ipynb') {
    const { source, cellOffsets } = parseNotebook(code);
    return sortFindings(runRules(source, filename, pythonRules, cellOffsets));
  }

  const rules = RULES_BY_LANGUAGE[language];
  if (!rules) return [];

  return sortFindings(runRules(code, filename, rules));
};

// Scan a file from disk.
export const scanFile = (filepath) => {
  if (!fs.existsSync(filepath)) {
    throw new Error(`File not found: ${filepath}`);
  }
  const code = fs.readFileSync(filepath, 'utf-8');
  return scanCode(code, filepath);
};

// Recursively scan a directory. Default extension list now includes .py and .ipynb.
export const scanDirectory = (
  dirpath,
  extensions = SUPPORTED_EXTENSIONS,
) => {
  if (!fs.existsSync(dirpath)) {
    throw new Error(`Directory not found: ${dirpath}`);
  }

  const results = {};

  const walk = (currentPath) => {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      if (entry.isDirectory()) {
        // Skip node_modules, Python cache dirs, virtualenvs, hidden dirs
        if (
          entry.name === 'node_modules' ||
          entry.name === '__pycache__' ||
          entry.name === '.venv' ||
          entry.name === 'venv' ||
          entry.name.startsWith('.')
        ) {
          continue;
        }
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extensions.includes(ext)) {
          const findings = scanFile(fullPath);
          if (findings.length > 0) results[fullPath] = findings;
        }
      }
    }
  };

  walk(dirpath);
  return results;
};

export default { scanCode, scanFile, scanDirectory };