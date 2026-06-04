import path from 'node:path';

// Map of file extensions to scanner language.
// 'js' covers JavaScript and TypeScript (same regex-based detection works for both).
// 'python' covers .py files.
// 'ipynb' is a special case — Jupyter notebook JSON containing Python code cells.
const EXTENSION_MAP = {
    '.js': 'js',
    '.mjs': 'js',
    '.cjs': 'js',
    '.jsx': 'js',
    '.ts': 'js',
    '.tsx': 'js',
    '.py': 'python',
    '.ipynb': 'ipynb',
};

export const detectLanguage = (filename) => {
    const ext = path.extname(filename).toLowerCase();
    return EXTENSION_MAP[ext] || 'unknown';
};

export const SUPPORTED_EXTENSIONS = Object.keys(EXTENSION_MAP);