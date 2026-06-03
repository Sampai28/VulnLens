// Parse a Jupyter notebook (.ipynb) into flattened Python source plus a
// cell offset map. The map lets us translate an absolute line in the
// flattened source back to (cell, lineInCell) when reporting findings.
//
// .ipynb files are JSON. We only care about cells where cell_type === 'code'.
// Each cell's `source` field is either a string or an array of strings.

export const parseNotebook = (raw) => {
    let notebook;
    try {
        notebook = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch (err) {
        throw new Error(`Invalid .ipynb file: ${err.message}`);
    }

    if (!notebook || !Array.isArray(notebook.cells)) {
        throw new Error('Invalid .ipynb structure: missing cells array');
    }

    const sourceParts = [];
    const cellOffsets = [];
    let codeCellNumber = 0;
    let currentLine = 1;

    for (const cell of notebook.cells) {
        if (cell.cell_type !== 'code') continue;
        codeCellNumber += 1;

        let cellSource = Array.isArray(cell.source)
            ? cell.source.join('')
            : (cell.source || '');

        // Ensure each cell ends with exactly one newline so cells stay cleanly
        // separated in the flattened source. This makes the line-counting math
        // predictable: lines-in-cell == newline count in the normalized source.
        if (!cellSource.endsWith('\n')) cellSource += '\n';

        const newlineCount = (cellSource.match(/\n/g) || []).length;

        cellOffsets.push({
            cell: codeCellNumber,
            startLine: currentLine,
            endLine: currentLine + newlineCount - 1,
        });

        sourceParts.push(cellSource);
        currentLine += newlineCount;
    }

    return {
        source: sourceParts.join(''),
        cellOffsets,
    };
};

// Translate an absolute line number in the flattened source to (cell, line).
// Returns null if the line falls outside any code cell (shouldn't happen in
// practice but guards against off-by-one bugs).
export const mapLineToCell = (absoluteLine, cellOffsets) => {
    for (const offset of cellOffsets) {
        if (absoluteLine >= offset.startLine && absoluteLine <= offset.endLine) {
            return {
                cell: offset.cell,
                lineInCell: absoluteLine - offset.startLine + 1,
            };
        }
    }
    return null;
};