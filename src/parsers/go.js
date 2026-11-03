'use strict';

const fs = require('fs');
const path = require('path');

const ECOSYSTEM = 'Go';

// go.sum lists every module version the build verified. Each module appears twice
// (the module zip and "/go.mod"); only the first is a real dependency line. go.sum has no
// graph, so direct/transitive is unknown. OSV expects Go versions without the "v" prefix.
function parseGoSum(text, { projectLabel = 'project' } = {}) {
  const byKey = new Map();
  for (const line of text.split(/\r?\n/)) {
    const [mod, version] = line.trim().split(/\s+/);
    if (!mod || !version || version.endsWith('/go.mod')) continue;
    const clean = version.replace(/^v/, '').replace(/\+incompatible$/, '');
    const key = `${mod}@${clean}`;
    if (!byKey.has(key)) {
      byKey.set(key, { name: mod, version: clean, ecosystem: ECOSYSTEM, direct: null, paths: [[projectLabel, key]] });
    }
  }
  return { name: projectLabel, dependencies: [...byKey.values()], skipped: [] };
}

function loadGoSum(filePath) {
  const label = path.basename(path.dirname(path.resolve(filePath)));
  return parseGoSum(fs.readFileSync(filePath, 'utf8'), { projectLabel: label });
}

module.exports = { parseGoSum, loadGoSum, ECOSYSTEM };
