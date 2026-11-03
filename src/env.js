'use strict';

const fs = require('fs');
const path = require('path');

function parseEnvString(content) {
  const result = {};
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let val = trimmed.slice(eqIdx + 1).trim();
    // Remove wrapping quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    result[key] = val;
  }
  return result;
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return {};
  try {
    const parsed = parseEnvString(fs.readFileSync(filePath, 'utf8'));
    for (const [key, val] of Object.entries(parsed)) {
      if (process.env[key] === undefined) {
        process.env[key] = val;
      }
    }
    return parsed;
  } catch {
    return {};
  }
}

function initEnv(rootDir = path.resolve(__dirname, '..')) {
  // .env.local takes precedence over .env (matches Next.js/Vite standard)
  const localEnv = loadEnvFile(path.join(rootDir, '.env.local'));
  const baseEnv = loadEnvFile(path.join(rootDir, '.env'));
  return { ...baseEnv, ...localEnv };
}

module.exports = { initEnv, loadEnvFile, parseEnvString };

