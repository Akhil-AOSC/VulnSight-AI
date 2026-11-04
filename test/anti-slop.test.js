'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function walkFiles(dir, exts) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '.git') {
        results.push(...walkFiles(full, exts));
      }
    } else if (exts.some((e) => entry.name.endsWith(e))) {
      results.push(full);
    }
  }
  return results;
}

test('Anti-Slop Hard Gate: No em dashes in frontend views or AI assistant prompts', () => {
  const files = [
    ...walkFiles(path.join(ROOT, 'web', 'src', 'views'), ['.jsx']),
    path.join(ROOT, 'src', 'ai', 'assistant.js'),
  ];

  const violations = [];
  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      // Ignore comment lines
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return;
      if (line.includes('—')) {
        violations.push(`${path.relative(ROOT, file)}:${idx + 1}: contains banned em dash: ${trimmed}`);
      }
    });
  }

  assert.deepEqual(violations, [], `Found em dashes violating Anti-Slop Hard Gate HG-02:\n${violations.join('\n')}`);
});

test('Anti-Slop Hard Gate: No banned marketing buzzwords in frontend views', () => {
  const BANNED_BUZZWORDS = [
    'supercharge',
    'seamlessly',
    'revolutionize',
    'game-changing',
    'unlock the power',
    'elevate your',
  ];

  const files = walkFiles(path.join(ROOT, 'web', 'src', 'views'), ['.jsx']);
  const violations = [];

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8').toLowerCase();
    for (const word of BANNED_BUZZWORDS) {
      if (content.includes(word)) {
        violations.push(`${path.relative(ROOT, file)} contains banned marketing buzzword: "${word}"`);
      }
    }
  }

  assert.deepEqual(violations, [], `Found marketing buzzwords violating Anti-Slop Hard Gate HG-02:\n${violations.join('\n')}`);
});

test('Anti-Slop Visual Quality Gate: No decorative gradients or frosted glass on cards', () => {
  const stylesPath = path.join(ROOT, 'web', 'styles.css');
  assert.ok(fs.existsSync(stylesPath), 'styles.css must exist');
  const styles = fs.readFileSync(stylesPath, 'utf8');

  // Verify no linear-gradient or backdrop-filter on cards
  const hasCardGradients = /\.card\s*\{[^}]*linear-gradient/i.test(styles);
  assert.equal(hasCardGradients, false, 'Cards must not have linear-gradient backgrounds');

  const hasBlurGlass = /backdrop-filter:\s*blur/i.test(styles);
  assert.equal(hasBlurGlass, false, 'Styles must not use blurred glassmorphism');
});

test('Anti-Slop Rulebook: .antigravity/rules/anti-slop.md exists and contains 3 tiers', () => {
  const rulePath = path.join(ROOT, '.antigravity', 'rules', 'anti-slop.md');
  assert.ok(fs.existsSync(rulePath), '.antigravity/rules/anti-slop.md must exist');
  const ruleContent = fs.readFileSync(rulePath, 'utf8');
  assert.ok(ruleContent.includes('Tier 1: Hard Gates'));
  assert.ok(ruleContent.includes('Tier 2: Purpose Gates'));
  assert.ok(ruleContent.includes('Tier 3: Quality Locks'));
  assert.ok(ruleContent.includes('Delivery Gate Verification Checklist'));
});
