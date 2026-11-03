'use strict';

const USER_INPUT = /\b(?:req\.(?:query|body|params|headers|cookies)|process\.argv)\b/;
const CONCAT = /\+|`[^`]*\$\{/;

function sourceText(context, node) {
  const sc = context.sourceCode || context.getSourceCode();
  return sc.getText(node);
}

function calleeName(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' && !node.computed && node.property && node.property.type === 'Identifier') {
    return `${calleeName(node.object)}.${node.property.name}`;
  }
  return '';
}

function rule(check) {
  return {
    meta: { type: 'problem', docs: { description: check.title }, schema: [] },
    create(context) {
      return {
        CallExpression(node) {
          const name = calleeName(node.callee);
          if (!check.match(name)) return;
          const slice = sourceText(context, node);
          if (!check.tainted(slice)) return;
          context.report({ node, message: check.title });
        },
      };
    },
  };
}

const rules = {
  'xss-res-send': rule({
    title: 'User input written into the HTTP response (XSS)',
    match: (name) => name === 'res.send' || name === 'res.write' || name === 'res.end',
    tainted: (slice) => USER_INPUT.test(slice),
  }),
  'detect-child-process': rule({
    title: 'User input concatenated into a shell command',
    match: (name) => /(?:^|\.)(?:exec|execSync|spawn|spawnSync)$/.test(name),
    tainted: (slice) => USER_INPUT.test(slice) && CONCAT.test(slice),
  }),
  'detect-eval-with-expression': rule({
    title: 'Dynamic eval() of untrusted input',
    match: (name) => name === 'eval',
    tainted: (slice) => USER_INPUT.test(slice),
  }),
};

const RULE_SETTINGS = {
  'vulnsight/xss-res-send': 'error',
  'vulnsight/detect-child-process': 'error',
  'vulnsight/detect-eval-with-expression': 'error',
};

module.exports = {
  meta: { name: 'eslint-plugin-vulnsight', version: '1.0.0' },
  rules,
  RULE_SETTINGS,
};
