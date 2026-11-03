// Deliberately uses outdated packages so scans can show code-level context. Do not deploy.
const minimist = require('minimist');
const _ = require('lodash');

const args = minimist(process.argv.slice(2));
const merged = _.merge({}, JSON.parse(args.config || '{}'));
console.log(merged);
