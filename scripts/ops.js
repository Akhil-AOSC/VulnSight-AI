#!/usr/bin/env node
'use strict';

// Operations CLI. Examples:
//   node scripts/ops.js backup  <db> <backup-file>
//   node scripts/ops.js verify  <backup-file>
//   node scripts/ops.js restore <backup-file> <db>        (the old db is kept aside, never deleted)
//   node scripts/ops.js rotate-key <db>                   (reads OLD_KEY and NEW_KEY from the environment)
//   node scripts/ops.js disable-user <db> <email>
//   node scripts/ops.js revoke-sessions <db>
//   node scripts/ops.js new-key                           (prints a fresh master key)
const ops = require('../src/platform/ops');
const { generateMasterKey } = require('../src/platform/crypto');

const [cmd, a, b] = process.argv.slice(2);
const usage = () => { console.error(require('fs').readFileSync(__filename, 'utf8').split('\n').slice(3, 11).join('\n').replace(/^\/\/ ?/gm, '')); process.exit(2); };

try {
  switch (cmd) {
    case 'backup': if (!a || !b) usage(); console.log(JSON.stringify(ops.backup(a, b))); break;
    case 'verify': if (!a) usage(); console.log(JSON.stringify(ops.verify(a))); break;
    case 'restore': if (!a || !b) usage(); console.log(JSON.stringify(ops.restore(a, b))); break;
    case 'rotate-key':
      if (!a || !process.env.OLD_KEY || !process.env.NEW_KEY) usage();
      console.log(JSON.stringify(ops.rotateMasterKey(a, process.env.OLD_KEY, process.env.NEW_KEY)));
      break;
    case 'disable-user': if (!a || !b) usage(); console.log(JSON.stringify(ops.disableUser(a, b))); break;
    case 'revoke-sessions': if (!a) usage(); console.log(JSON.stringify(ops.revokeAllSessions(a))); break;
    case 'new-key': console.log(generateMasterKey()); break;
    default: usage();
  }
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}
