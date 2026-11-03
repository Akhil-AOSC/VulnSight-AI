#!/usr/bin/env node
'use strict';

const { initEnv } = require('../src/env');
initEnv();

const { main } = require('../src/cli');

main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
});
