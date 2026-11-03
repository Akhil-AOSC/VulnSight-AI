#!/usr/bin/env node
import { cli } from '../src/cli.js';

cli()
  .then((exitCode) => {
    process.exit(exitCode);
  })
  .catch((err) => {
    console.error('Fatal scanner error:', err);
    process.exit(2);
  });
