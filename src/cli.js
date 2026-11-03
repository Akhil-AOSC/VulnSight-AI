import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import { runScan } from './scanner.js';
import { formatConsoleReport } from './reporter/console.js';
import { formatJsonReport } from './reporter/json.js';
import { formatMarkdownReport } from './reporter/markdown.js';

const VERSION = '0.1.0';

function printHelp() {
  console.log(`
${pc.cyan(pc.bold('vuln-scanner'))} ${pc.gray(`v${VERSION}`)}
A proof-of-concept dependency vulnerability scanner for npm using OSV.dev.

${pc.bold('USAGE:')}
  vuln-scanner [target-path] [options]

${pc.bold('ARGUMENTS:')}
  target-path               Directory containing package.json (default: current directory ".")

${pc.bold('OPTIONS:')}
  --fail-on <level>         Fail (exit code 1) if vulnerabilities meet/exceed this severity:
                            ${pc.yellow('critical')}, ${pc.yellow('high')}, ${pc.yellow('medium')}, ${pc.yellow('low')}, ${pc.yellow('none')} (default: ${pc.green('low')})
  --no-dev                  Exclude devDependencies from scan
  --format <format>         Output report format: ${pc.yellow('console')}, ${pc.yellow('json')}, ${pc.yellow('markdown')} (default: ${pc.green('console')})
  --output, -o <file>       Write report to the specified file path
  --timeout <ms>            OSV HTTP request timeout in milliseconds (default: 15000)
  --version, -v             Print version information and exit
  --help, -h                Show this help message

${pc.bold('EXAMPLES:')}
  vuln-scanner .
  vuln-scanner ./test-fixtures/vulnerable-npm-project
  vuln-scanner . --fail-on high --format json --output report.json
  vuln-scanner . --format markdown -o scan-summary.md
`);
}

export async function cli(args = process.argv.slice(2)) {
  let targetPath = '.';
  let failThreshold = 'low';
  let includeDev = true;
  let format = 'console';
  let outputFile = null;
  let timeoutMs = 15000;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      printHelp();
      return 0;
    }

    if (arg === '--version' || arg === '-v') {
      console.log(`vuln-scanner v${VERSION}`);
      return 0;
    }

    if (arg === '--no-dev') {
      includeDev = false;
      continue;
    }

    if (arg === '--fail-on') {
      failThreshold = (args[++i] || 'low').toLowerCase();
      continue;
    }

    if (arg.startsWith('--fail-on=')) {
      failThreshold = arg.split('=')[1].toLowerCase();
      continue;
    }

    if (arg === '--format') {
      format = (args[++i] || 'console').toLowerCase();
      continue;
    }

    if (arg.startsWith('--format=')) {
      format = arg.split('=')[1].toLowerCase();
      continue;
    }

    if (arg === '--output' || arg === '-o') {
      outputFile = args[++i];
      continue;
    }

    if (arg.startsWith('--output=')) {
      outputFile = arg.split('=')[1];
      continue;
    }

    if (arg === '--timeout') {
      timeoutMs = parseInt(args[++i], 10) || 15000;
      continue;
    }

    if (!arg.startsWith('-')) {
      targetPath = arg;
    }
  }

  try {
    const result = await runScan(targetPath, {
      includeDev,
      failThreshold,
      timeoutMs,
    });

    let outputString = '';
    switch (format) {
      case 'json':
        outputString = formatJsonReport(result);
        break;
      case 'markdown':
      case 'md':
        outputString = formatMarkdownReport(result);
        break;
      case 'console':
      default:
        outputString = formatConsoleReport(result);
        break;
    }

    if (outputFile) {
      const resolvedOut = path.resolve(outputFile);
      fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
      fs.writeFileSync(resolvedOut, outputString, 'utf8');
      console.log(pc.green(`✓ Scan report written to ${resolvedOut}`));
    }

    // Always print console report to stdout unless JSON was requested without output file
    if (!outputFile || format === 'console') {
      console.log(outputString);
    }

    return result.thresholdBreached ? 1 : 0;
  } catch (err) {
    console.error(pc.red(pc.bold(`\nError executing scan: ${err.message}`)));
    if (process.env.DEBUG) {
      console.error(err.stack);
    }
    return 2;
  }
}
