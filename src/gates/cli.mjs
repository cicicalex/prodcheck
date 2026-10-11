#!/usr/bin/env node
/**
 * prodcheck gates — CLI entrypoint for the gate of gates.
 *
 *   node src/gates/cli.mjs [config] [--json] [--timeout <ms>] [--no-color] [-h]
 *
 * Proves that each configured check can fail: it must pass on a copy of the
 * unmodified tree, and must fail on a copy broken by each of its breakers.
 * See the "Gate of gates" section of the README for the config format.
 *
 * Exit contract (same shape as src/cli.mjs):
 *   0 — every check can fail, and the original tree is byte-identical after the run
 *   1 — at least one CANNOT FAIL, BROKEN BASELINE, TIMEOUT or BREAKER ERROR,
 *       or the original tree changed
 *   2 — the run itself failed (bad config, bad flag, crash)
 */

import { readFileSync } from 'node:fs';

const DEFAULT_CONFIG = 'gates.json';

const HELP = `prodcheck gates — proves each check can fail

usage
  node src/gates/cli.mjs [config] [options]

examples
  node src/gates/cli.mjs                     run ./gates.json
  node src/gates/cli.mjs ci/gates.json       another config
  node src/gates/cli.mjs --json              machine-readable, for CI

options
  --json            print a JSON document instead of the report
  --timeout <ms>    per-step timeout, overrides the config's timeoutMs
  --no-color        plain text output
  -h, --help        this screen

exit codes
  0  every check passes unmodified and fails under every breaker
  1  CANNOT FAIL, BROKEN BASELINE, TIMEOUT, BREAKER ERROR, or tree changed
  2  bad config, bad flag, or crash
`;

function parseArgs(argv) {
  const opts = { config: DEFAULT_CONFIG, json: false, noColor: false, help: false, timeoutMs: undefined };
  const positionals = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') opts.json = true;
    else if (arg === '--no-color') opts.noColor = true;
    else if (arg === '-h' || arg === '--help') opts.help = true;
    else if (arg === '--timeout' || arg.startsWith('--timeout=')) {
      const value = arg === '--timeout' ? argv[++i] : arg.slice('--timeout='.length);
      const n = Number(value);
      if (!Number.isInteger(n) || n <= 0) throw new Error('--timeout expects a positive integer (milliseconds)');
      opts.timeoutMs = n;
    } else if (arg.startsWith('-')) {
      throw new Error(`unknown option: ${arg} (try --help)`);
    } else positionals.push(arg);
  }
  if (positionals.length > 1) throw new Error(`expected at most one config, got ${positionals.length}`);
  if (positionals.length === 1) opts.config = positionals[0];
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.noColor) process.env.NO_COLOR = '1';
  if (opts.help) {
    process.stdout.write(HELP);
    return;
  }

  const engine = await import('./engine.mjs');
  const config = engine.loadConfig(opts.config);
  if (opts.timeoutMs) for (const c of config.checks) c.timeoutMs = opts.timeoutMs;

  const startedAt = new Date().toISOString();
  const onProgress =
    !opts.json && process.stderr.isTTY
      ? ({ check, step }) => process.stderr.write(`\r\x1b[2K  running ${check}: ${step}`)
      : undefined;
  const result = await engine.runGates(config, { onProgress });
  if (onProgress) process.stderr.write('\r\x1b[2K');

  const report = await import('./report.mjs');
  if (opts.json) {
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
    process.stdout.write(report.renderJson(result, { version: pkg.version, config: opts.config, startedAt }));
  } else {
    process.stdout.write(report.renderReport(result));
  }
  process.exitCode = engine.exitCode(result);
}

main().catch((err) => {
  process.stderr.write(`prodcheck gates: ${err?.message ?? err}\n`);
  process.exit(2);
});
