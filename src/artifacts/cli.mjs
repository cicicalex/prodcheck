/**
 * `prodcheck artifacts` — the artifact scanner's command line.
 *
 *   prodcheck artifacts <artifact|dir>... [--deny-terms <file>] [--allow <file>]
 *                       [--max-depth <n>] [--max-inflate-mb <n>] [--allow-gaps]
 *                       [--json] [--no-color] [-h]
 *
 * Same structural rule as src/cli.mjs: arguments first, `--no-color` into the
 * environment, and only then the dynamic import of anything under src/ui.
 *
 * Exit contract:
 *   0 — every byte was read and nothing was found
 *   1 — findings (after the allow-list)
 *   2 — the scan itself failed (bad flag, unreadable artifact or list, crash)
 *   3 — nothing found, but something could not be read (a gap); --allow-gaps
 *       turns this into 0. Not clean is not the same as dirty, and neither is
 *       the same as "the tool broke", so it gets its own code.
 */

import { existsSync } from 'node:fs';
import { DEFAULTS, scanArtifacts } from './scan.mjs';
import { applyAllowList, loadAllowList, loadDenyTerms } from './lists.mjs';
import { denyRules } from './rules.mjs';

function intArg(flag, value, min) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min) throw new Error(`${flag} expects an integer >= ${min}`);
  return n;
}

export function parseArtifactArgs(argv) {
  const opts = {
    inputs: [],
    denyTerms: null,
    allow: null,
    maxDepth: DEFAULTS.maxDepth,
    maxInflateMb: DEFAULTS.maxInflate / 1024 / 1024,
    allowGaps: false,
    json: false,
    noColor: false,
    help: false,
  };
  const withValue = new Set(['--deny-terms', '--allow', '--max-depth', '--max-inflate-mb']);
  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i];
    let value;
    const eq = arg.indexOf('=');
    if (arg.startsWith('--') && eq !== -1 && withValue.has(arg.slice(0, eq))) {
      value = arg.slice(eq + 1);
      arg = arg.slice(0, eq);
    } else if (withValue.has(arg)) {
      value = argv[++i];
      if (value === undefined) throw new Error(`${arg} expects a value`);
    }
    if (arg === '--json') opts.json = true;
    else if (arg === '--no-color') opts.noColor = true;
    else if (arg === '--allow-gaps') opts.allowGaps = true;
    else if (arg === '-h' || arg === '--help') opts.help = true;
    else if (arg === '--deny-terms') opts.denyTerms = value;
    else if (arg === '--allow') opts.allow = value;
    else if (arg === '--max-depth') opts.maxDepth = intArg(arg, value, 0);
    else if (arg === '--max-inflate-mb') opts.maxInflateMb = intArg(arg, value, 1);
    else if (arg.startsWith('-') && arg !== '-') throw new Error(`unknown option: ${arg} (try artifacts --help)`);
    else opts.inputs.push(arg);
  }
  return opts;
}

export async function runArtifacts(argv, pkg) {
  const opts = parseArtifactArgs(argv);
  if (opts.noColor) process.env.NO_COLOR = '1';

  if (opts.help) {
    const { renderArtifactsHelp } = await import('../ui/artifacts.mjs');
    process.stdout.write(renderArtifactsHelp(pkg.version));
    return 0;
  }
  if (!opts.inputs.length) throw new Error('artifacts: expected at least one artifact or directory (try artifacts --help)');
  for (const input of opts.inputs) {
    if (!existsSync(input)) throw new Error(`cannot read path: ${input}`);
  }

  const deny = opts.denyTerms ? loadDenyTerms(opts.denyTerms) : [];
  const allow = opts.allow ? loadAllowList(opts.allow) : [];

  const startedAt = new Date().toISOString();
  const raw = scanArtifacts(opts.inputs, {
    maxDepth: opts.maxDepth,
    maxInflate: opts.maxInflateMb * 1024 * 1024,
    deny: denyRules(deny),
  });
  const { findings, allowed } = applyAllowList(raw.findings, allow);
  const result = {
    findings,
    allowed: allowed.length,
    gaps: raw.gaps,
    stats: raw.stats,
    denyTerms: deny.length,
    unusedAllow: allow.filter((a) => !a.used).map((a) => a.line),
  };

  const ui = await import('../ui/artifacts.mjs');
  process.stdout.write(
    opts.json
      ? ui.renderArtifactsJson(result, { version: pkg.version, inputs: opts.inputs, startedAt, maxDepth: opts.maxDepth })
      : ui.renderArtifactsReport(result)
  );
  return artifactsExitCode(result, opts.allowGaps);
}

export function artifactsExitCode(result, allowGaps = false) {
  if (result.findings.length) return 1;
  if (result.gaps.length && !allowGaps) return 3;
  return 0;
}
