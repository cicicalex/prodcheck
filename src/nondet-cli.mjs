#!/usr/bin/env node
/**
 * prodcheck-nondet — runs a command several times under perturbed
 * environments and fails when the runs disagree.
 *
 *   prodcheck-nondet [options] -- <command> [args...]
 *
 * Same structural rule as cli.mjs: `--no-color` must land in the environment
 * before theme.mjs is imported, so the ui import is dynamic and comes after
 * argument parsing.
 *
 * Exit contract:
 *   0 — every run agreed with the baseline
 *   1 — at least one run differed (nondeterminism found)
 *   2 — verification incomplete or failed: a run timed out, the command did
 *       not start, or a bad flag
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { DEFAULT_RUNS, DEFAULT_TIMEOUT_MS, detect, exitCodeFor } from './nondet/detect.mjs';

const HELP = `prodcheck-nondet — run a command N times under perturbed environments and
fail when the runs disagree. One green run proves one outcome, not the outcome.

usage
  prodcheck-nondet [options] -- <command> [args...]

examples
  prodcheck-nondet -- python3 pick_category.py input.json
  prodcheck-nondet --output out/report.csv --vary-tz -- python3 build_report.py
  prodcheck-nondet --normalize '\\d{4}-\\d\\d-\\d\\dT[\\d:.]+' -- python3 job.py
  prodcheck-nondet --vary-env WORKERS=1,4,16 --json -- ./run.sh

options
  --runs <n>              total runs, >= 2 ${`[default: ${DEFAULT_RUNS}]`}
                          run 0 baseline (PYTHONHASHSEED=0), run 1 identical
                          control, runs 2+ perturbed (PYTHONHASHSEED=random,
                          then generated integers)
  --timeout <seconds>     per-run timeout ${`[default: ${DEFAULT_TIMEOUT_MS / 1000}]`}
  --output <path>         file or directory the command writes, relative to
                          --workdir; compared by content (repeatable)
  --normalize <regex>     JavaScript regex; matches in stdout, stderr and text
                          outputs are replaced before comparing (repeatable)
  --vary-tz               also vary TZ
  --vary-locale           also vary LC_ALL and LANG
  --vary-env NAME=a,b,c   also vary NAME; first value is the baseline (repeatable)
  --workdir <dir>         copied fresh into a temp dir for every run, the
                          command runs there ${'[default: .]'} (.git and
                          node_modules are not copied)
  --seed <n>              seed for the generated hash seeds, to replay a report
  --no-isolate            skip the one-dimension-at-a-time replay
  --json                  emit JSON instead of the report
  --no-color              disable colour
  -h, --help              this screen

exit codes
  0 runs agree    1 runs differ    2 incomplete (timeout, command did not start, bad flag)
`;

function parseArgs(argv) {
  const opts = {
    runs: DEFAULT_RUNS,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    outputs: [],
    normalizers: [],
    varyTz: false,
    varyLocale: false,
    varyEnv: [],
    workdir: '.',
    seed: undefined,
    isolate: true,
    json: false,
    noColor: false,
    help: false,
    command: null,
    args: [],
  };
  const value = (i, name) => {
    const v = argv[i];
    if (v === undefined) throw new Error(`${name} expects a value`);
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      const rest = argv.slice(i + 1);
      if (rest.length === 0) throw new Error('missing command after --');
      [opts.command, ...opts.args] = rest;
      break;
    }
    if (arg === '-h' || arg === '--help') opts.help = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--no-color') opts.noColor = true;
    else if (arg === '--vary-tz') opts.varyTz = true;
    else if (arg === '--vary-locale') opts.varyLocale = true;
    else if (arg === '--no-isolate') opts.isolate = false;
    else if (arg === '--runs') {
      const n = Number(value(++i, arg));
      if (!Number.isInteger(n) || n < 2) throw new Error('--runs expects an integer >= 2');
      opts.runs = n;
    } else if (arg === '--timeout') {
      const n = Number(value(++i, arg));
      if (!Number.isFinite(n) || n <= 0) throw new Error('--timeout expects a positive number of seconds');
      opts.timeoutMs = Math.round(n * 1000);
    } else if (arg === '--seed') {
      const n = Number(value(++i, arg));
      if (!Number.isInteger(n) || n < 0) throw new Error('--seed expects a non-negative integer');
      opts.seed = n;
    } else if (arg === '--output') {
      const p = value(++i, arg).replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
      if (!p || path.isAbsolute(p) || p.split('/').includes('..')) {
        throw new Error(`--output must be a relative path inside --workdir: ${argv[i]}`);
      }
      opts.outputs.push(p);
    } else if (arg === '--normalize') {
      const src = value(++i, arg);
      try {
        opts.normalizers.push(new RegExp(src, 'g'));
      } catch (err) {
        throw new Error(`--normalize: invalid regex ${src}: ${err.message}`);
      }
    } else if (arg === '--vary-env') {
      const spec = value(++i, arg);
      const eq = spec.indexOf('=');
      const name = spec.slice(0, eq);
      const values = spec.slice(eq + 1).split(',');
      if (eq <= 0 || values.length < 2) throw new Error(`--vary-env expects NAME=v1,v2[,...]: ${spec}`);
      opts.varyEnv.push([name, values]);
    } else if (arg === '--workdir') {
      opts.workdir = value(++i, arg);
    } else {
      throw new Error(`unknown option: ${arg} (the command goes after --; try --help)`);
    }
  }
  if (!opts.help && !opts.command) throw new Error('missing command: prodcheck-nondet [options] -- <command> [args...]');
  return opts;
}

function shellQuote(s) {
  return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

function renderReport(result, style) {
  const lines = [];
  const indent = (text, pad) => text.split('\n').map((l) => pad + l).join('\n');
  const envStr = (env) => Object.entries(env).map(([k, v]) => `${k}=${v}`).join(' ');

  lines.push('');
  lines.push(`  ${style.bold('command')}  ${result.command.map(shellQuote).join(' ')}`);
  lines.push(`  ${style.bold('varied')}   ${result.dimensions.map((d) => d.name).join(', ')}   ${style.dim(`seed ${result.seed}`)}`);
  lines.push('');

  for (const r of result.runs) {
    const mark = r.spawnError ? style.yellow('ERROR  ') : r.timedOut ? style.yellow('TIMEOUT') : r.differences.length ? style.red('DIFFERS') : style.green('same   ');
    const what = r.role === 'baseline' ? style.dim('baseline') : r.differences.length ? r.differences.map((d) => d.aspect).join(', ') : '';
    lines.push(`  run ${String(r.index).padStart(2)}  ${mark}  ${r.role.padEnd(9)} ${style.dim(envStr(r.env))}  ${what}`.trimEnd());
  }

  const differing = result.runs.filter((r) => r.differences.length > 0);
  if (differing.length) {
    // A run with only fixed values, so --seed replays exactly what is shown.
    const first = differing.find((r) => r.env.PYTHONHASHSEED !== 'random') ?? differing[0];
    lines.push('');
    lines.push(`  ${style.bold(`difference: run ${first.index}`)} vs baseline` + (first.changed.length ? ` (changed: ${first.changed.join(', ')})` : ' (no perturbation)'));
    for (const d of first.differences) {
      lines.push('');
      lines.push(`     ${style.bold(d.aspect)}`);
      lines.push(indent(d.diff, '     '));
    }
  }

  if (result.intrinsic) {
    lines.push('');
    lines.push(`  ${style.red('!!')} the control run, with the identical environment, already differs:`);
    lines.push('     the program is nondeterministic on its own (clock, randomness, concurrency).');
    lines.push('     No perturbation can be blamed; use --normalize if the difference is benign.');
  }

  if (result.isolation.length) {
    lines.push('');
    lines.push(`  ${style.bold('which perturbation')} ${style.dim(`(replaying run ${result.isolation[0].replayOf} one dimension at a time)`)}`);
    for (const x of result.isolation) {
      const verdict = x.timedOut ? style.yellow('timed out') : x.reproduced ? style.red(`alone reproduces: ${x.aspects.join(', ')}`) : style.green('alone does not reproduce');
      lines.push(`     ${x.dimension}=${x.value}  ${verdict}`);
    }
  }

  lines.push('');
  lines.push('  ' + '-'.repeat(74));
  const n = result.runs.length;
  if (result.verdict === 'nondeterministic') {
    lines.push(`  ${style.red('NONDETERMINISTIC')}  ${differing.length} of ${n - 1} runs differ from the baseline`);
  } else if (result.verdict === 'incomplete') {
    const why = result.runs.some((r) => r.spawnError)
      ? `command did not start: ${result.runs.find((r) => r.spawnError).spawnError}`
      : `${result.runs.filter((r) => r.timedOut).length} run(s) timed out after ${result.timeoutMs / 1000}s`;
    lines.push(`  ${style.yellow('INCOMPLETE')}  ${why} — determinism not proven`);
  } else {
    lines.push(`  ${style.green('DETERMINISTIC')}  all ${n} runs agree on exit code, stdout, stderr and outputs`);
  }
  lines.push('');
  return lines.join('\n') + '\n';
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.noColor) process.env.NO_COLOR = '1';
  if (opts.help) {
    process.stdout.write(HELP);
    return;
  }

  const result = await detect({ ...opts, workdir: path.resolve(opts.workdir) });

  if (opts.json) {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    const doc = { schemaVersion: 1, tool: { name: 'prodcheck-nondet', version: pkg.version }, ...result };
    process.stdout.write(`${JSON.stringify(doc, null, 2)}\n`);
  } else {
    const { style } = await import('./ui/theme.mjs');
    process.stdout.write(renderReport(result, style));
  }
  process.exitCode = exitCodeFor(result);
}

main().catch((err) => {
  process.stderr.write(`prodcheck-nondet: ${err?.message ?? err}\n`);
  process.exit(2);
});
