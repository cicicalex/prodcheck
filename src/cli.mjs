#!/usr/bin/env node
/**
 * prodcheck — CLI entrypoint.
 *
 *   prodcheck [path] [--fail-on <level>] [--json] [--no-color] [-h] [-v]
 *
 * One structural rule shapes this file: the ui modules read the environment at
 * module load (theme.mjs decides color once, at import time). So argument
 * parsing happens first, `--no-color` sets NO_COLOR in the environment, and
 * only then are the ui modules imported — always dynamically, never at the
 * top of this file. A static import here would freeze the color decision
 * before the flag was seen.
 *
 * The scan itself is two passes over one read of the tree. Pass 1 walks every
 * file and asks each check the single-file question it has always asked, plus
 * — for the checks that opted into the two-phase contract in checks/index.mjs
 * — collects that file's facts. Pass 2 runs after the walk and lets those
 * checks answer the questions that need the whole tree. Files are read once,
 * for both.
 *
 * Exit contract (mirrors src/ui/report.mjs):
 *   0 — clean
 *   1 — findings at or above --fail-on
 *   2 — the scan itself failed (bad path, bad flag, crash)
 */

import { readFileSync } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { checks, LOCKED_PAID_CHECKS } from './checks/index.mjs';

const FAIL_LEVELS = new Set(['critical', 'high', 'medium', 'low', 'never']);
/** Union of every registered check's extensions — the walk collects on this. */
const EXTENSIONS = new Set(checks.flatMap((c) => [...c.extensions]));
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);
const MAX_FILE_BYTES = 1024 * 1024; // generated bundles are noise, not signal

function parseArgs(argv) {
  const opts = { path: '.', failOn: 'high', json: false, noColor: false, help: false, version: false };
  const positionals = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') opts.json = true;
    else if (arg === '--no-color') opts.noColor = true;
    else if (arg === '-h' || arg === '--help') opts.help = true;
    else if (arg === '-v' || arg === '--version') opts.version = true;
    else if (arg === '--fail-on' || arg.startsWith('--fail-on=')) {
      const value = arg === '--fail-on' ? argv[++i] : arg.slice('--fail-on='.length);
      if (!value || !FAIL_LEVELS.has(value)) {
        throw new Error(`--fail-on expects one of: critical, high, medium, low, never`);
      }
      opts.failOn = value;
    } else if (arg.startsWith('-') && arg !== '-') {
      throw new Error(`unknown option: ${arg} (try --help)`);
    } else {
      positionals.push(arg);
    }
  }

  if (positionals.length > 1) {
    throw new Error(`expected at most one path, got ${positionals.length}`);
  }
  if (positionals.length === 1) opts.path = positionals[0];
  return opts;
}

/**
 * Depth-first, sorted, so repeat runs produce identical output. Named `walk`
 * rather than `collect` because `collect` now means the checks' phase-1 hook,
 * and one of the two had to give.
 */
async function walk(dir, out) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return; // unreadable subdirectory: skip it, do not kill the scan
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      await walk(abs, out);
    } else if (entry.isFile()) {
      // Symlinks are neither, and are skipped on purpose: following them
      // invites cycles and scanning files outside the root.
      if (EXTENSIONS.has(path.extname(entry.name))) out.push(abs);
    }
  }
}

/**
 * One finding per (rule, file, line), first occurrence wins.
 *
 * A location is the thing a developer fixes, and a rule that reaches the same
 * line twice — once from the file itself, once from a cross-file join, or once
 * per call site of a shared helper — has found one bug, not several. Eleven
 * routes keying a limiter on the same forgeable helper must produce one line to
 * change, not eleven identical diffs.
 */
function dedupe(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const key = JSON.stringify([f.rule, f.file, f.line]);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

/**
 * Sort by file, then line, then rule.
 *
 * Pass 2 appends findings after the walk has moved on, so without this the JSON
 * output would list a file's findings out of order and the report — which sorts
 * by severity and file with a stable sort, inheriting this order underneath —
 * would print line 40 above line 12. Sorting on the finding's own identity also
 * makes the output independent of the order the checks ran in.
 */
function order(findings) {
  return findings.sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.rule.localeCompare(b.rule)
  );
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  // Must happen before any ui import — theme.mjs reads env at module load.
  if (opts.noColor) process.env.NO_COLOR = '1';

  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

  if (opts.help) {
    const { renderHelp } = await import('./ui/help.mjs');
    process.stdout.write(renderHelp(pkg.version));
    return;
  }
  if (opts.version) {
    process.stdout.write(`${pkg.version}\n`);
    return;
  }

  const root = path.resolve(opts.path);
  let rootInfo;
  try {
    rootInfo = await stat(root);
  } catch {
    throw new Error(`cannot read path: ${opts.path}`);
  }

  const startedAt = new Date().toISOString();
  const t0 = performance.now();

  const files = [];
  if (rootInfo.isFile()) {
    if (EXTENSIONS.has(path.extname(root))) files.push(root);
  } else {
    await walk(root, files);
  }

  const findings = [];
  // Pass-1 facts, per check that collects them: relative POSIX path -> facts.
  // Insertion order is walk order, which is sorted, so pass 2 sees the tree in
  // the same order however the host filesystem enumerates it.
  const facts = new Map(checks.filter((c) => c.collect).map((c) => [c, new Map()]));
  let filesScanned = 0;
  for (const abs of files) {
    let info;
    try {
      info = await stat(abs);
    } catch {
      continue;
    }
    if (info.size > MAX_FILE_BYTES) continue;

    let content;
    try {
      content = await readFile(abs, 'utf8');
    } catch {
      continue;
    }
    filesScanned += 1;

    const rel = rootInfo.isFile() ? path.basename(abs) : path.relative(root, abs);
    const file = { path: rel.split(path.sep).join('/'), content };
    const ext = path.extname(abs);
    // Each check re-gates on its own candidacy inside check(); the extension
    // filter here just keeps a check away from file types it never claimed.
    for (const c of checks) {
      if (!c.extensions.has(ext)) continue;
      findings.push(...c.check(file));
      if (c.collect) {
        const collected = c.collect(file);
        if (collected) facts.get(c).set(file.path, collected);
      }
    }
  }

  // Pass 2: the questions a single file cannot answer. Appended after the
  // walk, so `filesScanned` is already final and no check can see a file the
  // walk skipped.
  for (const c of checks) {
    if (c.finalize) findings.push(...(c.finalize(facts.get(c) ?? new Map()) ?? []));
  }

  const result = {
    findings: order(dedupe(findings)),
    filesScanned,
    durationMs: Math.round(performance.now() - t0),
    lockedChecks: LOCKED_PAID_CHECKS,
  };

  if (opts.json) {
    const { renderJson } = await import('./ui/json.mjs');
    process.stdout.write(renderJson(result, { version: pkg.version, root: opts.path, startedAt }));
  } else {
    const { renderReport } = await import('./ui/report.mjs');
    process.stdout.write(renderReport(result));
  }

  const { exitCode } = await import('./ui/report.mjs');
  process.exitCode = exitCode(result.findings, opts.failOn);
}

main().catch((err) => {
  process.stderr.write(`prodcheck: ${err?.message ?? err}\n`);
  process.exit(2);
});
