/**
 * Nondeterminism detector — the engine.
 *
 * The incident this exists for: a Python program picked a category by
 * iterating over a set. With hash randomization on, the pick changed from one
 * run to the next on the same input, and the one green test run in CI said
 * nothing. A single run proves one outcome, not the outcome.
 *
 * So the command runs N times and every run is compared with the first:
 *
 *   run 0  baseline   PYTHONHASHSEED=0, plus the baseline value of every other
 *                     dimension being varied
 *   run 1  control    the exact same environment again. If this one already
 *                     differs, the program is nondeterministic on its own
 *                     (clock, randomness, concurrency) and no perturbation can
 *                     be blamed for it.
 *   run 2+ perturbed  every varied dimension moves at once: PYTHONHASHSEED
 *                     (the literal `random` on run 2, fresh integers after),
 *                     and optionally TZ, LC_ALL/LANG and user-listed env vars.
 *
 * When a perturbed run differs and the control did not, the first such run is
 * replayed once per dimension, changing only that one, so the report can say
 * which perturbation alone reproduces the difference instead of listing all of
 * them as suspects.
 *
 * Isolation between runs: each run gets its own fresh copy of the work
 * directory in a new temporary directory, and its declared output paths are
 * read from that copy. No run can see another run's files.
 *
 * Runs are sequential on purpose. Parallel runs would add a perturbation the
 * report cannot name (contention on shared /tmp, ports, CPU).
 */

import { spawn } from 'node:child_process';
import { createHash, randomInt } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { minimalDiff } from './diff.mjs';

export const DEFAULT_RUNS = 8;
export const DEFAULT_TIMEOUT_MS = 60_000;
/** Directories never copied into a run's sandbox: large, and not program input. */
export const COPY_SKIP = new Set(['.git', 'node_modules']);

export const TZ_VALUES = ['UTC', 'America/Los_Angeles', 'Asia/Kolkata', 'Pacific/Chatham'];
// A locale the host does not have falls back to C without an error. That only
// makes a run less perturbed, never falsely different, so it is tolerated.
export const LOCALE_VALUES = ['C', 'C.UTF-8', 'en_US.UTF-8', 'de_DE.UTF-8'];

const MAX_CAPTURE_BYTES = 16 * 1024 * 1024;

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/** Deterministic PRNG so `--seed` reproduces the exact hash seeds of a report. */
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * The varied dimensions, each with its value list. Index 0 is the baseline.
 * A dimension maps to one or more env vars (locale sets LC_ALL and LANG).
 */
export function buildDimensions({ runs, seed, varyTz, varyLocale, varyEnv }) {
  const rand = mulberry32(seed);
  const hashSeeds = ['0', 'random'];
  while (hashSeeds.length < runs) {
    // 1..4294967295 is PYTHONHASHSEED's valid range; 0 is the baseline.
    hashSeeds.push(String(1 + Math.floor(rand() * 4294967294)));
  }
  const dims = [{ name: 'PYTHONHASHSEED', vars: ['PYTHONHASHSEED'], values: hashSeeds }];
  if (varyTz) dims.push({ name: 'TZ', vars: ['TZ'], values: TZ_VALUES });
  if (varyLocale) dims.push({ name: 'locale', vars: ['LC_ALL', 'LANG'], values: LOCALE_VALUES });
  for (const [name, values] of varyEnv) {
    dims.push({ name: `env:${name}`, vars: [name], values });
  }
  return dims;
}

/** Value index per dimension for run k: baseline and control use 0. */
function planIndices(dims, k) {
  if (k < 2) return dims.map(() => 0);
  return dims.map((d) => (k - 1) % d.values.length);
}

function envFor(dims, indices) {
  const env = {};
  dims.forEach((d, i) => {
    for (const v of d.vars) env[v] = d.values[indices[i]];
  });
  return env;
}

function sandbox(workdir) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'prodcheck-nondet-'));
  const root = path.join(dir, 'work');
  cpSync(workdir, root, {
    recursive: true,
    filter: (src) => !COPY_SKIP.has(path.basename(src)) || src === workdir,
    verbatimSymlinks: true,
  });
  return { dir, root };
}

/** Spawn one run; resolves with exit info, captured output and timing. */
function execute(command, args, { cwd, env, timeoutMs }) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    let child;
    try {
      // detached: the child leads its own process group, so a timeout can kill
      // the whole tree, not just the shell that started it.
      child = spawn(command, args, { cwd, env, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      resolve({ exitCode: null, signal: null, timedOut: false, spawnError: err.message, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), durationMs: 0 });
      return;
    }
    const out = [];
    const errc = [];
    let outBytes = 0;
    let errBytes = 0;
    child.stdout.on('data', (b) => {
      if (outBytes < MAX_CAPTURE_BYTES) out.push(b);
      outBytes += b.length;
    });
    child.stderr.on('data', (b) => {
      if (errBytes < MAX_CAPTURE_BYTES) errc.push(b);
      errBytes += b.length;
    });

    let timedOut = false;
    let spawnError = null;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    }, timeoutMs);

    child.on('error', (err) => {
      spawnError = err.message;
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        exitCode: code,
        signal,
        timedOut,
        spawnError,
        stdout: Buffer.concat(out),
        stderr: Buffer.concat(errc),
        durationMs: Math.round(performance.now() - t0),
      });
    });
  });
}

/** Every regular file under the declared outputs: POSIX relative path -> Buffer|null. */
function collectOutputs(root, outputs) {
  const files = new Map();
  const visit = (abs, rel) => {
    let info;
    try {
      info = statSync(abs);
    } catch {
      files.set(rel, null);
      return;
    }
    if (info.isDirectory()) {
      const names = readdirSync(abs).sort();
      if (names.length === 0) files.set(`${rel}/`, Buffer.alloc(0));
      for (const name of names) visit(path.join(abs, name), `${rel}/${name}`);
    } else {
      files.set(rel, readFileSync(abs));
    }
  };
  for (const o of outputs) visit(path.join(root, ...o.split('/')), o);
  return files;
}

function applyNormalizers(text, normalizers) {
  let s = text;
  for (const re of normalizers) {
    s = s.replace(re.global ? re : new RegExp(re.source, `${re.flags}g`), '<normalized>');
  }
  return s;
}

/** Text if it decodes as UTF-8 without NUL bytes, else null (compared by hash). */
function asText(buf) {
  if (buf.includes(0)) return null;
  const s = buf.toString('utf8');
  return s.includes('�') ? null : s;
}

/** The comparable view of a run: normalized streams and per-file digests. */
function fingerprint(raw, files, normalizers) {
  const stdout = applyNormalizers(raw.stdout.toString('utf8'), normalizers);
  const stderr = applyNormalizers(raw.stderr.toString('utf8'), normalizers);
  const fileView = {};
  for (const [rel, buf] of files) {
    if (buf === null) {
      fileView[rel] = { present: false, sha256: null, text: null };
      continue;
    }
    const text = asText(buf);
    const norm = text === null ? null : applyNormalizers(text, normalizers);
    fileView[rel] = { present: true, sha256: norm === null ? sha256(buf) : sha256(norm), rawSha256: sha256(buf), text: norm };
  }
  const exit = raw.timedOut ? 'timeout' : raw.spawnError ? `spawn-error: ${raw.spawnError}` : raw.signal ? `signal ${raw.signal}` : `exit ${raw.exitCode}`;
  return { exit, stdout, stderr, files: fileView };
}

/** Aspects in which `b` differs from baseline `a`, each with a minimal diff. */
export function compare(a, b) {
  const diffs = [];
  if (a.exit !== b.exit) diffs.push({ aspect: 'exit', diff: `- ${a.exit}\n+ ${b.exit}` });
  if (a.stdout !== b.stdout) diffs.push({ aspect: 'stdout', diff: minimalDiff(a.stdout, b.stdout) });
  if (a.stderr !== b.stderr) diffs.push({ aspect: 'stderr', diff: minimalDiff(a.stderr, b.stderr) });
  const names = [...new Set([...Object.keys(a.files), ...Object.keys(b.files)])].sort();
  for (const name of names) {
    const fa = a.files[name] ?? { present: false };
    const fb = b.files[name] ?? { present: false };
    if (!fa.present && !fb.present) continue;
    if (fa.present !== fb.present) {
      diffs.push({ aspect: `file:${name}`, diff: `- ${fa.present ? 'present' : 'missing'}\n+ ${fb.present ? 'present' : 'missing'}` });
    } else if (fa.sha256 !== fb.sha256) {
      const diff = fa.text !== null && fb.text !== null ? minimalDiff(fa.text, fb.text) : `- sha256 ${fa.rawSha256}\n+ sha256 ${fb.rawSha256}`;
      diffs.push({ aspect: `file:${name}`, diff });
    }
  }
  return diffs;
}

async function runOnce(opts, env) {
  const box = sandbox(opts.workdir);
  try {
    const raw = await execute(opts.command, opts.args, {
      cwd: box.root,
      env: { ...process.env, ...env },
      timeoutMs: opts.timeoutMs,
    });
    const files = collectOutputs(box.root, opts.outputs);
    return { raw, view: fingerprint(raw, files, opts.normalizers) };
  } finally {
    rmSync(box.dir, { recursive: true, force: true });
  }
}

/**
 * @param {object} opts
 * @param {string} opts.command          executable (no shell)
 * @param {string[]} opts.args
 * @param {string} opts.workdir          copied fresh into each run's sandbox
 * @param {string[]} opts.outputs        POSIX paths relative to workdir
 * @param {RegExp[]} opts.normalizers    global regexes; matches become <normalized>
 * @param {number} [opts.runs]
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.seed]           seeds the generated PYTHONHASHSEED values
 * @param {boolean} [opts.varyTz]
 * @param {boolean} [opts.varyLocale]
 * @param {Array<[string, string[]]>} [opts.varyEnv]
 * @param {boolean} [opts.isolate]       replay one dimension at a time (default true)
 */
export async function detect(opts) {
  const o = {
    runs: DEFAULT_RUNS,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    seed: randomInt(0, 2 ** 31),
    varyTz: false,
    varyLocale: false,
    varyEnv: [],
    isolate: true,
    outputs: [],
    normalizers: [],
    ...opts,
  };
  // An explicit `seed: undefined` (the CLI without --seed) still gets one, so
  // every report names the seed that replays it.
  o.seed ??= randomInt(0, 2 ** 31);
  if (!Number.isInteger(o.runs) || o.runs < 2) throw new Error('runs must be an integer >= 2');
  if (!existsSync(o.workdir) || !statSync(o.workdir).isDirectory()) throw new Error(`workdir is not a directory: ${o.workdir}`);
  const rel = path.relative(path.resolve(o.workdir), os.tmpdir());
  if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
    // The sandbox copy would land inside the tree being copied.
    throw new Error(`workdir contains the temp directory ${os.tmpdir()}; pick a narrower --workdir`);
  }

  const dims = buildDimensions(o);
  const runs = [];
  let baseline = null;
  for (let k = 0; k < o.runs; k++) {
    const indices = planIndices(dims, k);
    const env = envFor(dims, indices);
    const { raw, view } = await runOnce(o, env);
    if (k === 0) baseline = view;
    runs.push({
      index: k,
      role: k === 0 ? 'baseline' : k === 1 ? 'control' : 'perturbed',
      env,
      exit: view.exit,
      exitCode: raw.exitCode,
      timedOut: raw.timedOut,
      spawnError: raw.spawnError,
      durationMs: raw.durationMs,
      stdoutSha256: sha256(view.stdout),
      stderrSha256: sha256(view.stderr),
      files: Object.fromEntries(Object.entries(view.files).map(([n, f]) => [n, f.present ? f.sha256 : null])),
      // Dimensions whose value differs from baseline on this run.
      changed: dims.filter((d, i) => indices[i] !== 0 && d.values[indices[i]] !== d.values[0]).map((d) => d.name),
      differences: k === 0 ? [] : compare(baseline, view),
      _indices: indices,
    });
  }

  const control = runs[1];
  const ok = (r) => !r.timedOut && !r.spawnError;
  const intrinsic = ok(runs[0]) && ok(control) && control.differences.length > 0;
  const differing = runs.filter((r) => r.differences.length > 0);

  // One-factor replay of one differing perturbed run.
  const isolation = [];
  // Prefer a run whose values are all fixed: replaying PYTHONHASHSEED=random
  // rolls a new seed, so it re-tests the dimension rather than the run.
  const perturbedDiffs = differing.filter((r) => r.role === 'perturbed');
  const target = perturbedDiffs.find((r) => r.env.PYTHONHASHSEED !== 'random') ?? perturbedDiffs[0];
  if (o.isolate && !intrinsic && target) {
    for (let i = 0; i < dims.length; i++) {
      const d = dims[i];
      if (!target.changed.includes(d.name)) continue;
      const indices = dims.map(() => 0);
      indices[i] = target._indices[i];
      const { raw, view } = await runOnce(o, envFor(dims, indices));
      const diffs = compare(baseline, view);
      isolation.push({
        dimension: d.name,
        value: d.values[indices[i]],
        replayOf: target.index,
        reproduced: diffs.length > 0,
        aspects: diffs.map((x) => x.aspect),
        timedOut: raw.timedOut,
      });
    }
  }

  for (const r of runs) delete r._indices;

  const anyTimeout = runs.some((r) => r.timedOut) || isolation.some((x) => x.timedOut);
  const spawnFailed = runs.some((r) => r.spawnError);
  // A difference that is only "this run timed out" proves nothing about the
  // program's output; it means the verification is incomplete. So does a
  // command that never started: eight identical spawn errors are not proof of
  // determinism.
  const realDiff = ok(runs[0]) && runs.some((r) => ok(r) && r.differences.length > 0);
  const verdict = realDiff ? 'nondeterministic' : anyTimeout || spawnFailed ? 'incomplete' : 'deterministic';

  return {
    verdict,
    intrinsic,
    seed: o.seed,
    command: [o.command, ...o.args],
    timeoutMs: o.timeoutMs,
    dimensions: dims.map((d) => ({ name: d.name, vars: d.vars, values: d.values })),
    runs,
    isolation,
  };
}

/** 0 deterministic, 1 difference found, 2 incomplete (timeout, command did not start). */
export function exitCodeFor(result) {
  return result.verdict === 'nondeterministic' ? 1 : result.verdict === 'incomplete' ? 2 : 0;
}
