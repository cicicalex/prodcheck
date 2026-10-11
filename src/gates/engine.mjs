/**
 * Gate of gates — the engine.
 *
 * A check that cannot fail proves nothing. The incident that produced this
 * module: a marker `cap=262144` was a hard-coded constant, three gates verified
 * that constant, and so none of the three could ever go red. Each was green,
 * each was worthless, and nothing in the pipeline could tell.
 *
 * So for every configured check this module asks two questions, in order:
 *
 *   1. Does it pass on the unmodified tree?  If not: BROKEN BASELINE. A check
 *      that is already red tells you nothing about whether it can go red.
 *   2. For each breaker — a deliberate, named way to make the subject wrong —
 *      does it FAIL?  If it still passes: CANNOT FAIL.
 *
 * Every run, the baseline included, happens in a fresh temporary copy of the
 * tree. Nothing is ever executed in place: a check that writes files, a patch
 * that half-applies, or a setup command that deletes things all land in a
 * directory that is removed afterwards. The original tree is hashed before and
 * after, and a changed hash is itself reported as a failure, not a warning —
 * a verification tool that corrupts what it verifies is worse than none.
 *
 * Zero dependencies, like the rest of prodcheck: node:fs, node:child_process,
 * node:crypto, and `git apply` for patches (git is the one external binary, and
 * it is only needed when a breaker uses `patch`).
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_EXCLUDE = ['.git'];
/** How much of each step's output is kept for the report — the tail is where the error is. */
const OUTPUT_TAIL_BYTES = 4096;
/** How long to wait for output to drain after the step exits or is killed. */
const STDIO_GRACE_MS = 2000;

/** Per-breaker outcomes. Only CAUGHT is good. */
export const CAUGHT = 'CAUGHT';
export const CANNOT_FAIL = 'CANNOT FAIL';
export const TIMEOUT = 'TIMEOUT';
export const BREAKER_ERROR = 'BREAKER ERROR';

/** Per-check verdicts. Only CAN_FAIL is good. */
export const CAN_FAIL = 'CAN FAIL';
export const BROKEN_BASELINE = 'BROKEN BASELINE';
export const INCONCLUSIVE = 'INCONCLUSIVE';

const BREAKER_KINDS = ['patch', 'replace', 'setup', 'env'];

// ── config ──────────────────────────────────────────────────────────────────

function fail(msg) {
  throw new Error(`config: ${msg}`);
}

function positiveInt(value, where) {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value <= 0) fail(`${where} must be a positive integer (milliseconds)`);
  return value;
}

/**
 * Validate and normalise a parsed config object. Every problem is a thrown
 * error naming the exact field: a gate-of-gates config that is silently
 * half-read is the same bug this module exists to catch.
 *
 * @param {object} raw        parsed JSON
 * @param {string} configDir  directory that patch / contentFrom paths resolve against
 */
export function normaliseConfig(raw, configDir) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('top level must be an object');
  const known = new Set(['root', 'timeoutMs', 'exclude', 'checks']);
  for (const k of Object.keys(raw)) if (!known.has(k)) fail(`unknown top-level key "${k}"`);

  const timeoutMs = positiveInt(raw.timeoutMs, 'timeoutMs') ?? DEFAULT_TIMEOUT_MS;
  const exclude = raw.exclude ?? DEFAULT_EXCLUDE;
  if (!Array.isArray(exclude) || exclude.some((e) => typeof e !== 'string' || !e || e.includes('/'))) {
    fail('exclude must be an array of entry names (no slashes)');
  }
  if (raw.root !== undefined && typeof raw.root !== 'string') fail('root must be a string');
  const root = path.resolve(configDir, raw.root ?? '.');

  if (!Array.isArray(raw.checks) || raw.checks.length === 0) fail('checks must be a non-empty array');
  const names = new Set();
  const checks = raw.checks.map((c, i) => {
    const where = `checks[${i}]`;
    if (!c || typeof c !== 'object') fail(`${where} must be an object`);
    for (const k of Object.keys(c)) {
      if (!['name', 'run', 'timeoutMs', 'breakers'].includes(k)) fail(`${where}: unknown key "${k}"`);
    }
    if (typeof c.name !== 'string' || !c.name) fail(`${where}.name must be a non-empty string`);
    if (names.has(c.name)) fail(`duplicate check name "${c.name}"`);
    names.add(c.name);
    if (typeof c.run !== 'string' || !c.run.trim()) fail(`${where}.run must be a non-empty command`);
    // A check with no breakers is exactly the unproven gate this tool rejects.
    if (!Array.isArray(c.breakers) || c.breakers.length === 0) {
      fail(`${where}.breakers must list at least one way to break the subject`);
    }
    const bnames = new Set();
    const breakers = c.breakers.map((b, j) => normaliseBreaker(b, `${where}.breakers[${j}]`, configDir, bnames));
    return {
      name: c.name,
      run: c.run,
      timeoutMs: positiveInt(c.timeoutMs, `${where}.timeoutMs`) ?? timeoutMs,
      breakers,
    };
  });

  return { root, timeoutMs, exclude, checks };
}

function normaliseBreaker(b, where, configDir, seen) {
  if (!b || typeof b !== 'object') fail(`${where} must be an object`);
  for (const k of Object.keys(b)) {
    if (k !== 'name' && !BREAKER_KINDS.includes(k)) fail(`${where}: unknown key "${k}"`);
  }
  if (!BREAKER_KINDS.some((k) => b[k] !== undefined)) {
    fail(`${where} needs at least one of: ${BREAKER_KINDS.join(', ')}`);
  }
  const out = {};

  if (b.patch !== undefined) {
    if (typeof b.patch !== 'string' || !b.patch) fail(`${where}.patch must be a path to a patch file`);
    out.patch = path.resolve(configDir, b.patch);
  }
  if (b.replace !== undefined) {
    const list = Array.isArray(b.replace) ? b.replace : [b.replace];
    out.replace = list.map((r, k) => {
      const w = `${where}.replace${Array.isArray(b.replace) ? `[${k}]` : ''}`;
      if (!r || typeof r !== 'object') fail(`${w} must be an object`);
      if (typeof r.file !== 'string' || !r.file) fail(`${w}.file must be a path inside the tree`);
      const hasContent = typeof r.content === 'string';
      const hasFrom = typeof r.contentFrom === 'string' && r.contentFrom;
      if (hasContent === Boolean(hasFrom)) fail(`${w} needs exactly one of content, contentFrom`);
      const rel = path.normalize(r.file);
      if (path.isAbsolute(rel) || rel === '..' || rel.startsWith(`..${path.sep}`)) {
        fail(`${w}.file must stay inside the tree: ${r.file}`);
      }
      return hasContent
        ? { file: rel, content: r.content }
        : { file: rel, contentFrom: path.resolve(configDir, r.contentFrom) };
    });
  }
  if (b.setup !== undefined) {
    if (typeof b.setup !== 'string' || !b.setup.trim()) fail(`${where}.setup must be a non-empty command`);
    out.setup = b.setup;
  }
  if (b.env !== undefined) {
    if (!b.env || typeof b.env !== 'object' || Array.isArray(b.env)) fail(`${where}.env must be an object`);
    for (const [k, v] of Object.entries(b.env)) {
      if (typeof v !== 'string') fail(`${where}.env.${k} must be a string`);
    }
    out.env = { ...b.env };
  }

  out.name = typeof b.name === 'string' && b.name ? b.name : describeBreaker(out);
  if (seen.has(out.name)) fail(`${where}: duplicate breaker name "${out.name}"`);
  seen.add(out.name);
  return out;
}

function describeBreaker(b) {
  const parts = [];
  if (b.patch) parts.push(`patch ${path.basename(b.patch)}`);
  if (b.replace) parts.push(`replace ${b.replace.map((r) => r.file.split(path.sep).join('/')).join(', ')}`);
  if (b.setup) parts.push(`setup \`${b.setup}\``);
  if (b.env) parts.push(`env ${Object.keys(b.env).join(', ')}`);
  return parts.join(' + ');
}

export function loadConfig(configPath) {
  let text;
  try {
    text = readFileSync(configPath, 'utf8');
  } catch {
    throw new Error(`cannot read config: ${configPath}`);
  }
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new Error(`config is not valid JSON: ${err.message}`);
  }
  return normaliseConfig(raw, path.dirname(path.resolve(configPath)));
}

// ── tree: hash and copy ─────────────────────────────────────────────────────

/**
 * SHA-256 over every entry under `root` (minus excluded names): relative POSIX
 * path, kind, mode, and the bytes (or the link target for a symlink), in
 * sorted order. Two trees with the same hash are byte-identical in content,
 * layout and permissions.
 */
export function hashTree(root, exclude = DEFAULT_EXCLUDE) {
  const skip = new Set(exclude);
  const h = createHash('sha256');
  const visit = (dir, rel) => {
    const names = readdirSync(dir).sort();
    for (const name of names) {
      if (skip.has(name)) continue;
      const abs = path.join(dir, name);
      const r = rel ? `${rel}/${name}` : name;
      const st = lstatSync(abs);
      const mode = (st.mode & 0o777).toString(8);
      if (st.isSymbolicLink()) {
        h.update(`L\0${r}\0${readlinkSync(abs)}\0`);
      } else if (st.isDirectory()) {
        h.update(`D\0${r}\0${mode}\0`);
        visit(abs, r);
      } else if (st.isFile()) {
        const bytes = readFileSync(abs);
        h.update(`F\0${r}\0${mode}\0${bytes.length}\0`);
        h.update(bytes);
      } else {
        h.update(`O\0${r}\0`);
      }
    }
  };
  visit(root, '');
  return h.digest('hex');
}

function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/** Fresh copy of `root` in a new temp directory. Returns the copy's path. */
function copyTree(root, exclude) {
  const base = mkdtempSync(path.join(os.tmpdir(), 'prodcheck-gates-'));
  const dest = path.join(base, 'tree');
  if (isInside(dest, root)) {
    rmSync(base, { recursive: true, force: true });
    throw new Error(`temporary directory ${base} is inside the tree; set TMPDIR elsewhere`);
  }
  const skip = new Set(exclude);
  cpSync(root, dest, {
    recursive: true,
    verbatimSymlinks: true,
    filter: (src) => src === root || !skip.has(path.basename(src)),
  });
  return { base, dest };
}

// ── processes ───────────────────────────────────────────────────────────────

function tail(buf) {
  const s = buf.toString('utf8');
  return s.length > OUTPUT_TAIL_BYTES ? `…${s.slice(-OUTPUT_TAIL_BYTES)}` : s;
}

/**
 * Run one shell command with a hard timeout. The child gets its own process
 * group so a timeout kills everything it started — `npm test` that spawned a
 * hung server must not outlive the step.
 *
 * @returns {Promise<{code: number|null, signal: string|null, timedOut: boolean, durationMs: number, output: string}>}
 */
export function runStep(command, { cwd, env, timeoutMs }) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const chunks = [];
    let size = 0;
    const keep = (c) => {
      chunks.push(c);
      size += c.length;
      // Bounded memory: drop the oldest chunks once well past the tail size.
      while (size > OUTPUT_TAIL_BYTES * 4 && chunks.length > 1) size -= chunks.shift().length;
    };
    let child;
    try {
      child = spawn(command, {
        cwd,
        env,
        shell: true,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      resolve({ code: null, signal: null, timedOut: false, durationMs: 0, output: String(err?.message ?? err) });
      return;
    }
    let timedOut = false;
    let exited = null;
    let settled = false;
    let grace;
    const killGroup = () => {
      try {
        if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {
        // already gone
      }
    };
    const finish = (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(grace);
      // A process that left the group (setsid, a daemon) can hold our pipes
      // open forever; stop listening rather than wait for it.
      child.stdout.destroy();
      child.stderr.destroy();
      child.unref();
      resolve({
        code,
        signal,
        timedOut,
        durationMs: Math.round(performance.now() - t0),
        output: tail(Buffer.concat(chunks)),
      });
    };
    const timer = setTimeout(() => {
      if (exited) return; // finished in time, only the pipes are still draining
      timedOut = true;
      killGroup();
      grace = setTimeout(() => finish(exited?.code ?? null, exited?.signal ?? 'SIGKILL'), STDIO_GRACE_MS);
    }, timeoutMs);
    child.stdout.on('data', keep);
    child.stderr.on('data', keep);
    child.on('error', (err) => {
      keep(Buffer.from(`\n${err.message}\n`));
      finish(null, null);
    });
    child.on('exit', (code, signal) => {
      exited = { code, signal };
      // The step is over: anything it left running in its group (a dev
      // server, a watcher) goes with it, so it cannot outlive the step or
      // keep the pipes open.
      killGroup();
      clearTimeout(grace);
      grace = setTimeout(() => finish(code, signal), STDIO_GRACE_MS);
    });
    child.on('close', (code, signal) => finish(exited?.code ?? code, exited?.signal ?? signal));
  });
}

function stepSummary(r) {
  return { exitCode: r.code, signal: r.signal, timedOut: r.timedOut, durationMs: r.durationMs, output: r.output };
}

// ── breakers ────────────────────────────────────────────────────────────────

/**
 * Apply a breaker's file-level changes to the copy. `env` is not applied here
 * — it only shapes the environment the setup and the check run with.
 * Returns null on success, or a step summary describing what went wrong.
 */
async function applyBreaker(breaker, tree, env, timeoutMs) {
  if (breaker.patch) {
    // --unsafe-paths is NOT passed: git apply refuses paths outside the tree.
    // Run from the copy with no repository around it, it behaves as plain
    // `patch -p1`, which is exactly what we want.
    const r = await runStep(`git apply --whitespace=nowarn ${JSON.stringify(breaker.patch)}`, {
      cwd: tree,
      env: { ...env, GIT_CEILING_DIRECTORIES: path.dirname(tree) },
      timeoutMs,
    });
    if (r.code !== 0 || r.timedOut) return { step: 'patch', ...stepSummary(r) };
  }
  for (const rep of breaker.replace ?? []) {
    const target = path.join(tree, rep.file);
    try {
      const content = rep.content ?? readFileSync(rep.contentFrom);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, content);
    } catch (err) {
      return { step: 'replace', exitCode: null, signal: null, timedOut: false, durationMs: 0, output: err.message };
    }
  }
  if (breaker.setup) {
    const r = await runStep(breaker.setup, { cwd: tree, env, timeoutMs });
    if (r.code !== 0 || r.timedOut) return { step: 'setup', ...stepSummary(r) };
  }
  return null;
}

// ── the run ─────────────────────────────────────────────────────────────────

/**
 * Run one check once inside a fresh copy, optionally broken first.
 */
async function runInCopy(config, check, breaker) {
  const { base, dest } = copyTree(config.root, config.exclude);
  try {
    const env = { ...process.env, ...(breaker?.env ?? {}) };
    if (breaker) {
      const broke = await applyBreaker(breaker, dest, env, check.timeoutMs);
      if (broke) return { breakerError: broke };
    }
    const r = await runStep(check.run, { cwd: dest, env, timeoutMs: check.timeoutMs });
    return { run: stepSummary(r), passed: r.code === 0 && !r.timedOut };
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

/**
 * @param {object} config   normalised config (see normaliseConfig)
 * @param {object} [hooks]  { onProgress?(event) } — for a live progress line
 * @returns {Promise<object>} the full result; see report.mjs for its shape
 */
export async function runGates(config, hooks = {}) {
  const progress = hooks.onProgress ?? (() => {});
  const t0 = performance.now();
  const hashBefore = hashTree(config.root, config.exclude);
  const checks = [];

  for (const check of config.checks) {
    progress({ check: check.name, step: 'baseline' });
    const baseline = await runInCopy(config, check, null);
    const result = { name: check.name, run: check.run, timeoutMs: check.timeoutMs, baseline: baseline.run, breakers: [] };

    if (!baseline.passed) {
      // No point breaking a check that is already red: every breaker would
      // "catch" and the report would show green rows for a worthless gate.
      result.verdict = BROKEN_BASELINE;
      result.reason = baseline.run.timedOut
        ? `timed out after ${check.timeoutMs}ms on the unmodified tree`
        : `exited ${baseline.run.exitCode ?? baseline.run.signal} on the unmodified tree`;
      checks.push(result);
      continue;
    }

    for (const breaker of check.breakers) {
      progress({ check: check.name, step: breaker.name });
      const r = await runInCopy(config, check, breaker);
      const row = { name: breaker.name };
      if (r.breakerError) {
        row.outcome = BREAKER_ERROR;
        row.reason = r.breakerError.timedOut
          ? `${r.breakerError.step} timed out after ${check.timeoutMs}ms`
          : `${r.breakerError.step} failed (exit ${r.breakerError.exitCode ?? r.breakerError.signal ?? 'n/a'})`;
        row.step = r.breakerError;
      } else if (r.run.timedOut) {
        // A hang is not a clean failure: it would also hang on a good tree
        // under load. Report it, do not count it as "caught".
        row.outcome = TIMEOUT;
        row.reason = `check timed out after ${check.timeoutMs}ms with the breaker applied`;
        row.run = r.run;
      } else if (r.passed) {
        row.outcome = CANNOT_FAIL;
        row.reason = 'check still passes with the subject broken';
        row.run = r.run;
      } else {
        row.outcome = CAUGHT;
        row.run = r.run;
      }
      result.breakers.push(row);
    }

    const outcomes = result.breakers.map((b) => b.outcome);
    if (outcomes.includes(CANNOT_FAIL)) result.verdict = CANNOT_FAIL;
    else if (outcomes.every((o) => o === CAUGHT)) result.verdict = CAN_FAIL;
    else result.verdict = INCONCLUSIVE;
    checks.push(result);
  }

  const hashAfter = hashTree(config.root, config.exclude);
  const summary = { total: checks.length, canFail: 0, cannotFail: 0, brokenBaseline: 0, inconclusive: 0 };
  for (const c of checks) {
    if (c.verdict === CAN_FAIL) summary.canFail += 1;
    else if (c.verdict === CANNOT_FAIL) summary.cannotFail += 1;
    else if (c.verdict === BROKEN_BASELINE) summary.brokenBaseline += 1;
    else summary.inconclusive += 1;
  }

  return {
    root: config.root,
    checks,
    summary,
    tree: { hashBefore, hashAfter, unchanged: hashBefore === hashAfter },
    durationMs: Math.round(performance.now() - t0),
  };
}

/** 0 only when every check can fail and the original tree is untouched. */
export function exitCode(result) {
  return result.summary.canFail === result.summary.total && result.tree.unchanged ? 0 : 1;
}
