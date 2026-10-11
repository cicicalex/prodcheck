/**
 * Tests for the gate of gates (src/gates/).
 * node:test + node:assert only — the zero-dependency rule covers dev-time too.
 *
 * Every test builds its own small subject tree in a temp directory, so nothing
 * here depends on the rest of the repository except the last test, which runs
 * the repository's own gates.json against this checkout.
 *
 * The subject reproduces the incident the feature exists for: a `cap` value
 * that should come from config, and two gates over it — one that greps a
 * hard-coded `cap=262144` marker (and therefore cannot fail), and one that
 * actually computes the value.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BREAKER_ERROR,
  BROKEN_BASELINE,
  CANNOT_FAIL,
  CAN_FAIL,
  CAUGHT,
  INCONCLUSIVE,
  TIMEOUT,
  exitCode,
  hashTree,
  normaliseConfig,
  runGates,
} from '../src/gates/engine.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..');
const CLI = path.join(REPO, 'src', 'gates', 'cli.mjs');

const CAP_SOURCE = `export const config = { cap: 262144 };\n`;
const CAP_CHECK = `
import { config } from './src/config.mjs';
if (config.cap !== 262144) { console.error('cap is ' + config.cap); process.exit(1); }
console.log('cap ok');
`;

/** A fresh subject tree. Returns its root; removed by the caller's `t.after`. */
function makeSubject(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'gates-subject-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, 'src'));
  writeFileSync(path.join(root, 'src', 'config.mjs'), CAP_SOURCE);
  // The useless gate's evidence: a constant somebody typed once.
  writeFileSync(path.join(root, 'marker.txt'), 'cap=262144\n');
  writeFileSync(path.join(root, 'check-cap.mjs'), CAP_CHECK);
  writeFileSync(
    path.join(root, 'hang.mjs'),
    `import { writeFileSync } from 'node:fs';\n` +
      `if (process.env.PIDFILE) writeFileSync(process.env.PIDFILE, String(process.pid));\n` +
      `if (process.env.HANG) setInterval(() => {}, 1000);\n`
  );
  return root;
}

/** Independent of the engine's own hashTree: the proof must not trust the code it checks. */
function sha256Tree(root) {
  const h = createHash('sha256');
  const visit = (dir) => {
    for (const name of readdirSync(dir).sort()) {
      const abs = path.join(dir, name);
      const rel = path.relative(root, abs);
      const st = lstatSync(abs);
      h.update(`${rel}\0${st.mode}\0`);
      if (st.isSymbolicLink()) h.update(readlinkSync(abs));
      else if (st.isDirectory()) visit(abs);
      else h.update(readFileSync(abs));
    }
  };
  visit(root);
  return h.digest('hex');
}

/**
 * Alive means running: a killed grandchild is reparented and can sit as a
 * zombie until init reaps it, which is dead for every purpose that matters.
 */
function isAlive(pid) {
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  try {
    return !/^\d+ \(.*\) Z/.test(readFileSync(`/proc/${pid}/stat`, 'utf8'));
  } catch {
    return true; // no /proc: trust kill(0)
  }
}

const BREAK_CAP = { name: 'cap halved', replace: { file: 'src/config.mjs', content: 'export const config = { cap: 131072 };\n' } };

function config(root, checks, extra = {}) {
  return normaliseConfig({ timeoutMs: 20000, ...extra, checks }, root);
}

function runCli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', ...opts });
}

// ── verdicts ────────────────────────────────────────────────────────────────

test('a check that always passes is flagged CANNOT FAIL', async (t) => {
  const root = makeSubject(t);
  const result = await runGates(
    config(root, [{ name: 'marker says cap=262144', run: 'grep -q cap=262144 marker.txt', breakers: [BREAK_CAP] }])
  );
  const [c] = result.checks;
  assert.equal(c.verdict, CANNOT_FAIL);
  assert.equal(c.breakers[0].outcome, CANNOT_FAIL);
  assert.equal(result.summary.cannotFail, 1);
  assert.equal(exitCode(result), 1);
});

test('`true` is CANNOT FAIL under every kind of breaker', async (t) => {
  const root = makeSubject(t);
  const patchFile = path.join(root, '..', `${path.basename(root)}.patch`);
  writeFileSync(
    patchFile,
    '--- a/src/config.mjs\n+++ b/src/config.mjs\n@@ -1 +1 @@\n-export const config = { cap: 262144 };\n+export const config = { cap: 1 };\n'
  );
  t.after(() => rmSync(patchFile, { force: true }));
  const result = await runGates(
    config(root, [
      {
        name: 'always green',
        run: 'true',
        breakers: [
          BREAK_CAP,
          { name: 'patched', patch: patchFile },
          { name: 'env', env: { CAP: '1' } },
          { name: 'setup', setup: 'rm src/config.mjs' },
        ],
      },
    ])
  );
  assert.deepEqual(
    result.checks[0].breakers.map((b) => b.outcome),
    [CANNOT_FAIL, CANNOT_FAIL, CANNOT_FAIL, CANNOT_FAIL]
  );
  assert.equal(result.checks[0].verdict, CANNOT_FAIL);
});

test('a real check is accepted: passes unmodified, fails under each breaker kind', async (t) => {
  const root = makeSubject(t);
  const patchFile = path.join(root, '..', `${path.basename(root)}.patch`);
  writeFileSync(
    patchFile,
    '--- a/src/config.mjs\n+++ b/src/config.mjs\n@@ -1 +1 @@\n-export const config = { cap: 262144 };\n+export const config = { cap: 1 };\n'
  );
  t.after(() => rmSync(patchFile, { force: true }));
  const result = await runGates(
    config(root, [
      {
        name: 'cap is computed',
        // The env breaker needs a check that reads the environment.
        run: 'node check-cap.mjs && test -z "$CAP_OVERRIDE"',
        breakers: [
          BREAK_CAP,
          { name: 'patched', patch: patchFile },
          { name: 'env', env: { CAP_OVERRIDE: '1' } },
          { name: 'setup', setup: `sed -i 's/262144/7/' src/config.mjs` },
        ],
      },
    ])
  );
  const [c] = result.checks;
  assert.equal(c.verdict, CAN_FAIL, JSON.stringify(c, null, 2));
  assert.deepEqual(c.breakers.map((b) => b.outcome), [CAUGHT, CAUGHT, CAUGHT, CAUGHT]);
  assert.match(c.baseline.output, /cap ok/);
  assert.equal(exitCode(result), 0);
});

test('a check that fails on the unmodified tree is BROKEN BASELINE, and its breakers are not run', async (t) => {
  const root = makeSubject(t);
  const result = await runGates(
    config(root, [{ name: 'wrong expectation', run: 'grep -q cap=1 marker.txt', breakers: [BREAK_CAP] }])
  );
  const [c] = result.checks;
  assert.equal(c.verdict, BROKEN_BASELINE);
  assert.deepEqual(c.breakers, []);
  assert.equal(result.summary.brokenBaseline, 1);
  assert.equal(exitCode(result), 1);
});

test('a breaker that cannot be applied is BREAKER ERROR, never CAUGHT', async (t) => {
  const root = makeSubject(t);
  const patchFile = path.join(root, '..', `${path.basename(root)}-stale.patch`);
  writeFileSync(patchFile, '--- a/src/config.mjs\n+++ b/src/config.mjs\n@@ -1 +1 @@\n-no such line\n+x\n');
  t.after(() => rmSync(patchFile, { force: true }));
  const result = await runGates(
    config(root, [
      {
        name: 'cap is computed',
        run: 'node check-cap.mjs',
        breakers: [
          { name: 'stale patch', patch: patchFile },
          { name: 'failing setup', setup: 'exit 3' },
        ],
      },
    ])
  );
  const [c] = result.checks;
  assert.deepEqual(c.breakers.map((b) => b.outcome), [BREAKER_ERROR, BREAKER_ERROR]);
  assert.equal(c.verdict, INCONCLUSIVE);
  assert.equal(exitCode(result), 1);
});

// ── timeouts ────────────────────────────────────────────────────────────────

// Test-level timeouts: if the engine ever stops killing the process group,
// these must fail, not hang the suite.
test('a check that hangs under a breaker is TIMEOUT, killed at the per-step limit', { timeout: 15000 }, async (t) => {
  const root = makeSubject(t);
  const pidFile = path.join(root, '..', `${path.basename(root)}.pid`);
  t.after(() => rmSync(pidFile, { force: true }));
  const t0 = Date.now();
  const result = await runGates(
    config(root, [
      {
        name: 'hangs when told to',
        run: 'node hang.mjs',
        timeoutMs: 500,
        breakers: [{ name: 'hang', env: { HANG: '1', PIDFILE: pidFile } }],
      },
    ])
  );
  // Not just reported: the hung process is gone.
  const pid = Number(readFileSync(pidFile, 'utf8'));
  let alive = true;
  for (let i = 0; i < 50 && alive; i++) {
    alive = isAlive(pid);
    if (alive) await new Promise((r) => setTimeout(r, 100));
  }
  assert.equal(alive, false, `hung process ${pid} still alive`);
  const [c] = result.checks;
  assert.equal(c.breakers[0].outcome, TIMEOUT);
  assert.equal(c.breakers[0].run.timedOut, true);
  assert.equal(c.verdict, INCONCLUSIVE);
  assert.equal(exitCode(result), 1);
  assert.ok(Date.now() - t0 < 10000, 'the hung process group was killed, not waited out');
});

test('a baseline that hangs is BROKEN BASELINE with a timeout reason; --timeout overrides the config', { timeout: 15000 }, (t) => {
  const root = makeSubject(t);
  writeFileSync(
    path.join(root, 'gates.json'),
    JSON.stringify({ checks: [{ name: 'sleeps', run: 'sleep 30', breakers: [{ setup: 'true' }] }] })
  );
  const t0 = Date.now();
  const r = runCli([path.join(root, 'gates.json'), '--json', '--timeout', '400'], { timeout: 10000, killSignal: 'SIGKILL' });
  assert.equal(r.status, 1, r.stderr);
  assert.ok(Date.now() - t0 < 10000, 'sleep 30 was killed');
  const doc = JSON.parse(r.stdout);
  assert.equal(doc.checks[0].verdict, BROKEN_BASELINE);
  assert.equal(doc.checks[0].baseline.timedOut, true);
  assert.match(doc.checks[0].reason, /timed out after 400ms/);
});

// ── the original tree ───────────────────────────────────────────────────────

test('the original tree is byte-identical after a run that tries hard to damage it', async (t) => {
  const root = makeSubject(t);
  const before = sha256Tree(root);
  const result = await runGates(
    config(root, [
      {
        name: 'check that writes files',
        run: 'echo junk > junk.txt && rm marker.txt && node check-cap.mjs',
        breakers: [
          BREAK_CAP,
          { name: 'wipe', setup: 'rm -rf ./* && echo "export const config = {cap: 0}" > x.mjs' },
          { name: 'rewrite marker', setup: `printf 'cap=0\\n' > marker.txt && sed -i 's/262144/0/' src/config.mjs` },
        ],
      },
    ])
  );
  const after = sha256Tree(root);
  assert.equal(after, before, 'original tree changed');
  assert.equal(result.tree.unchanged, true);
  assert.equal(result.tree.hashBefore, result.tree.hashAfter);
  assert.equal(result.checks[0].verdict, CAN_FAIL);
  assert.equal(readFileSync(path.join(root, 'marker.txt'), 'utf8'), 'cap=262144\n');
});

test('hashTree sees a one-byte change', (t) => {
  const root = makeSubject(t);
  const a = hashTree(root);
  writeFileSync(path.join(root, 'marker.txt'), 'cap=262145\n');
  assert.notEqual(hashTree(root), a);
});

// ── config ──────────────────────────────────────────────────────────────────

test('config: a check with no breakers is rejected, not silently accepted', () => {
  assert.throws(() => normaliseConfig({ checks: [{ name: 'x', run: 'true', breakers: [] }] }, '/'), /at least one way/);
  assert.throws(() => normaliseConfig({ checks: [{ name: 'x', run: 'true' }] }, '/'), /breakers/);
});

test('config: unknown keys, empty breakers and escaping paths are rejected', () => {
  const one = (b) => ({ checks: [{ name: 'x', run: 'true', breakers: [b] }] });
  assert.throws(() => normaliseConfig({ ...one({ setup: 'true' }), chekcs: [] }, '/'), /unknown top-level key/);
  assert.throws(() => normaliseConfig(one({ name: 'nothing' }), '/'), /needs at least one of/);
  assert.throws(() => normaliseConfig(one({ envv: {} }), '/'), /unknown key "envv"/);
  assert.throws(() => normaliseConfig(one({ replace: { file: '../outside', content: '' } }), '/'), /inside the tree/);
  assert.throws(() => normaliseConfig(one({ replace: { file: '/etc/passwd', content: '' } }), '/'), /inside the tree/);
  assert.throws(() => normaliseConfig(one({ replace: { file: 'a', content: '', contentFrom: 'b' } }), '/'), /exactly one/);
  assert.throws(() => normaliseConfig(one({ env: { A: 1 } }), '/'), /must be a string/);
});

test('cli: bad config exits 2 with a message naming the problem', (t) => {
  const root = makeSubject(t);
  const cfg = path.join(root, 'gates.json');
  writeFileSync(cfg, JSON.stringify({ checks: [{ name: 'x', run: 'true', breakers: [] }] }));
  const r = runCli([cfg]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /prodcheck gates: config: checks\[0\]\.breakers/);
  assert.equal(runCli([path.join(root, 'missing.json')]).status, 2);
  assert.equal(runCli(['--bogus']).status, 2);
});

// ── cli output ──────────────────────────────────────────────────────────────

test('cli: report names CANNOT FAIL and CAN FAIL, JSON carries the same verdicts', (t) => {
  const root = makeSubject(t);
  const cfg = path.join(root, 'gates.json');
  writeFileSync(
    cfg,
    JSON.stringify({
      checks: [
        { name: 'useless marker gate', run: 'grep -q cap=262144 marker.txt', breakers: [BREAK_CAP] },
        { name: 'real cap gate', run: 'node check-cap.mjs', breakers: [BREAK_CAP] },
      ],
    })
  );
  const human = runCli([cfg, '--no-color']);
  assert.equal(human.status, 1);
  assert.match(human.stdout, /!! CANNOT FAIL {2}useless marker gate/);
  assert.match(human.stdout, /ok CAN FAIL {2}real cap gate/);
  assert.match(human.stdout, /- CANNOT FAIL {2}cap halved/);
  assert.match(human.stdout, /2 checks · 1 can fail · 1 cannot fail/);
  assert.match(human.stdout, /original tree unchanged · sha256 [0-9a-f]{16}/);
  assert.doesNotMatch(human.stdout, /\x1b\[/);

  const json = runCli([cfg, '--json']);
  assert.equal(json.status, 1);
  const doc = JSON.parse(json.stdout);
  assert.equal(doc.schemaVersion, 1);
  assert.deepEqual(doc.summary, { total: 2, canFail: 1, cannotFail: 1, brokenBaseline: 0, inconclusive: 0 });
  assert.deepEqual(doc.checks.map((c) => c.verdict), [CANNOT_FAIL, CAN_FAIL]);
  assert.equal(doc.tree.unchanged, true);
  assert.match(doc.tree.hashBefore, /^[0-9a-f]{64}$/);
});

test("the repository's own gates.json passes: every self-check can fail", () => {
  const before = sha256Tree(path.join(REPO, 'src'));
  // node --test marks its children with NODE_TEST_CONTEXT; a nested `node
  // --test` inside a gate would then report to this runner instead of exiting
  // with its own status.
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const r = runCli([path.join(REPO, 'gates.json'), '--json'], { env, cwd: REPO });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const doc = JSON.parse(r.stdout);
  assert.ok(doc.checks.length >= 2);
  for (const c of doc.checks) assert.equal(c.verdict, CAN_FAIL, c.name);
  assert.equal(doc.tree.unchanged, true);
  assert.equal(sha256Tree(path.join(REPO, 'src')), before);
});

test('a process that escapes the group and holds stdout open cannot hang the run', { timeout: 15000 }, async (t) => {
  const root = makeSubject(t);
  const t0 = Date.now();
  const result = await runGates(
    config(root, [
      {
        name: 'leaves a daemon behind',
        // setsid puts the sleeper in its own session, out of reach of the
        // group kill, and it inherits stdout: 'close' would never fire.
        run: 'setsid sleep 20 & node check-cap.mjs',
        timeoutMs: 5000,
        breakers: [BREAK_CAP],
      },
    ])
  );
  t.after(() => spawnSync('pkill', ['-f', '^sleep 20$']));
  assert.equal(result.checks[0].verdict, CAN_FAIL, JSON.stringify(result.checks[0], null, 2));
  assert.ok(Date.now() - t0 < 12000);
});
