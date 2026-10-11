/**
 * Tests for the nondeterminism detector (src/nondet/, src/nondet-cli.mjs).
 * node:test + node:assert only — the zero-dependency rule covers dev-time too.
 *
 * The end-to-end cases run real Python scripts from tests/fixtures/nondet/,
 * because the bug this detector exists for is CPython's per-process string
 * hash randomization; a JavaScript stand-in would prove nothing about it. When
 * no python3 is on PATH those cases are skipped with that reason, never passed
 * silently.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { minimalDiff } from '../src/nondet/diff.mjs';
import { buildDimensions, compare } from '../src/nondet/detect.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, 'fixtures', 'nondet');
const CLI = path.join(HERE, '..', 'src', 'nondet-cli.mjs');

const PYTHON = ['python3', 'python'].find((p) => spawnSync(p, ['--version']).status === 0);
const needsPython = PYTHON ? {} : { skip: 'python3 not found on PATH' };

/** Run the CLI with the fixtures directory as --workdir; parse --json. */
function runCli(flags, script, extra = []) {
  const res = spawnSync(
    process.execPath,
    [CLI, '--json', '--workdir', FIXTURES, ...flags, '--', PYTHON, script, ...extra],
    { encoding: 'utf8' }
  );
  let json = null;
  try {
    json = JSON.parse(res.stdout);
  } catch {
    // leave null; the assertion on status will show stderr
  }
  return { status: res.status, json, stdout: res.stdout, stderr: res.stderr };
}

// ── diff ────────────────────────────────────────────────────────────────────

test('minimalDiff is empty for equal input', () => {
  assert.equal(minimalDiff('a\nb\n', 'a\nb\n'), '');
});

test('minimalDiff shows only the changed line with context', () => {
  const d = minimalDiff('1\n2\n3\n4\n5\n6\n', '1\n2\n3\nX\n5\n6\n');
  assert.equal(d, ['@@ line 4 @@', '  2', '  3', '- 4', '+ X', '  5', '  6'].join('\n'));
});

test('minimalDiff names a trailing-newline-only difference', () => {
  assert.match(minimalDiff('a\n', 'a'), /trailing newline/);
});

// ── engine units ────────────────────────────────────────────────────────────

test('hash seeds include 0 (baseline) and the literal random, and --seed replays them', () => {
  const a = buildDimensions({ runs: 8, seed: 42, varyTz: false, varyLocale: false, varyEnv: [] });
  const b = buildDimensions({ runs: 8, seed: 42, varyTz: false, varyLocale: false, varyEnv: [] });
  assert.equal(a.length, 1);
  assert.equal(a[0].values.length, 8);
  assert.equal(a[0].values[0], '0');
  assert.equal(a[0].values[1], 'random');
  assert.deepEqual(a[0].values, b[0].values);
  for (const v of a[0].values.slice(2)) {
    const n = Number(v);
    assert.ok(Number.isInteger(n) && n >= 1 && n <= 4294967295, v);
  }
});

test('optional dimensions: TZ, locale (LC_ALL + LANG) and user env vars', () => {
  const dims = buildDimensions({ runs: 4, seed: 1, varyTz: true, varyLocale: true, varyEnv: [['WORKERS', ['1', '4']]] });
  assert.deepEqual(dims.map((d) => d.name), ['PYTHONHASHSEED', 'TZ', 'locale', 'env:WORKERS']);
  assert.deepEqual(dims[2].vars, ['LC_ALL', 'LANG']);
  assert.deepEqual(dims[3].values, ['1', '4']);
});

test('compare reports a missing output file and a binary file by hash', () => {
  const base = { exit: 'exit 0', stdout: '', stderr: '', files: { a: { present: true, sha256: 'x', rawSha256: 'x', text: null } } };
  const gone = { ...base, files: { a: { present: false } } };
  assert.deepEqual(compare(base, gone).map((d) => d.aspect), ['file:a']);
  assert.match(compare(base, gone)[0].diff, /- present\n\+ missing/);
  const other = { ...base, files: { a: { present: true, sha256: 'y', rawSha256: 'y', text: null } } };
  assert.match(compare(base, other)[0].diff, /sha256 x\n\+ sha256 y/);
});

// ── end to end ──────────────────────────────────────────────────────────────

test('flags a set-order-dependent script and blames PYTHONHASHSEED', needsPython, () => {
  const { status, json, stderr } = runCli(['--seed', '7'], 'set_order.py');
  assert.equal(status, 1, stderr);
  assert.equal(json.verdict, 'nondeterministic');
  assert.equal(json.runs.length, 8);
  assert.equal(json.intrinsic, false, 'the identical control run must match the baseline');
  assert.equal(json.runs[0].env.PYTHONHASHSEED, '0');
  assert.equal(json.runs[2].env.PYTHONHASHSEED, 'random');
  const differing = json.runs.filter((r) => r.differences.length > 0);
  assert.ok(differing.length >= 1);
  for (const r of differing) assert.deepEqual(r.differences.map((d) => d.aspect), ['stdout']);
  // The order line, not the category: one of eight tags comes first, so the
  // picked category can coincide with the baseline even when the order moved.
  assert.match(differing[0].differences[0].diff, /^- order: /m);
  assert.match(differing[0].differences[0].diff, /^\+ order: /m);
  assert.equal(json.isolation.length, 1);
  assert.equal(json.isolation[0].dimension, 'PYTHONHASHSEED');
  assert.equal(json.isolation[0].reproduced, true);
});

test('the human-readable report names the run, the diff and the verdict', needsPython, () => {
  const res = spawnSync(process.execPath, [CLI, '--no-color', '--seed', '7', '--workdir', FIXTURES, '--', PYTHON, 'set_order.py'], { encoding: 'utf8' });
  assert.equal(res.status, 1, res.stderr);
  assert.match(res.stdout, /seed 7/);
  assert.match(res.stdout, /difference: run 3 vs baseline \(changed: PYTHONHASHSEED\)/);
  assert.match(res.stdout, /PYTHONHASHSEED=\d+ {2}alone reproduces: stdout/);
  assert.match(res.stdout, /NONDETERMINISTIC/);
});

test('a set-order difference only in a declared output file is flagged', needsPython, () => {
  const { status, json, stderr } = runCli(['--output', 'out'], 'set_order_file.py');
  assert.equal(status, 1, stderr);
  const differing = json.runs.filter((r) => r.differences.length > 0);
  assert.ok(differing.length >= 1);
  assert.deepEqual(differing[0].differences.map((d) => d.aspect), ['file:out/result.txt']);
});

test('a deterministic script passes, and runs cannot see each other\'s output files', needsPython, () => {
  // deterministic.py APPENDS to out/result.txt: had any two runs shared a
  // directory, the later run's file would carry two lines and differ.
  const { status, json, stderr } = runCli(['--output', 'out', '--vary-tz', '--vary-locale', '--vary-env', 'FOO=a,b'], 'deterministic.py');
  assert.equal(status, 0, stderr);
  assert.equal(json.verdict, 'deterministic');
  const hashes = new Set(json.runs.map((r) => r.files['out/result.txt']));
  assert.equal(hashes.size, 1);
  assert.ok([...hashes][0], 'the output file must exist');
});

test('a timestamp-only difference is flagged without, and suppressed with, --normalize', needsPython, () => {
  const raw = runCli(['--runs', '3'], 'timestamp.py');
  assert.equal(raw.status, 1, raw.stderr);
  assert.equal(raw.json.intrinsic, true, 'the control run already differs: the clock, not a perturbation');
  assert.equal(raw.json.isolation.length, 0);

  const norm = runCli(['--runs', '3', '--normalize', String.raw`\d{4}-\d\d-\d\dT[\d:.]+`], 'timestamp.py');
  assert.equal(norm.status, 0, norm.stderr);
  assert.equal(norm.json.verdict, 'deterministic');
});

test('a run that exceeds --timeout is reported and the verdict is incomplete (exit 2)', needsPython, () => {
  const t0 = Date.now();
  const { status, json, stderr } = runCli(['--runs', '2', '--timeout', '0.5'], 'sleep.py');
  assert.equal(status, 2, stderr);
  assert.equal(json.verdict, 'incomplete');
  assert.ok(json.runs.every((r) => r.timedOut));
  assert.ok(Date.now() - t0 < 15_000, 'the sleeping script (30s) must be killed, not waited for');
});

test('a command that does not start is incomplete, not deterministic', () => {
  const res = spawnSync(process.execPath, [CLI, '--json', '--runs', '2', '--', 'prodcheck-no-such-command-xyz'], { encoding: 'utf8' });
  assert.equal(res.status, 2);
  assert.equal(JSON.parse(res.stdout).verdict, 'incomplete');
});

test('bad flags exit 2 with a message', () => {
  for (const args of [['--runs', '1', '--', 'true'], ['--output', '../x', '--', 'true'], ['--normalize', '(', '--', 'true'], ['--vary-env', 'FOO', '--', 'true'], []]) {
    const res = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
    assert.equal(res.status, 2, args.join(' '));
    assert.match(res.stderr, /^prodcheck-nondet: /);
  }
});
