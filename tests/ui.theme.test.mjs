/**
 * Tests for src/ui/theme.mjs.
 *
 * Color detection runs at MODULE LOAD TIME, so this file pins the env FIRST
 * and only then loads the module via dynamic import(). A static import would
 * hoist above the env assignment and capture whatever env the runner has.
 * Env-variant behavior (FORCE_COLOR, TERM=dumb, ...) is exercised in child
 * processes, one fresh module load per env.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

process.env.NO_COLOR = '1';
delete process.env.FORCE_COLOR;

const themeUrl = new URL('../src/ui/theme.mjs', import.meta.url).href;
const { style, SEVERITY, SEVERITY_COL, colorEnabled, width, wrap } = await import(themeUrl);

/** Load theme.mjs in a child process with a controlled env; return colorEnabled. */
function colorEnabledIn(overrides) {
  const env = { ...process.env };
  // Start from a neutral slate: none of the vars that drive detection.
  delete env.NO_COLOR;
  delete env.FORCE_COLOR;
  delete env.TERM;
  Object.assign(env, overrides);
  const script = `const m = await import(${JSON.stringify(themeUrl)}); process.stdout.write(String(m.colorEnabled));`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, `child failed: ${r.stderr}`);
  return r.stdout.trim();
}

/** Temporarily force process.stdout.columns to a value. */
function withColumns(value, fn) {
  const had = Object.getOwnPropertyDescriptor(process.stdout, 'columns');
  Object.defineProperty(process.stdout, 'columns', { value, configurable: true, writable: true });
  try {
    return fn();
  } finally {
    if (had) Object.defineProperty(process.stdout, 'columns', had);
    else delete process.stdout.columns;
  }
}

// ---------------------------------------------------------------- wrap()

test('wrap: empty string produces no lines', () => {
  assert.deepEqual(wrap('', 40), []);
});

test('wrap: whitespace-only string produces no lines', () => {
  assert.deepEqual(wrap('   \n\t  ', 40), []);
});

test('wrap: single word longer than max stays whole on its own line', () => {
  // Greedy word wrap never splits inside a word; an overlong word overflows.
  assert.deepEqual(wrap('supercalifragilistic', 5), ['supercalifragilistic']);
});

test('wrap: overlong word between short words gets its own line', () => {
  assert.deepEqual(wrap('a extraordinarily b', 6), ['a', 'extraordinarily', 'b']);
});

test('wrap: exact-width fit stays on one line', () => {
  // 'abc def' is exactly 7 chars — the boundary is inclusive.
  assert.deepEqual(wrap('abc def', 7), ['abc def']);
});

test('wrap: one char over the exact fit breaks the line', () => {
  assert.deepEqual(wrap('abcd efg', 7), ['abcd', 'efg']);
});

test('wrap: multi-line result wraps greedily', () => {
  assert.deepEqual(wrap('one two three four', 9), ['one two', 'three', 'four']);
});

test('wrap: every produced line fits max (except unsplittable words)', () => {
  const text = 'The catch block returns 200 without re-throwing so the event is lost forever';
  const lines = wrap(text, 20);
  assert.ok(lines.length > 1);
  for (const line of lines) assert.ok(line.length <= 20, `line too long: "${line}"`);
  // No content lost and no pre-indentation.
  assert.equal(lines.join(' '), text);
  for (const line of lines) assert.ok(!/^\s|\s$/.test(line), `line has edge whitespace: "${line}"`);
});

test('wrap: collapses internal whitespace runs and newlines', () => {
  assert.deepEqual(wrap('a\n  b\t\tc', 80), ['a b c']);
});

test('wrap: coerces non-string input', () => {
  assert.deepEqual(wrap(12345, 80), ['12345']);
});

// ---------------------------------------------------------------- tokens

test('SEVERITY: weights order critical < high < medium < low', () => {
  assert.ok(SEVERITY.critical.weight < SEVERITY.high.weight);
  assert.ok(SEVERITY.high.weight < SEVERITY.medium.weight);
  assert.ok(SEVERITY.medium.weight < SEVERITY.low.weight);
});

test('SEVERITY: every level carries a label and a 2-char ASCII glyph', () => {
  for (const [name, sev] of Object.entries(SEVERITY)) {
    assert.equal(typeof sev.label, 'string', name);
    assert.equal(sev.glyph.length, 2, `glyph width must be uniform for column alignment: ${name}`);
    assert.ok(/^[\x20-\x7e]+$/.test(sev.glyph), `glyph must be ASCII: ${name}`);
    assert.equal(typeof sev.color, 'function', name);
  }
});

test('SEVERITY_COL is the widest label (CRITICAL = 8)', () => {
  assert.equal(SEVERITY_COL, 8);
  assert.equal(
    SEVERITY_COL,
    Math.max(...Object.values(SEVERITY).map((s) => s.label.length))
  );
});

// ------------------------------------------------- color off in this process

test('colorEnabled is false under NO_COLOR', () => {
  assert.equal(colorEnabled, false);
});

test('style functions are identity when color is off — no ANSI escapes', () => {
  for (const [name, fn] of Object.entries(style)) {
    const out = fn('text');
    assert.equal(out, 'text', `style.${name} must pass through untouched`);
    assert.ok(!out.includes('\x1b'), `style.${name} leaked an escape`);
  }
});

// ------------------------------------------- env matrix via child processes

test('color detection: NO_COLOR=1 disables color', () => {
  assert.equal(colorEnabledIn({ NO_COLOR: '1' }), 'false');
});

test('color detection: FORCE_COLOR=1 enables color even when piped', () => {
  // Child stdout is a pipe (not a TTY); FORCE_COLOR must still win.
  assert.equal(colorEnabledIn({ FORCE_COLOR: '1' }), 'true');
});

test('color detection: FORCE_COLOR beats NO_COLOR (ecosystem precedence)', () => {
  assert.equal(colorEnabledIn({ FORCE_COLOR: '1', NO_COLOR: '1' }), 'true');
});

test('color detection: FORCE_COLOR=0 disables color', () => {
  assert.equal(colorEnabledIn({ FORCE_COLOR: '0' }), 'false');
});

test('color detection: TERM=dumb disables color', () => {
  assert.equal(colorEnabledIn({ TERM: 'dumb' }), 'false');
});

test('color detection: FORCE_COLOR overrides TERM=dumb', () => {
  assert.equal(colorEnabledIn({ FORCE_COLOR: '1', TERM: 'dumb' }), 'true');
});

test('color detection: piped stdout with clean env disables color', () => {
  assert.equal(colorEnabledIn({}), 'false');
});

test('style emits SGR sequences when color is forced on', () => {
  const env = { ...process.env };
  delete env.NO_COLOR;
  delete env.TERM;
  env.FORCE_COLOR = '1';
  const script = `const m = await import(${JSON.stringify(themeUrl)}); process.stdout.write(m.style.red('x'));`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, '\x1b[31mx\x1b[39m');
});

// ---------------------------------------------------------------- width()

test('width: always within [40, 76]', () => {
  const w = width();
  assert.ok(Number.isInteger(w));
  assert.ok(w >= 40 && w <= 76, `width ${w} out of bounds`);
});

test('width: caps wide terminals at 76', () => {
  assert.equal(withColumns(200, width), 76);
});

test('width: passes through a mid-range terminal', () => {
  assert.equal(withColumns(60, width), 60);
});

test('width: floors narrow terminals at 40', () => {
  assert.equal(withColumns(10, width), 40);
});

test('width: falls back to 80 columns (capped to 76) when columns is unknown', () => {
  assert.equal(withColumns(undefined, width), 76);
  assert.equal(withColumns(0, width), 76);
});
