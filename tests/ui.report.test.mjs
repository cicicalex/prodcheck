/**
 * Tests for src/ui/report.mjs (renderReport, exitCode) and src/ui/help.mjs.
 *
 * theme.mjs detects color at MODULE LOAD TIME, and report/help import it, so
 * the env is pinned BEFORE any of these modules load: NO_COLOR is set here and
 * the modules come in through dynamic import() (static imports would hoist
 * above the assignment). Every rendering assertion below therefore runs
 * against the plain-text, no-ANSI code path.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.NO_COLOR = '1';
delete process.env.FORCE_COLOR;

const { renderReport, exitCode } = await import(
  new URL('../src/ui/report.mjs', import.meta.url).href
);
const { renderHelp } = await import(new URL('../src/ui/help.mjs', import.meta.url).href);

/** Minimal valid finding in the canonical shape (see demo.mjs). */
function finding(severity, overrides = {}) {
  return {
    severity,
    rule: `${severity}-rule`,
    file: 'src/app.ts',
    line: 1,
    impact: 'Something bad happens in production.',
    ...overrides,
  };
}

function report(findings, extra = {}) {
  return renderReport({ findings, filesScanned: 340, durationMs: 1200, ...extra });
}

// ---------------------------------------------------------------- exitCode()

test('exitCode: empty findings is 0 at every threshold', () => {
  for (const t of ['critical', 'high', 'medium', 'low', 'never']) {
    assert.equal(exitCode([], t), 0, `threshold ${t}`);
  }
});

test("exitCode: threshold 'never' is 0 even with critical findings", () => {
  assert.equal(exitCode([finding('critical'), finding('low')], 'never'), 0);
});

test("exitCode: threshold 'critical' fires only on critical", () => {
  assert.equal(exitCode([finding('critical')], 'critical'), 1);
  assert.equal(exitCode([finding('high')], 'critical'), 0);
  assert.equal(exitCode([finding('medium')], 'critical'), 0);
  assert.equal(exitCode([finding('low')], 'critical'), 0);
});

test("exitCode: threshold 'high' fires at high and above", () => {
  assert.equal(exitCode([finding('critical')], 'high'), 1);
  assert.equal(exitCode([finding('high')], 'high'), 1);
  assert.equal(exitCode([finding('medium')], 'high'), 0);
  assert.equal(exitCode([finding('low')], 'high'), 0);
});

test("exitCode: threshold 'medium' fires at medium and above", () => {
  assert.equal(exitCode([finding('high')], 'medium'), 1);
  assert.equal(exitCode([finding('medium')], 'medium'), 1);
  assert.equal(exitCode([finding('low')], 'medium'), 0);
});

test("exitCode: threshold 'low' fires on anything", () => {
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    assert.equal(exitCode([finding(sev)], 'low'), 1, sev);
  }
});

test("exitCode: default threshold is 'high'", () => {
  assert.equal(exitCode([finding('high')]), 1);
  assert.equal(exitCode([finding('critical')]), 1);
  assert.equal(exitCode([finding('medium')]), 0);
  assert.equal(exitCode([finding('low')]), 0);
});

test('exitCode: one qualifying finding among many below threshold still fires', () => {
  assert.equal(exitCode([finding('low'), finding('low'), finding('critical')], 'high'), 1);
});

// ------------------------------------------------------------ renderReport()

test('renderReport: no ANSI escapes anywhere under NO_COLOR', () => {
  const withFindings = report([
    finding('critical', { fix: { remove: ['old line'], add: ['new line'] } }),
    finding('low'),
  ]);
  const clean = report([]);
  assert.ok(!withFindings.includes('\x1b'), 'findings report leaked ANSI');
  assert.ok(!clean.includes('\x1b'), 'clean report leaked ANSI');
});

test("renderReport: clean state prints 'OK clean' when color is off", () => {
  const out = report([]);
  assert.ok(out.includes('OK clean'), out);
  assert.ok(out.includes('no issues found'), out);
  assert.ok(out.includes('340 files'), out);
  assert.ok(out.includes('1.2s'), out);
});

test('renderReport: orders critical before high before medium before low', () => {
  const out = report([
    finding('medium', { rule: 'rule-medium' }),
    finding('low', { rule: 'rule-low' }),
    finding('critical', { rule: 'rule-critical' }),
    finding('high', { rule: 'rule-high' }),
  ]);
  const at = (rule) => {
    const i = out.indexOf(rule);
    assert.ok(i !== -1, `missing ${rule}`);
    return i;
  };
  assert.ok(at('rule-critical') < at('rule-high'), 'critical before high');
  assert.ok(at('rule-high') < at('rule-medium'), 'high before medium');
  assert.ok(at('rule-medium') < at('rule-low'), 'medium before low');
});

test('renderReport: equal severity ties break by file A->Z', () => {
  const out = report([
    finding('critical', { rule: 'rule-zebra', file: 'src/zebra.ts' }),
    finding('critical', { rule: 'rule-alpha', file: 'src/alpha.ts' }),
    finding('critical', { rule: 'rule-middle', file: 'src/middle.ts' }),
  ]);
  const at = (rule) => out.indexOf(rule);
  assert.ok(at('rule-alpha') < at('rule-middle'), 'alpha before middle');
  assert.ok(at('rule-middle') < at('rule-zebra'), 'middle before zebra');
});

test('renderReport: does not mutate the findings array it is given', () => {
  const input = [finding('low', { rule: 'r1' }), finding('critical', { rule: 'r2' })];
  report(input);
  assert.deepEqual(
    input.map((f) => f.rule),
    ['r1', 'r2'],
    'input order must be untouched'
  );
});

test('renderReport: summary line carries issue count, critical count, files, duration', () => {
  const out = report([
    finding('critical'),
    finding('critical', { file: 'src/b.ts' }),
    finding('high'),
    finding('medium'),
  ]);
  assert.ok(out.includes('4 issues'), out);
  assert.ok(out.includes('2 critical'), out);
  assert.ok(out.includes('340 files'), out);
  assert.ok(out.includes('1.2s'), out);
});

test('renderReport: singular form for one issue, no critical segment when none', () => {
  const out = report([finding('medium')]);
  assert.ok(out.includes('1 issue'), out);
  assert.ok(!out.includes('1 issues'), out);
  assert.ok(!out.includes('critical'), 'no critical count when there are none');
});

test('renderReport: location is a linkifiable path:line on its own line', () => {
  const out = report([finding('high', { file: 'src/middleware.ts', line: 18 })]);
  const lines = out.split('\n');
  assert.ok(
    lines.some((l) => l.trim() === 'src/middleware.ts:18'),
    `expected a standalone location line in:\n${out}`
  );
});

test('renderReport: fix diff prints remove as "- " and add as "+ " lines', () => {
  const out = report([
    finding('critical', {
      fix: { remove: ['const a = 1'], add: ['const a = 2', 'log(a)'] },
    }),
  ]);
  assert.ok(out.includes('- const a = 1'), out);
  assert.ok(out.includes('+ const a = 2'), out);
  assert.ok(out.includes('+ log(a)'), out);
});

test('renderReport: impact prose appears in the output', () => {
  const out = report([finding('low', { impact: 'A very specific impact sentence.' })]);
  assert.ok(out.includes('A very specific impact sentence.'), out);
});

test('renderReport: uses ASCII rule (not box drawing) when color is off', () => {
  const out = report([finding('low')]);
  assert.ok(!out.includes('─'), 'box-drawing char leaked into no-color output');
  assert.ok(/-{10,}/.test(out), 'expected an ASCII dash rule');
});

test('renderReport: upsell row appears only when lockedChecks > 0', () => {
  const withUpsell = report([finding('low')], { lockedChecks: 4 });
  assert.ok(withUpsell.includes('4 more checks designed, not built yet'), withUpsell);
  assert.ok(withUpsell.includes('designed, not built yet'), withUpsell);
  const without = report([finding('low')]);
  assert.ok(!without.includes('designed, not built yet'), without);
});

// -------------------------------------------------------------- renderHelp()

test('renderHelp: contains USAGE, EXAMPLES, OPTIONS and EXIT CODES sections', () => {
  const out = renderHelp('1.2.3');
  for (const section of ['USAGE', 'EXAMPLES', 'OPTIONS', 'EXIT CODES']) {
    assert.ok(out.includes(section), `missing section ${section}`);
  }
});

test('renderHelp: shows the version it was given', () => {
  assert.ok(renderHelp('9.9.9').includes('v9.9.9'));
});

test('renderHelp: fits in <= 24 lines (one terminal height, no scrolling)', () => {
  const out = renderHelp('1.2.3');
  const rows = out.replace(/\n$/, '').split('\n').length;
  assert.ok(rows <= 24, `help is ${rows} rows`);
});

test('renderHelp: no ANSI escapes under NO_COLOR', () => {
  assert.ok(!renderHelp('1.2.3').includes('\x1b'));
});

test('renderHelp: documents the flags and all severity thresholds', () => {
  const out = renderHelp('1.2.3');
  for (const s of ['--fail-on', '--json', '--no-color', '--version', '--help']) {
    assert.ok(out.includes(s), `missing flag ${s}`);
  }
  for (const level of ['critical', 'high', 'medium', 'low', 'never']) {
    assert.ok(out.includes(level), `missing threshold ${level}`);
  }
});

test('renderHelp: documents exit codes 0, 1 and 2', () => {
  const out = renderHelp('1.2.3');
  assert.ok(out.includes('0 clean'), out);
  assert.ok(/1 findings/.test(out), out);
  assert.ok(/2 scan failed/.test(out), out);
});
