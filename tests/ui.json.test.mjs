/**
 * Tests for src/ui/json.mjs (renderJson, SCHEMA_VERSION).
 *
 * json.mjs has no color/env dependence, so a static import is safe here.
 * These assertions treat the JSON output as the public API it is: field
 * names, path normalisation, precomputed summary, trailing newline.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderJson, SCHEMA_VERSION } from '../src/ui/json.mjs';

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

function parsed(findings, meta) {
  const out = renderJson({ findings, filesScanned: 340, durationMs: 1200 }, meta);
  return JSON.parse(out);
}

test('SCHEMA_VERSION export is 1 and matches the payload', () => {
  assert.equal(SCHEMA_VERSION, 1);
  assert.equal(parsed([]).schemaVersion, 1);
});

test('schemaVersion is the first key so consumers can reject early', () => {
  const out = renderJson({ findings: [], filesScanned: 0, durationMs: 0 });
  assert.equal(Object.keys(JSON.parse(out))[0], 'schemaVersion');
});

test('output is valid JSON with exactly one trailing newline', () => {
  const out = renderJson(
    { findings: [finding('critical')], filesScanned: 1, durationMs: 10 },
    { version: '1.0.0', root: '.', startedAt: '2026-08-14T20:00:00.000Z' }
  );
  assert.doesNotThrow(() => JSON.parse(out));
  assert.ok(out.endsWith('\n'), 'missing trailing newline');
  assert.ok(!out.endsWith('\n\n'), 'more than one trailing newline');
});

test("tool block: name 'prodcheck', vendor 'Zero Point Logic', version passthrough", () => {
  const { tool } = parsed([], { version: '2.3.4' });
  assert.deepEqual(tool, { name: 'prodcheck', version: '2.3.4', vendor: 'Zero Point Logic' });
});

test('meta defaults: version 0.0.0, root ".", startedAt null', () => {
  const { tool, scan } = parsed([]);
  assert.equal(tool.version, '0.0.0');
  assert.equal(scan.root, '.');
  assert.equal(scan.startedAt, null);
});

test('scan block carries filesScanned and durationMs', () => {
  const { scan } = parsed([], { startedAt: '2026-08-14T20:00:00.000Z' });
  assert.equal(scan.filesScanned, 340);
  assert.equal(scan.durationMs, 1200);
  assert.equal(scan.startedAt, '2026-08-14T20:00:00.000Z');
});

test('windows path normalisation: finding files become POSIX', () => {
  const { findings } = parsed([finding('high', { file: 'src\\api\\x.ts' })]);
  assert.equal(findings[0].file, 'src/api/x.ts');
});

test('windows path normalisation: scan.root becomes POSIX', () => {
  const { scan } = parsed([], { root: 'C:\\Dev\\Proiecte\\prodcheck' });
  assert.equal(scan.root, 'C:/Dev/Proiecte/prodcheck');
});

test('path normalisation strips a leading ./', () => {
  const { findings, scan } = parsed([finding('low', { file: './src/a.ts' })], { root: '.\\src' });
  assert.equal(findings[0].file, 'src/a.ts');
  assert.equal(scan.root, 'src');
});

test('summary counts match the findings, zero-filled for absent severities', () => {
  const { summary } = parsed([
    finding('critical'),
    finding('critical'),
    finding('high'),
    finding('medium'),
  ]);
  assert.deepEqual(summary, { total: 4, critical: 2, high: 1, medium: 1, low: 0 });
});

test('summary for a clean run is all zeroes', () => {
  assert.deepEqual(parsed([]).summary, { total: 0, critical: 0, high: 0, medium: 0, low: 0 });
});

test('summary.total equals findings.length', () => {
  const list = [finding('low'), finding('low'), finding('high')];
  const p = parsed(list);
  assert.equal(p.summary.total, p.findings.length);
  assert.equal(p.summary.total, list.length);
});

test('every finding carries a docs URL derived from its rule', () => {
  const { findings } = parsed([
    finding('critical', { rule: 'webhook-swallows-2xx' }),
    finding('high', { rule: 'rate-limit-bypass' }),
  ]);
  assert.equal(findings[0].docs, 'https://github.com/cicicalex/prodcheck/blob/main/docs/rules/webhook-swallows-2xx.md');
  assert.equal(findings[1].docs, 'https://github.com/cicicalex/prodcheck/blob/main/docs/rules/rate-limit-bypass.md');
});

test('finding fields pass through: rule, severity, line, impact', () => {
  const [f] = parsed([
    finding('medium', { rule: 'account-delete-blocked', line: 96, impact: 'GDPR says no.' }),
  ]).findings;
  assert.equal(f.rule, 'account-delete-blocked');
  assert.equal(f.severity, 'medium');
  assert.equal(f.line, 96);
  assert.equal(f.impact, 'GDPR says no.');
});

test('column defaults to null and passes through when present', () => {
  const { findings } = parsed([finding('low'), finding('low', { column: 7 })]);
  assert.equal(findings[0].column, null);
  assert.equal(findings[1].column, 7);
});

test('fix is null when absent, and normalised to {remove, add} arrays when present', () => {
  const { findings } = parsed([
    finding('low'),
    finding('high', { fix: { remove: ['old'] } }),
    finding('critical', { fix: { remove: ['a'], add: ['b', 'c'] } }),
  ]);
  assert.equal(findings[0].fix, null);
  assert.deepEqual(findings[1].fix, { remove: ['old'], add: [] });
  assert.deepEqual(findings[2].fix, { remove: ['a'], add: ['b', 'c'] });
});

test('output is pretty-printed (2-space indent) for human debugging', () => {
  const out = renderJson({ findings: [], filesScanned: 0, durationMs: 0 });
  assert.ok(out.includes('\n  "schemaVersion"'), 'expected two-space indentation');
});
