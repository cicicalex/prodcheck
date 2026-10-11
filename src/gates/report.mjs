/**
 * Gate of gates — output.
 *
 * Same split as the scanner: a human report for the terminal and a JSON
 * document for CI. Like src/ui/theme.mjs, verdicts never rely on color alone:
 * every row carries its verdict as words, so the report survives NO_COLOR,
 * CI logs and piping to a file.
 *
 * This module imports theme.mjs, which decides color at load time, so the CLI
 * imports it dynamically after handling --no-color.
 */

import { style } from '../ui/theme.mjs';
import { BREAKER_ERROR, BROKEN_BASELINE, CANNOT_FAIL, CAN_FAIL, CAUGHT, TIMEOUT } from './engine.mjs';

const SCHEMA_VERSION = 1;
const OUTPUT_LINES = 12;

const TONE = {
  [CAN_FAIL]: style.green,
  [CAUGHT]: style.green,
  [CANNOT_FAIL]: style.red,
  [BROKEN_BASELINE]: style.red,
  [TIMEOUT]: style.yellow,
  [BREAKER_ERROR]: style.yellow,
};
const tone = (verdict) => (TONE[verdict] ?? style.yellow)(verdict);

function lastLines(output, n = OUTPUT_LINES) {
  const lines = String(output ?? '').replace(/\s+$/, '').split('\n');
  if (lines.length === 1 && lines[0] === '') return [];
  return lines.slice(-n);
}

function indent(lines, pad) {
  return lines.map((l) => `${pad}${style.dim('|')} ${l}`).join('\n');
}

export function renderReport(result) {
  const out = [''];
  for (const c of result.checks) {
    const glyph = c.verdict === CAN_FAIL ? 'ok' : '!!';
    out.push(`  ${glyph} ${tone(c.verdict)}  ${style.bold(c.name)}`);
    out.push(`     ${style.dim('$')} ${c.run}`);
    if (c.verdict === BROKEN_BASELINE) {
      out.push(`     baseline: ${c.reason}`);
      const lines = lastLines(c.baseline.output);
      if (lines.length) out.push(indent(lines, '     '));
      out.push('');
      continue;
    }
    out.push(`     baseline: passes ${style.dim(`(${c.baseline.durationMs}ms)`)}`);
    for (const b of c.breakers) {
      const ms = b.run ? style.dim(` (${b.run.durationMs}ms)`) : '';
      out.push(`     - ${tone(b.outcome)}  ${b.name}${ms}`);
      if (b.outcome !== CAUGHT) {
        out.push(`         ${b.reason}`);
        const lines = lastLines((b.step ?? b.run)?.output, b.outcome === CANNOT_FAIL ? 4 : OUTPUT_LINES);
        if (lines.length) out.push(indent(lines, '         '));
      }
    }
    out.push('');
  }

  const s = result.summary;
  const parts = [`${s.total} check${s.total === 1 ? '' : 's'}`, `${s.canFail} can fail`];
  if (s.cannotFail) parts.push(style.red(`${s.cannotFail} cannot fail`));
  if (s.brokenBaseline) parts.push(style.red(`${s.brokenBaseline} broken baseline`));
  if (s.inconclusive) parts.push(style.yellow(`${s.inconclusive} inconclusive`));
  parts.push(`${(result.durationMs / 1000).toFixed(1)}s`);

  out.push(`  ${'-'.repeat(74)}`);
  out.push(`  ${parts.join(' · ')}`);
  const t = result.tree;
  out.push(
    t.unchanged
      ? `  original tree unchanged · sha256 ${t.hashBefore.slice(0, 16)}`
      : style.red(`  !! ORIGINAL TREE CHANGED · sha256 ${t.hashBefore.slice(0, 16)} -> ${t.hashAfter.slice(0, 16)}`)
  );
  out.push('');
  return out.join('\n');
}

export function renderJson(result, meta = {}) {
  const doc = {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: 'prodcheck-gates', version: meta.version ?? null },
    config: meta.config ?? null,
    root: result.root,
    startedAt: meta.startedAt ?? null,
    durationMs: result.durationMs,
    summary: result.summary,
    tree: result.tree,
    checks: result.checks,
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}
