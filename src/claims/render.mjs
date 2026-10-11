/**
 * Output for `prodcheck-claims verify`: a report for people, JSON for CI.
 *
 * Same rules as the scanner's report: status is a fixed-width column with a
 * word, not just a colour, so it survives NO_COLOR and CI logs; FAILs print
 * expected vs actual on their own line, because that line is the fix for the
 * page. JSON field names are a contract, versioned by `schemaVersion`.
 *
 * Imports theme.mjs, which reads the environment at load — import this module
 * dynamically, after --no-color has been applied (see cli.mjs).
 */

import { style } from '../ui/theme.mjs';

export const REPORT_SCHEMA_VERSION = 1;
const DETAIL_LIMIT = 10;

export function summarize(results) {
  const fail = results.filter((r) => r.status === 'FAIL').length;
  return { total: results.length, pass: results.length - fail, fail };
}

export function renderClaimsReport(results, meta) {
  const out = [''];
  const idWidth = Math.min(40, Math.max(...results.map((r) => r.id.length)));
  for (const r of results) {
    const tag = r.status === 'PASS' ? style.green('PASS') : style.red(style.bold('FAIL'));
    out.push(`  ${tag}  ${style.bold(r.id.padEnd(idWidth))}  ${style.dim(r.claim)}`);
    if (r.status === 'FAIL') {
      out.push(`        expected: ${r.expected}`);
      out.push(`        actual:   ${style.red(r.actual)}`);
      for (const d of r.details.slice(0, DETAIL_LIMIT)) out.push(`        ${style.dim(`- ${d}`)}`);
      if (r.details.length > DETAIL_LIMIT) out.push(`        ${style.dim(`… and ${r.details.length - DETAIL_LIMIT} more (see --json)`)}`);
    } else {
      out.push(`        ${style.dim(`${r.actual}`)}`);
    }
  }
  const s = summarize(results);
  out.push('');
  out.push(`  ${'-'.repeat(74)}`);
  const verdict = s.fail ? style.red(style.bold(`${s.fail} FAIL`)) : style.green('all pass');
  out.push(
    `  ${s.total} claims · ${s.pass} pass · ${verdict} · ${meta.source} (${meta.kind}, ${meta.files} files, ${meta.totalBytes.toLocaleString('en-US')} B)`
  );
  out.push('');
  return `${out.join('\n')}\n`;
}

export function renderClaimsJson(results, meta) {
  const payload = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: { name: 'prodcheck-claims', version: meta.version, vendor: 'Zero Point Logic' },
    source: { path: meta.source, kind: meta.kind, files: meta.files, totalBytes: meta.totalBytes },
    claimsFile: meta.claimsFile,
    pageFile: meta.pageFile ?? null,
    summary: summarize(results),
    results,
  };
  return `${JSON.stringify(payload, null, 2)}\n`;
}
