#!/usr/bin/env node
/**
 * prodcheck-claims — PAGE CLAIMS = SHIPPED BYTES.
 *
 *   prodcheck-claims verify   <archive.zip|dir> --claims <claims.json> [--page <page.txt|.html>] [--json] [--no-color]
 *   prodcheck-claims generate <archive.zip|dir> [--out <claims.json>] [--facts]
 *
 * A separate entrypoint from the scanner on purpose: it checks a product
 * archive, not source code, and shares nothing with the scan walk but the
 * terminal theme. As in src/cli.mjs, ui modules are imported only after
 * --no-color has been applied, because theme.mjs decides colour at load.
 *
 * Exit contract (same as the scanner):
 *   0 — every claim PASS (or generate succeeded)
 *   1 — at least one claim FAIL
 *   2 — the run itself failed (bad path, bad claims file, corrupt zip header, bad flag)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const USAGE = `usage:
  prodcheck-claims verify   <archive.zip|dir> --claims <claims.json> [--page <page.txt|.html>] [--json] [--no-color]
  prodcheck-claims generate <archive.zip|dir> [--out <claims.json>] [--facts]

exit codes: 0 all claims pass · 1 a claim failed · 2 the run failed
`;

function parseArgs(argv) {
  const opts = { command: null, target: null, claims: null, page: null, out: null, json: false, noColor: false, facts: false, help: false };
  const positionals = [];
  const value = (i, name) => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) throw new Error(`${name} expects a file path`);
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--no-color') opts.noColor = true;
    else if (a === '--facts') opts.facts = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--claims') opts.claims = value(i++, a);
    else if (a === '--page') opts.page = value(i++, a);
    else if (a === '--out' || a === '-o') opts.out = value(i++, a);
    else if (a.startsWith('-')) throw new Error(`unknown option: ${a}`);
    else positionals.push(a);
  }
  if (opts.help) return opts;
  [opts.command, opts.target] = positionals;
  if (positionals.length !== 2 || !['verify', 'generate'].includes(opts.command)) {
    throw new Error(`expected a command and one path\n${USAGE}`);
  }
  if (opts.command === 'verify' && !opts.claims) throw new Error('verify needs --claims <file>');
  return opts;
}

function readJson(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    throw new Error(`cannot read claims file: ${file}`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`${file}: not valid JSON (${err.message})`);
  }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.noColor) process.env.NO_COLOR = '1';
  if (opts.help) {
    process.stdout.write(USAGE);
    return;
  }

  const { loadSource } = await import('./source.mjs');
  const source = loadSource(opts.target);

  if (opts.command === 'generate') {
    const { generateClaims, pageFacts } = await import('./generate.mjs');
    if (opts.facts) {
      if (source.problems.length) throw new Error(`source has integrity problems:\n  ${source.problems.join('\n  ')}`);
      process.stdout.write(pageFacts(source));
      return;
    }
    const json = `${JSON.stringify(generateClaims(source), null, 2)}\n`;
    if (opts.out) writeFileSync(opts.out, json);
    else process.stdout.write(json);
    return;
  }

  const { parseClaims, verifyClaims, htmlToText } = await import('./verify.mjs');
  let claims;
  try {
    claims = parseClaims(readJson(opts.claims));
  } catch (err) {
    throw new Error(err.message.startsWith('claims') ? `${opts.claims}: ${err.message}` : err.message);
  }
  let pageText = null;
  if (opts.page) {
    try {
      pageText = readFileSync(opts.page, 'utf8');
    } catch {
      throw new Error(`cannot read page file: ${opts.page}`);
    }
    if (/\.html?$/i.test(opts.page)) pageText = htmlToText(pageText);
  }
  const results = verifyClaims(claims, source, pageText);

  const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
  const meta = {
    version: pkg.version,
    source: opts.target.split(path.sep).join('/'),
    kind: source.kind,
    files: source.files.length,
    totalBytes: source.files.reduce((s, f) => s + f.size, 0),
    claimsFile: opts.claims,
    pageFile: opts.page,
  };
  const { renderClaimsReport, renderClaimsJson } = await import('./render.mjs');
  process.stdout.write(opts.json ? renderClaimsJson(results, meta) : renderClaimsReport(results, meta));
  process.exitCode = results.some((r) => r.status === 'FAIL') ? 1 : 0;
}

main().catch((err) => {
  process.stderr.write(`prodcheck-claims: ${err?.message ?? err}\n`);
  process.exit(2);
});
