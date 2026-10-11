/**
 * The two user-supplied lists: deny terms and the allow-list.
 *
 * Both are read from paths given on the command line. Neither has a default
 * location and neither is looked up in the repository — a deny-terms file is
 * a list of the things you most need kept out of public bytes (your name,
 * your machine's name, a customer's domain), and the one place it must never
 * be committed is next to the code it guards.
 */

import { readFileSync } from 'node:fs';
import { RULE_IDS } from './rules.mjs';
import { locationOf } from './scan.mjs';

const MIN_TERM = 3;

function lines(file, what) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    throw new Error(`cannot read ${what} file (${err.code ?? err.message})`);
  }
  return text.replace(/^﻿/, '').split(/\r?\n/);
}

/**
 * One term per line, case-insensitive; blank lines and lines starting with
 * `#` are skipped. An empty list is an error, not a clean scan: a deny file
 * that matched nothing because it held nothing would prove nothing. Error
 * messages name line numbers, never terms.
 */
export function loadDenyTerms(file) {
  const terms = [];
  lines(file, 'deny-terms').forEach((raw, i) => {
    const term = raw.trim();
    if (!term || term.startsWith('#')) return;
    if (term.length < MIN_TERM) {
      throw new Error(`deny-terms line ${i + 1}: terms must be at least ${MIN_TERM} characters`);
    }
    terms.push({ term, line: i + 1 });
  });
  if (!terms.length) throw new Error('deny-terms file has no terms');
  return terms;
}

function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      re += '.*';
      i += 1;
    } else if (c === '*') re += '[^/!]*';
    else if (c === '?') re += '[^/!]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

/**
 * Allow-list: one known false positive per line,
 *
 *   <location-glob>  <rule|*>  [pattern]
 *
 * The glob is matched against the whole location — the artifact path as
 * given on the command line, then each entry, joined with `!`:
 * `dist/app.iso!TOOLS/SETUP.EXE`. `*` stops at `/` and `!`, `**` does not.
 * The optional pattern is matched against the unredacted value: a plain
 * case-insensitive substring, or `/regex/` (case-insensitive). With no
 * pattern the rule is allowed anywhere under the glob.
 *
 * An unknown rule id is an error: a typo there would otherwise allow nothing,
 * silently, and the finding it was meant for would keep failing the build
 * for a reason nobody could see.
 */
export function loadAllowList(file) {
  const entries = [];
  lines(file, 'allow-list').forEach((raw, i) => {
    const text = raw.trim();
    if (!text || text.startsWith('#')) return;
    const m = /^(\S+)\s+(\S+)(?:\s+(.+))?$/.exec(text);
    if (!m) throw new Error(`allow-list line ${i + 1}: expected "<location-glob> <rule> [pattern]"`);
    const [, glob, rule, pattern] = m;
    if (rule !== '*' && !RULE_IDS.has(rule)) {
      throw new Error(`allow-list line ${i + 1}: unknown rule "${rule}" (known: ${[...RULE_IDS].join(', ')})`);
    }
    let test = () => true;
    if (pattern) {
      const re = /^\/(.+)\/$/.exec(pattern);
      if (re) {
        const compiled = new RegExp(re[1], 'i');
        test = (v) => compiled.test(v);
      } else {
        const needle = pattern.toLowerCase();
        test = (v) => v.toLowerCase().includes(needle);
      }
    }
    entries.push({ line: i + 1, glob: globToRegExp(glob), rule, test, used: 0 });
  });
  return entries;
}

/** Split findings into reported and allowed; count use per allow entry. */
export function applyAllowList(findings, allow) {
  if (!allow?.length) return { findings, allowed: [] };
  const kept = [];
  const allowed = [];
  for (const f of findings) {
    const loc = locationOf(f);
    const hit = allow.find((a) => (a.rule === '*' || a.rule === f.rule) && a.glob.test(loc) && a.test(f.value));
    if (hit) {
      hit.used += 1;
      allowed.push(f);
    } else {
      kept.push(f);
    }
  }
  return { findings: kept, allowed };
}
