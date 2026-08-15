/**
 * webhook-swallows-2xx
 *
 * Finds catch blocks in webhook handlers that answer the provider with a 2xx
 * and never rethrow. The provider (Stripe, Svix, GitHub, ...) sees the 2xx,
 * marks the event delivered, and never retries — the failure is permanently
 * swallowed. This is the single most expensive "ships green" bug we know of.
 *
 * Deliberately a heuristic, not a parser. Zero runtime dependencies is a hard
 * rule for this tool, so instead of an AST we do a light lexical pass that
 * classifies every character as code or not-code (strings, template literals,
 * regex literals, comments), then brace-match catch blocks on the code channel
 * only. That is enough to be right on real-world handler code without dragging
 * in babel.
 *
 * That classifier used to live here, in a copy this file kept in step with
 * rate-limit-bypass by hand, and both copies shared one hole: a regex literal
 * was read as whatever its body looked like, so `const RE = /`/;` opened a
 * template frame that never closed and every character after it — every catch
 * block, every 2xx — was classified not-code and skipped. It lives in
 * ./_lexer.mjs now, once, and both rules read the same channel.
 *
 * Modelling regex literals was not the end of it. In a position where the lexer
 * REFUSES a regex, the same body was left in the code channel and opened the
 * same frame — `if (1) /` + backtick + `/.test(x)` above a handler took the
 * whole file dark and this rule reported the swallowed 2xx as clean. What ended
 * it is the INVARIANT in _lexer.mjs: the scan may not finish holding an open
 * frame, and no character may be classified not-code because of a disputed `/`
 * reading. The first is checked after the scan and repaired; the second is
 * unconditional and applied within the scan — no line test, no cost test —
 * because a version of it that carried either was evaded by three separate
 * mechanisms. Read that header before touching anything here that reads the
 * channel; it fails OPEN rather than blind, and this rule depends on it.
 */

import { codeMask, stripComments } from './_lexer.mjs';

export const rule = 'webhook-swallows-2xx';

/**
 * File extensions worth reading at all. The CLI filters on these, and their
 * union across every registered check is the entire scan scope — a file whose
 * extension is not here is never opened, so renaming one is enough to drop it.
 * `.cts` was missing while `.mts` was present, which made `route.cts` invisible
 * and `route.mts` checked, for no reason anyone had decided. The scope is
 * documented in the README ("What gets scanned") and every omission shows up as
 * a drop in `filesScanned`.
 */
export const extensions = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.mts',
  '.cts',
  '.jsx',
  '.tsx',
]);

/** A file is a candidate when its path smells like a webhook... */
const PATH_HINT = /webhook|hook/i;
/**
 * ...or its content does. The hint is matched against comment-stripped source,
 * never raw text: a stray `// TODO: notify via webhook` must not turn an
 * unrelated file's legitimate 200-fallback catch into a critical finding.
 * Strings are deliberately KEPT in the hint text — Express routes register
 * webhooks as string paths (`app.post('/webhook', ...)`), and stripping
 * strings would blind us to exactly those files.
 */
const CONTENT_HINT = /stripe\.webhooks|constructEvent|svix|webhook/i;

const IMPACT =
  'The catch block returns a 2xx without re-throwing, so the webhook provider ' +
  'marks the event delivered and never retries. The failed event is silently ' +
  'lost — no retry, no alert, no trace in the provider dashboard.';

const FIX_ADD = '} catch (e) { logger.error(e); throw e }';

const isTwoXX = (n) => n >= 200 && n <= 299;

export function isCandidate(relPath, content) {
  return PATH_HINT.test(relPath) || CONTENT_HINT.test(stripComments(content));
}

/** `src` with every not-code character blanked (newlines kept for line math). */
function maskedSource(src, mask) {
  const out = new Array(src.length);
  for (let i = 0; i < src.length; i++) {
    out[i] = mask[i] || src[i] === '\n' ? src[i] : ' ';
  }
  return out.join('');
}

/** Advance past whitespace and not-code (comments) to the next code char. */
function skipToCode(src, mask, j) {
  while (j < src.length && (!mask[j] || /\s/.test(src[j]))) j += 1;
  return j;
}

/**
 * Yield every `catch` clause: {catchIndex, bodyStart, bodyEnd}.
 * `.catch(...)` promise-method calls are deliberately skipped — the callback
 * body has different shapes and flagging it needs different heuristics.
 */
function* catchBlocks(src, mask) {
  const re = /\bcatch\b/g;
  let m;
  while ((m = re.exec(src))) {
    const at = m.index;
    if (!mask[at]) continue; // inside a string or comment

    let p = at - 1;
    while (p >= 0 && /\s/.test(src[p])) p -= 1;
    if (p >= 0 && src[p] === '.') continue; // promise .catch(), not a clause

    let j = skipToCode(src, mask, at + 'catch'.length);

    // Optional binding: catch (err) — also destructuring, catch ({ message }).
    if (src[j] === '(') {
      let depth = 0;
      while (j < src.length) {
        if (mask[j]) {
          if (src[j] === '(') depth += 1;
          else if (src[j] === ')') {
            depth -= 1;
            if (depth === 0) { j += 1; break; }
          }
        }
        j += 1;
      }
      j = skipToCode(src, mask, j);
    }

    if (src[j] !== '{') continue;
    const open = j;
    let depth = 0;
    let close = -1;
    for (let k = open; k < src.length; k++) {
      if (!mask[k]) continue;
      if (src[k] === '{') depth += 1;
      else if (src[k] === '}') {
        depth -= 1;
        if (depth === 0) { close = k; break; }
      }
    }
    if (close === -1) continue; // unbalanced — bail on this block, not the file

    yield { catchIndex: at, bodyStart: open + 1, bodyEnd: close };
  }
}

/** The argument text of the paren group opening at `openIndex` (masked text). */
function parenGroup(text, openIndex) {
  let depth = 0;
  for (let i = openIndex; i < text.length; i++) {
    if (text[i] === '(') depth += 1;
    else if (text[i] === ')') {
      depth -= 1;
      if (depth === 0) return text.slice(openIndex + 1, i);
    }
  }
  return text.slice(openIndex + 1);
}

/**
 * Does this Response/json argument list produce a 2xx?
 *
 * What it ACTUALLY does, which is narrower than the three bullets that used to
 * stand here ("numeric → decide by the number; dynamic → do not flag; absent →
 * flag"). `args` is MASKED text — string and template contents are blanked —
 * and the number test is `\bstatus\s*:\s*(\d{3})\b`, so:
 *
 *   - the FIRST `status:` followed by exactly three digits anywhere in the
 *     argument text decides, whether or not it is the Response's status option.
 *     `Response.json({ status: 500 }, { status: 200 })` is read as a 500 and
 *     goes unreported, though the status it actually sends is 200. A `status`
 *     field in the BODY outranks the real one because it comes first.
 *   - a `status:` whose value is not exactly three digits — `status: 99`,
 *     `status: 5000`, `status: code`, `status: HTTP_OK` — falls to the second
 *     test and is treated as dynamic, so it is never flagged. Only the
 *     three-digit spelling is ever "decided by the number".
 *   - a QUOTED key is invisible. `{ "status": 500 }` masks to `{ ⌷⌷⌷⌷⌷⌷⌷⌷: 500 }`
 *     because the quotes open a string, so neither test matches and the third
 *     branch reports it as a defaulted 200. That is a false CRITICAL on a
 *     handler that answers 500, and it is the one case here that errs towards
 *     over-reporting rather than under-.
 *   - no `status:` on the code channel at all → treated as the Response default
 *     of 200 → flag. True of `new Response(body)`, and also of
 *     `new Response(body, init)` where the options are held in a variable this
 *     pass cannot open.
 *
 * Verified against the shipped check, not read off the source: see the DOC-1
 * block of the round-11 falsification probe.
 */
function statusOffends(args) {
  const m = args.match(/\bstatus\s*:\s*(\d{3})\b/);
  if (m) return isTwoXX(Number(m[1]));
  if (/\bstatus\s*:/.test(args)) return false;
  return true;
}

/**
 * Find the earliest expression in the (masked) catch body that answers the
 * client with a 2xx. Returns its index in `body`, or null.
 */
function findOffense(body) {
  const offenses = [];
  let m;

  // return new Response(...) — status option decides; absent means 200.
  const RET_NEW = /\breturn\s+(?:await\s+)?new\s+Response\s*\(/g;
  while ((m = RET_NEW.exec(body))) {
    if (statusOffends(parenGroup(body, m.index + m[0].length - 1))) offenses.push(m.index);
  }

  // return NextResponse.json(...) / Response.json(...) — same status logic.
  const RET_JSON = /\breturn\s+(?:await\s+)?(?:NextResponse|Response)\s*\.\s*json\s*\(/g;
  while ((m = RET_JSON.exec(body))) {
    if (statusOffends(parenGroup(body, m.index + m[0].length - 1))) offenses.push(m.index);
  }

  // Express: res.status(2xx) / res.sendStatus(2xx) / res.json() (defaults 200).
  // Express responds via side effect, so no `return` keyword is required.
  //
  // The `json` branch reads NO status. It flags every `res.json(` it finds in a
  // catch body, unconditionally. What used to stand here — "res.status(500)
  // .json() never matches the json branch because the regex needs `.json`
  // directly after `res`" — is true of that one chained spelling and describes
  // an accident of adjacency rather than a rule, so it read as a safety
  // property this branch does not have. Measured, both directions are wrong:
  //
  //   res.status(500).json({ e })              silent   — the only escape, and
  //                                                       only because `res` is
  //                                                       not adjacent to json
  //   res.status(500); res.json({ e })         CRITICAL — the same 500 response
  //                                                       written as two
  //                                                       statements: a false
  //                                                       positive
  //   res.set('h','v').status(200).json({ o }) silent   — a real 2xx swallow,
  //                                                       missed, because the
  //                                                       chain starts with a
  //                                                       different verb
  //
  // Reading the status a chain actually sets is dataflow over the response
  // object, which is the same thing the rate-limit rule refuses to guess at.
  // Until that exists this is a documented false positive on one spelling and a
  // documented miss on another, both listed in the README's Known limitations.
  const RES = /\bres\s*\.\s*(status|sendStatus|json)\s*\(/g;
  while ((m = RES.exec(body))) {
    if (m[1] === 'json') { offenses.push(m.index); continue; }
    const num = parenGroup(body, m.index + m[0].length - 1).match(/\b(\d{3})\b/);
    if (num && isTwoXX(Number(num[1]))) offenses.push(m.index);
  }

  return offenses.length ? Math.min(...offenses) : null;
}

function lineNumberAt(src, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (src[i] === '\n') line += 1;
  return line;
}

function sourceLineAt(src, index) {
  const start = src.lastIndexOf('\n', index - 1) + 1;
  let end = src.indexOf('\n', index);
  if (end === -1) end = src.length;
  return src.slice(start, end);
}

/**
 * Run the check on one file.
 *
 * @param {object} file {path: POSIX path relative to scan root, content: string}
 * @returns {Array} findings in the shape the renderers consume
 */
export function check(file) {
  const relPath = String(file.path ?? '').replace(/\\/g, '/');
  const content = file.content ?? '';
  const findings = [];

  if (!isCandidate(relPath, content)) return findings;

  const mask = codeMask(content);
  const masked = maskedSource(content, mask);

  for (const block of catchBlocks(content, mask)) {
    const body = masked.slice(block.bodyStart, block.bodyEnd);

    // A rethrow (or any throw) means the failure escapes — not our bug.
    if (/\bthrow\b/.test(body)) continue;

    const offense = findOffense(body);
    if (offense === null) continue;

    findings.push({
      severity: 'critical',
      rule,
      file: relPath,
      line: lineNumberAt(content, block.catchIndex),
      impact: IMPACT,
      fix: {
        remove: [sourceLineAt(content, block.bodyStart + offense).trim()],
        add: [FIX_ADD],
      },
    });
  }

  return findings;
}
