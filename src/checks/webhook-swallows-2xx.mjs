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
 *
 * ── what a 2xx in a catch does NOT mean ─────────────────────────────────────
 *
 * "The catch contains a 2xx" was the whole question this rule asked, and it is
 * the wrong one. The right one is whether the catch ANSWERS 2xx ON THE GENERAL
 * ERROR PATH. A catch that recognises a specific error and answers 200 to that
 * one alone is the standard idempotency pattern:
 *
 *     catch (err) {
 *       if (err.code === "P2002") {          // duplicate delivery: 200 is right,
 *         return NextResponse.json({ dup: true });   // the provider must not retry
 *       }
 *       log(err);                            // anything else falls through and
 *     }                                      // is processed for real
 *
 * That is correct code, every serious payment webhook has a branch like it, and
 * reporting it is noise on exactly the users this rule needs to keep. It was
 * measured as a false positive twice independently — by C1, running his own
 * implementation of this rule on a real repository, and by this one, on the
 * fixture he built from it (tests/fixtures/webhook/webhook-examples.ts). Both
 * implementations had the same hole: neither separated an UNCONDITIONAL success
 * response from one on a branch that handles a named case.
 *
 * So a 2xx is exempted only when BOTH hold: it sits under a condition that
 * inspects the caught error, and the catch has a path out of it that does not
 * answer 2xx. `guardedRegions` and `hasNonTwoXXPath` are those two halves; the
 * comments on each say what they can and cannot read, and every uncertainty is
 * resolved towards reporting.
 *
 * ── frameworks ──────────────────────────────────────────────────────────────
 *
 * The other half of being right about real handlers is knowing how they answer.
 * Express is not the only one: Fastify's `reply.code(204).send()` is a 2xx (204
 * is delivered as far as the provider is concerned), Koa's `ctx` and Hono's `c`
 * are response objects too, and `send`/`end` imply 200 with no status named at
 * all. The receiver list is EXPLICIT and Hono's `c.text` is gated on the import,
 * because `.text()` is also how a fetch body is read — see RESPONSE_RECEIVERS.
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

/**
 * Response objects a 2xx can be written to.
 *
 * The list is EXPLICIT and it stays explicit. "Any identifier followed by
 * `.send(`" reports `logger.send(payload)` and `queue.end()`, neither of which
 * answers an HTTP client, and a rule that reports those is uninstalled before it
 * ever reports a real one.
 *
 * `response` and `resp` earn their place — Fastify hands the handler `reply`,
 * Koa `ctx`, and plenty of Express code spells the second parameter `response` —
 * but they are also what a `fetch` result is called, and `await response.json()`
 * inside a catch READS a body rather than answering one. `valueConsumed` below
 * is what separates the two, and it is why `r` is absent from this list
 * altogether: a one-letter name is a fetch result at least as often as a
 * response object, and nothing lexical can tell them apart.
 *
 * Longest first, so `response` is tried before `res`. The alternation would
 * backtrack into it anyway; the order makes the intent readable.
 */
const RESPONSE_RECEIVERS = ['response', 'reply', 'resp', 'res', 'ctx'];

/** Methods carrying the status code as their first argument. */
const STATUS_METHODS = new Set(['sendStatus', 'status', 'code']);

/**
 * Methods that END the response. With no status set anywhere, every one of
 * these frameworks defaults to 200 — which is exactly the shape that swallows
 * an event without ever naming a status: `reply.send()`, `res.end()`.
 */
const TERMINAL_METHODS = new Set(['sendStatus', 'json', 'send', 'end']);

/**
 * Hono writes the body with `c.text(...)` / `c.html(...)` / `c.body(...)` too —
 * and these are the reason the receiver list can never be widened by feel.
 *
 * `.text()` is ALSO how a `fetch` response body is read:
 *
 *     catch (err) { const detail = await r.text(); ... }   // perfectly correct
 *
 * Flagging that is a false positive on ordinary code, so `text`/`html`/`body`
 * are accepted on `c` ALONE, and `c` is a receiver only in a file that imports
 * hono. Two independent gates on the one method that most looks like a read.
 * (C1 documents the same trap in his implementation; the reasoning is his.)
 */
const HONO_METHODS = new Set(['text', 'html', 'body']);

/** Does this file import hono? Decided on comment-stripped source, imports included. */
const HONO_IMPORT = /(?:\bfrom|\brequire\s*\(\s*)\s*['"]hono(?:\/[\w./-]*)?['"]/;

/**
 * Calls through which the error ESCAPES the catch rather than being answered.
 * `next(err)` hands it to Express error middleware, `reject(...)` fails the
 * surrounding promise, `process.exit(...)` ends the process. None of them
 * answers the provider 2xx, so each is a non-2xx path out of the block.
 * `next()` with no argument merely continues the chain and is not one.
 */
const ERROR_ESCAPES = /\bnext\s*\(\s*[^)\s]|\breject\s*\(|\bprocess\s*\.\s*exit\s*\(/;

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
 * The names a catch clause binds the error to.
 *
 * `catch (err)` → `['err']`; `catch (err: unknown)` → `['err']`, the type
 * annotation dropped; `catch ({ code, message })` → both, because a condition
 * that discriminates on a DESTRUCTURED field references the field name and
 * nothing else. `catch {}` binds nothing and yields `[]`, which makes every
 * guard test below fail closed: with no binding, no condition can be shown to
 * inspect the error, so nothing is ever exempted.
 */
function bindingNames(text) {
  const t = text.trim();
  if (!t) return [];
  if (t.startsWith('{') || t.startsWith('[')) {
    return [...t.matchAll(/[A-Za-z_$][\w$]*/g)].map((m) => m[0]);
  }
  const name = t.split(':')[0].match(/[A-Za-z_$][\w$]*/);
  return name ? [name[0]] : [];
}

/**
 * Yield every `catch` clause: {catchIndex, bodyStart, bodyEnd, binding}.
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
    let binding = [];

    // Optional binding: catch (err) — also destructuring, catch ({ message }).
    if (src[j] === '(') {
      const bindStart = j + 1;
      let depth = 0;
      while (j < src.length) {
        if (mask[j]) {
          if (src[j] === '(') depth += 1;
          else if (src[j] === ')') {
            depth -= 1;
            if (depth === 0) { binding = bindingNames(src.slice(bindStart, j)); j += 1; break; }
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

    yield { catchIndex: at, bodyStart: open + 1, bodyEnd: close, binding };
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

// ── reading the shape of a catch body ───────────────────────────────────────
//
// Everything below runs on MASKED text, where string bodies, template text,
// regex literals and comments are blanked to spaces. That is what makes these
// walks safe without a parser: a brace, a paren or a `?` still standing in the
// text is one the code channel put there, so depth counting cannot be thrown by
// a `}` inside a string or a `//` inside a URL. It is also what the exemption
// below requires — a condition that merely MENTIONS the error binding in a
// comment or a log message must not count as discriminating on it.

/** The index just past the `)` matching the `(` at `openIndex`, or -1. */
function parenEnd(text, openIndex) {
  let depth = 0;
  for (let i = openIndex; i < text.length; i++) {
    if (text[i] === '(') depth += 1;
    else if (text[i] === ')') {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/** The index just past the `}` matching the `{` at `openIndex`, or -1. */
function braceEnd(text, openIndex) {
  let depth = 0;
  for (let i = openIndex; i < text.length; i++) {
    if (text[i] === '{') depth += 1;
    else if (text[i] === '}') {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/** The next non-whitespace index at or after `i`. Comments are already blank. */
function skipSpace(text, i) {
  let j = i;
  while (j < text.length && /\s/.test(text[j])) j += 1;
  return j;
}

/** Is `word` the word standing at `i`? */
const wordAt = (text, i, word) =>
  text.startsWith(word, i) && !/[\w$]/.test(text[i + word.length] ?? '');

/**
 * The index just past the end of the single statement starting at `i`: the `;`
 * that terminates it, or the `}` that closes the block it lives in, or EOF.
 */
function statementEnd(text, i) {
  let depth = 0;
  for (let k = i; k < text.length; k++) {
    const c = text[k];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']') depth -= 1;
    else if (c === '}') {
      if (depth === 0) return k;
      depth -= 1;
    } else if (c === ';' && depth === 0) return k + 1;
  }
  return text.length;
}

/** How many `{`/`(`/`[` are still open at `index`. */
function depthAt(text, index) {
  let depth = 0;
  for (let k = 0; k < index; k++) {
    const c = text[k];
    if (c === '{' || c === '(' || c === '[') depth += 1;
    else if (c === '}' || c === ')' || c === ']') depth -= 1;
  }
  return depth;
}

/** The end of a whole `if (...) ... else ...` chain whose body starts at `i`. */
function branchEnd(text, i) {
  const j = skipSpace(text, i);
  let end = text[j] === '{' ? braceEnd(text, j) : statementEnd(text, j);
  if (end === -1) return text.length;

  const k = skipSpace(text, end);
  if (!wordAt(text, k, 'else')) return end;

  const b = skipSpace(text, k + 'else'.length);
  if (wordAt(text, b, 'if')) {
    // `else if (...)`: the chain continues, and it continues as ONE statement.
    // Whether this arm's own condition inspects the error is not asked — an arm
    // of a chain the error opened is still part of that chain.
    const paren = skipSpace(text, b + 'if'.length);
    if (text[paren] === '(') {
      const after = parenEnd(text, paren);
      if (after !== -1) return branchEnd(text, after);
    }
    return statementEnd(text, b);
  }
  return text[b] === '{' ? (braceEnd(text, b) === -1 ? text.length : braceEnd(text, b)) : statementEnd(text, b);
}

/**
 * The [from, to) extents of every conditional in this catch body whose
 * CONDITION inspects the caught error.
 *
 * This is the whole of fix #1 and the reason it exists: a 2xx answered on a
 * branch that recognises a SPECIFIC error is not a swallowed event, it is the
 * standard idempotency pattern —
 *
 *     catch (err) {
 *       if (err.code === "P2002") return NextResponse.json({ duplicate: true });
 *       log(err);              // anything else falls through and is processed
 *     }
 *
 * — and every serious payment webhook has a duplicate-key branch exactly like
 * it. Reporting it is noise on correct code, which is the one thing a rule this
 * loud cannot afford. (Found independently by C1 running his implementation on
 * a real repository, and by this one on C1's fixture; both had the same hole.)
 *
 * `if` / `else if`, `switch` and the ternary are covered. `&&`/`||`
 * short-circuits (`isDup(err) && res.json(...)`) are NOT: they stay reported,
 * which is the rule's existing bias. So does an `else` arm whose `if` inspects
 * the error but whose OWN path answers every other error 2xx — that shape is
 * exempted by the letter of the rule and caught by nothing here; the second
 * half of the test below is what stands between it and silence.
 */
/**
 * Every name in this catch body bound to something derived from the error,
 * seeded with the binding itself.
 *
 * `inspectsError` asked the condition to name the binding TEXTUALLY. In
 * TypeScript the caught value is `unknown`, so narrowing through a local is not
 * an exotic spelling — it is the idiomatic one:
 *
 *     catch (err) {
 *       const code = (err as { code?: string }).code;
 *       if (code === "P2002") return NextResponse.json({ duplicate: true });
 *     }
 *
 * The direct form was recognised and this one was not, which means the shape
 * that appears MOST in real TypeScript was the shape reported. Found by C1
 * running `45fc147` against `zpl-finance`; the suite was green at 449 tests the
 * whole time, and it took real code to surface it — the same argument this
 * check was built on, pointed back at it.
 *
 * Destructuring is the other half of the same idiom (`const { code } = err`)
 * and is bound here too. Widening is transitive — `const e = err` then
 * `const code = e.code` — and iterates to a fixpoint bounded by the number of
 * declarations, so neither a chain nor a cycle can spin.
 *
 * `body` arrives already masked, so a declaration inside a string or a comment
 * is blank here and cannot open a gate. That is the lexer's invariant doing the
 * work, not a second check on top of it.
 */
function derivedNames(body, binding) {
  const names = [...binding];
  if (names.length === 0) return names;

  // `const x =`, `let {a, b: c} =`, with an optional type annotation between.
  const DECL = /\b(?:const|let|var)\s+(?:([A-Za-z_$][\w$]*)|\{([^{}]*)\})\s*(?::[^=;\n]+)?=/g;

  // The initialiser: from after `=` to the `;` that closes the statement at
  // depth zero. Bounded, so a body missing its semicolon cannot walk to the end
  // of the file on every pass.
  const initialiser = (from) => {
    let depth = 0;
    const stop = Math.min(body.length, from + 600);
    for (let i = from; i < stop; i += 1) {
      const c = body[i];
      if (c === '(' || c === '[' || c === '{') depth += 1;
      else if (c === ')' || c === ']' || c === '}') {
        if (depth === 0) return body.slice(from, i);
        depth -= 1;
      } else if (c === ';' && depth === 0) return body.slice(from, i);
    }
    return body.slice(from, stop);
  };

  const mentions = (text) => names.some((n) => new RegExp(`\\b${n}\\b`).test(text));

  // A later declaration can be fed by an earlier one, and the regex runs in
  // source order, so one pass can miss a chain written in any other order.
  // Repeat until nothing new is bound; each pass must add at least one name.
  for (let pass = 0; pass < 8; pass += 1) {
    const before = names.length;
    DECL.lastIndex = 0;
    let m;
    while ((m = DECL.exec(body))) {
      if (!mentions(initialiser(DECL.lastIndex))) continue;
      if (m[1]) {
        if (!names.includes(m[1])) names.push(m[1]);
        continue;
      }
      // `{ code }` binds `code`; `{ code: c }` binds `c`, not `code`.
      for (const part of m[2].split(',')) {
        const bound = part.includes(':') ? part.slice(part.indexOf(':') + 1) : part;
        const id = bound.trim().replace(/^\.\.\./, '').split('=')[0].trim();
        if (/^[A-Za-z_$][\w$]*$/.test(id) && !names.includes(id)) names.push(id);
      }
    }
    if (names.length === before) break;
  }

  return names;
}

function guardedRegions(body, binding) {
  const names = derivedNames(body, binding);
  if (names.length === 0) return [];
  const inspectsError = (cond) => {
    // `if (err)` inside a catch is not discrimination — it is always true, and
    // treating it as a guard would let the loudest swallow there is hide behind
    // three characters. The condition has to say something ABOUT the error.
    const bare = cond.replace(/[\s!]/g, '');
    if (names.includes(bare)) return false;
    return names.some((n) => new RegExp(`\\b${n}\\b`).test(cond));
  };
  const regions = [];

  const IF = /\bif\b/g;
  let m;
  while ((m = IF.exec(body))) {
    const paren = skipSpace(body, m.index + 'if'.length);
    if (body[paren] !== '(') continue;
    const after = parenEnd(body, paren);
    if (after === -1) continue;
    if (!inspectsError(parenGroup(body, paren))) continue;
    regions.push([m.index, branchEnd(body, after)]);
  }

  const SWITCH = /\bswitch\b/g;
  while ((m = SWITCH.exec(body))) {
    const paren = skipSpace(body, m.index + 'switch'.length);
    if (body[paren] !== '(') continue;
    const after = parenEnd(body, paren);
    if (after === -1) continue;
    if (!inspectsError(parenGroup(body, paren))) continue;
    const open = skipSpace(body, after);
    if (body[open] !== '{') continue;
    const end = braceEnd(body, open);
    regions.push([m.index, end === -1 ? body.length : end]);
  }

  // `cond ? a : b`. The condition runs back to the previous statement or group
  // boundary, which is coarse — it can pick up a `const x =` — and coarse in
  // the harmless direction: it can only make the condition text LONGER, and the
  // test is whether the error is named in it.
  for (let i = 0; i < body.length; i++) {
    if (body[i] !== '?' || body[i + 1] === '?' || body[i + 1] === '.') continue;
    if (body[i - 1] === '?') continue;
    let s = i - 1;
    while (s >= 0 && !';{}('.includes(body[s])) s -= 1;
    if (!inspectsError(body.slice(s + 1, i))) continue;
    regions.push([s + 1, statementEnd(body, i)]);
  }

  return regions;
}

/** Does `index` sit inside any of these extents? */
const within = (regions, index) => regions.some(([from, to]) => index >= from && index < to);

/**
 * The arms of the `if` chain starting at `at`, and whether it ends in a plain
 * `else`. A chain WITHOUT one always has a path through it that runs no arm at
 * all, which is the whole reason the distinction is drawn.
 */
function ifChain(text, at) {
  const arms = [];
  let i = at;
  for (;;) {
    const paren = skipSpace(text, i + 'if'.length);
    if (text[paren] !== '(') return null;
    const after = parenEnd(text, paren);
    if (after === -1) return null;

    const b = skipSpace(text, after);
    const end = text[b] === '{' ? braceEnd(text, b) : statementEnd(text, b);
    if (end === -1) return null;
    arms.push([b, end]);

    const k = skipSpace(text, end);
    if (!wordAt(text, k, 'else')) return { arms, hasElse: false };

    const e = skipSpace(text, k + 'else'.length);
    if (wordAt(text, e, 'if')) { i = e; continue; }
    const elseEnd = text[e] === '{' ? braceEnd(text, e) : statementEnd(text, e);
    if (elseEnd === -1) return null;
    arms.push([e, elseEnd]);
    return { arms, hasElse: true };
  }
}

/**
 * Can control leave this catch WITHOUT answering 2xx?
 *
 * Three ways, and they are the ones the rule names. The error escapes by a route
 * that is not an answer — `throw` (already handled by the caller), `next(err)`,
 * `reject(...)`, `process.exit(...)`. Or another branch ANSWERS non-2xx, which
 * the provider retries. Or control simply falls out of the bottom of the catch,
 * which is what the idempotency pattern does for every error its guard did not
 * recognise.
 *
 * Falling out has to mean falling out WITHOUT HAVING ANSWERED, and that is the
 * one place a purely local reading is not enough. Two shapes close it:
 *
 *   - an unconditional `return` at the catch body's own brace depth, outside
 *     every guarded region: nothing falls out past it;
 *   - a complete `if … else` chain at that same depth whose EVERY arm answers
 *     2xx. `if (err.code === 'P2002') res.json(a); else res.json(b);` reaches
 *     the bottom of the catch by both routes and has answered 2xx on both, so
 *     the guard exempts nothing — it discriminates between two ways of saying
 *     "delivered".
 *
 * Everything not read by those two is read as falling out cleanly, which errs
 * towards SUPPRESSING — a `return` nested in a loop inside a catch, an arm that
 * answers on some of its own paths. Each is a shape never measured in a real
 * webhook handler, each applies only to a 2xx that is already guarded, and each
 * is bounded by the fact that an UNGUARDED 2xx anywhere in the block reports
 * regardless of everything here. Where the shape cannot be read at all, the
 * rule's usual bias holds: report.
 */
function hasNonTwoXXPath(body, guards, answers) {
  if (answers.some((a) => a.twoXX === false)) return true; // another branch denies
  const ESCAPE = new RegExp(ERROR_ESCAPES.source, 'g');
  let m;
  while ((m = ESCAPE.exec(body))) if (!within(guards, m.index)) return true;

  const IF = /\bif\b/g;
  while ((m = IF.exec(body))) {
    if (depthAt(body, m.index) !== 0) continue;
    const chain = ifChain(body, m.index);
    if (!chain || !chain.hasElse) continue;
    const everyArmAnswers = chain.arms.every(([from, to]) =>
      answers.some((a) => a.twoXX === true && a.index >= from && a.index < to)
    );
    if (everyArmAnswers) return false; // every route out of the chain says 2xx
  }

  const RETURN = /\breturn\b/g;
  while ((m = RETURN.exec(body))) {
    if (within(guards, m.index)) continue;
    if (depthAt(body, m.index) !== 0) continue;
    return false; // an unconditional return: nothing falls out of this catch
  }
  return true;
}

/**
 * Is the call at `index` having its RESULT consumed rather than answering a
 * client? `const body = await response.json()` and `.then((resp) => resp.json())`
 * both read a fetch body; neither is a response written to a webhook provider.
 *
 * Only assignment and an arrow body count. `return res.json({ ok: true })` is
 * the ordinary Express answer and must keep reporting, so `return` is not here.
 */
function valueConsumed(text, index) {
  let j = index - 1;
  while (j >= 0 && /\s/.test(text[j])) j -= 1;
  if (j >= 4 && text.slice(j - 4, j + 1) === 'await' && !/[\w$]/.test(text[j - 5] ?? '')) {
    j -= 5;
    while (j >= 0 && /\s/.test(text[j])) j -= 1;
  }
  if (j < 0) return false;
  const before = j > 0 ? text[j - 1] : '';
  if (text[j] === '>' && before === '=') return true; // (resp) => resp.json()
  return text[j] === '=' && before !== '=' && before !== '!' && before !== '<' && before !== '>';
}

/**
 * The status in Hono's POSITIONAL form: `c.json({ error }, 400)`.
 *
 * Only a bare three-digit second argument counts. C1 measured the cost of not
 * reading it — 67 findings on a real Hono repository, every one of them false,
 * because each correctly-written `c.json(…, 400)` looked like an implicit 200.
 */
function positionalStatus(args) {
  let depth = 0;
  let start = 0;
  const parts = [];
  for (let i = 0; i < args.length; i++) {
    const c = args[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === ',' && depth === 0) {
      parts.push(args.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(args.slice(start));
  const second = (parts[1] ?? '').trim();
  return /^\d{3}$/.test(second) ? Number(second) : null;
}

/**
 * Does this Response/json argument list produce a 2xx? `true` yes, `false` an
 * explicit non-2xx, `null` when the status is there but cannot be read.
 *
 * The three-way answer is what fix #1 needs: a catch that answers 500 on one
 * branch has a NON-2XX PATH out of it, which is the second half of the
 * discrimination test below. A dynamic status proves neither, so it stays
 * `null` — it is not an offence (unchanged) and it is not an escape either.
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
function statusOf(args) {
  const m = args.match(/\bstatus\s*:\s*(\d{3})\b/);
  if (m) return isTwoXX(Number(m[1]));
  if (/\bstatus\s*:/.test(args)) return null;
  return true;
}

/**
 * Every expression in the (masked) catch body that answers the client, as
 * {index, twoXX} — `true` a success answer, `false` a failure answer, `null`
 * an answer whose status this pass cannot read.
 *
 * Failure answers are collected, not discarded, because they are evidence: a
 * catch that answers 500 anywhere has a path out of it that the provider will
 * retry, and that is half of what exempts a guarded 2xx.
 */
function findAnswers(body, hono) {
  const answers = [];
  let m;

  // return new Response(...) — status option decides; absent means 200.
  const RET_NEW = /\breturn\s+(?:await\s+)?new\s+Response\s*\(/g;
  while ((m = RET_NEW.exec(body))) {
    answers.push({ index: m.index, twoXX: statusOf(parenGroup(body, m.index + m[0].length - 1)) });
  }

  // return NextResponse.json(...) / Response.json(...) — same status logic.
  const RET_JSON = /\breturn\s+(?:await\s+)?(?:NextResponse|Response)\s*\.\s*json\s*\(/g;
  while ((m = RET_JSON.exec(body))) {
    answers.push({ index: m.index, twoXX: statusOf(parenGroup(body, m.index + m[0].length - 1)) });
  }

  // A response object and a method on it: `res.status(200).json(...)`,
  // `reply.code(204).send()`, `res.json({...})`, `c.text('ok')`. These respond
  // by side effect, so no `return` keyword is required.
  //
  // 204 is what made this branch worth widening. It is 2xx, the provider reads
  // it as delivered, and a rule that only knew `200` read Fastify's
  // `reply.code(204).send()` as clean — the one BAD case of C1's fixture the
  // shipped detector missed.
  //
  // The `json`/`send`/`end` branch reads NO status of its own. It flags every
  // such call it finds on a response receiver, and the chained non-2xx spelling
  // escapes only by adjacency — `res.status(500).json({ e })` is silent because
  // `json` does not follow `res` directly, while `res.status(500); res.json({e})`
  // is the same response in two statements and IS reported. Measured, both
  // directions are wrong:
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
  const receivers = hono ? [...RESPONSE_RECEIVERS, 'c'] : RESPONSE_RECEIVERS;
  const methods = [...STATUS_METHODS, ...TERMINAL_METHODS, ...(hono ? HONO_METHODS : [])];
  const CALL = new RegExp(`\\b(${receivers.join('|')})\\s*\\.\\s*(${methods.join('|')})\\s*\\(`, 'g');
  while ((m = CALL.exec(body))) {
    const [receiver, method] = [m[1], m[2]];
    if (HONO_METHODS.has(method) && receiver !== 'c') continue; // `await r.text()` is a READ
    if (valueConsumed(body, m.index)) continue; // `const b = await response.json()`

    const args = parenGroup(body, m.index + m[0].length - 1);
    if (STATUS_METHODS.has(method)) {
      const num = args.match(/\b(\d{3})\b/);
      // `res.sendStatus()` and a computed status say nothing either way.
      answers.push({ index: m.index, twoXX: num ? isTwoXX(Number(num[1])) : null });
      continue;
    }
    const positional = positionalStatus(args);
    answers.push({ index: m.index, twoXX: positional === null ? true : isTwoXX(positional) });
  }

  return answers;
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
  const hono = HONO_IMPORT.test(stripComments(content));

  for (const block of catchBlocks(content, mask)) {
    const body = masked.slice(block.bodyStart, block.bodyEnd);

    // A rethrow (or any throw) means the failure escapes — not our bug.
    if (/\bthrow\b/.test(body)) continue;

    const answers = findAnswers(body, hono);
    const offenses = answers.filter((a) => a.twoXX === true).map((a) => a.index);
    if (offenses.length === 0) continue;

    // Fix #1, the two halves of it. A 2xx answered on a branch that inspects the
    // caught error is DISCRIMINATION rather than swallowing — but only if the
    // catch also has a way out that does not answer 2xx. A catch whose every
    // exit is a guarded 2xx swallows what the guard matches AND what it does
    // not, so both halves have to hold before anything is exempted.
    const guards = guardedRegions(body, block.binding);
    const unguarded = offenses.filter((i) => !within(guards, i));
    let offense;
    if (unguarded.length > 0) offense = Math.min(...unguarded);
    else if (hasNonTwoXXPath(body, guards, answers)) continue;
    else offense = Math.min(...offenses);

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
