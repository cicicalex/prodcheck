/**
 * Tests for the webhook-swallows-2xx detector and the CLI entrypoint.
 * node:test + node:assert only — the zero-dependency rule covers dev-time too.
 *
 * Fixture layout: every detector owns one subdirectory of tests/fixtures/, and
 * this file only ever scans its own — tests/fixtures/webhook/. That is what
 * keeps the exact counts below (filesScanned, the summary, the file list)
 * true forever: fixtures added for rules #3-#7 land in sibling directories and
 * cannot move these numbers. The cross-rule expectations over the parent
 * directory live in the aggregation test in ratelimit.test.mjs.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { check, rule } from '../src/checks/webhook-swallows-2xx.mjs';
// The clause-(2) reproducers below assert a FINDING rather than a mask bit, and
// the rate-limit rule is where the three mechanisms were measured silencing
// real production bugs, so both detectors are needed here.
import { check as rateLimitCheck } from '../src/checks/rate-limit-bypass.mjs';
import { codeMask, stripComments } from '../src/checks/_lexer.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, 'fixtures', 'webhook');
const CLI = path.join(HERE, '..', 'src', 'cli.mjs');

/** Run the detector on one fixture, addressed by its POSIX-relative path. */
function detect(relPosix) {
  const content = readFileSync(path.join(FIXTURES, ...relPosix.split('/')), 'utf8');
  return check({ path: relPosix, content });
}

function runCli(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

// ── detector ────────────────────────────────────────────────────────────────

test('flags a stripe webhook catch that returns Response status 200', () => {
  const findings = detect('app/api/stripe/webhook/route.ts');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'critical');
  assert.equal(f.file, 'app/api/stripe/webhook/route.ts');
  assert.equal(f.line, 12); // the line of the catch keyword
  assert.deepEqual(f.fix.remove, [`return new Response('ok', { status: 200 });`]);
  assert.equal(f.fix.add.length, 1);
  assert.ok(f.impact.includes('never retries'));
});

test('flags new Response(null) with no status option in a webhook file', () => {
  const findings = detect('github-webhook.mjs');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.file, 'github-webhook.mjs');
  assert.equal(f.line, 6);
  assert.deepEqual(f.fix.remove, ['return new Response(null);']);
});

test('does not flag a catch that rethrows', () => {
  assert.deepEqual(detect('svix-hook.mjs'), []);
});

test('does not flag a catch that returns a 500', () => {
  assert.deepEqual(detect('stripe-webhook-500.ts'), []);
});

/**
 * The candidacy gate is half path-driven, so this case is asserted on inline
 * source rather than a file: any file living under tests/fixtures/webhook/
 * has a webhook-ish path by construction, which is precisely the input this
 * test needs to NOT have. Same idiom as the path-sensitive negatives in
 * ratelimit.test.mjs.
 */
test('does not flag a non-webhook file whose catch returns 200', () => {
  const src = [
    'export async function POST(req: Request) {',
    '  try {',
    '    const charge = await capture(await req.json());',
    '    return new Response(JSON.stringify({ id: charge.id }), { status: 201 });',
    '  } catch (err) {',
    `    return new Response('accepted', { status: 200 });`,
    '  }',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'payments.ts', content: src }), []);
});

// ── the acceptance fixture ──────────────────────────────────────────────────
//
// `fixtures/webhook/webhook-examples.ts` is a VERBATIM copy of the labelled
// fixture C1 built while implementing the same rule independently
// (_ZPL_TEAM/pentru-C4/ship-safe-webhook/fixtures/webhook-examples.ts). It is
// kept byte-identical, Romanian comments and all — they name each case — so the
// two copies stay diffable and either side can re-sync from the other. Only his
// COVERAGE was taken: his implementation parses with `typescript`, and a
// runtime dependency is not something this tool is allowed to have.
//
// It is the acceptance set for this rule: five BAD that must fire at their exact
// lines, four GOOD that must stay silent. Both halves cost something real.
//
//   bad5_replyCode204   Fastify `reply.code(204).send()`. 204 is 2xx and the
//                       provider reads it as delivered; the shipped detector
//                       knew `res.status/json` and nothing else, so this was a
//                       MISS.
//   good5_idempotenta…  a catch that answers 200 only on the branch that
//                       recognises a duplicate-key violation and falls through
//                       for every other error. MODELLED ON REAL PRODUCTION CODE
//                       — it was C1's first false positive, found by running his
//                       detector on a real repository, and it was this one's
//                       too. Every serious payment webhook has a duplicate
//                       branch, so reporting it is noise on correct code.
//
// The lines below are the `catch` keyword's line, which is where this rule
// anchors a finding.

const ACCEPTANCE = 'webhook-examples.ts';

test('acceptance fixture: all five BAD cases fire, at their exact lines', () => {
  const got = detect(ACCEPTANCE)
    .map((f) => ({ line: f.line, remove: f.fix.remove[0] }))
    .sort((a, b) => a.line - b.line);
  assert.deepEqual(got, [
    { line: 37, remove: 'res.status(200).json({ received: true });' }, // bad1
    { line: 48, remove: 'res.json({ ok: true });' }, // bad2
    { line: 59, remove: 'return NextResponse.json({ received: true });' }, // bad3
    { line: 70, remove: 'return new Response("ok", { status: 200 });' }, // bad4
    { line: 81, remove: 'reply.code(204).send();' }, // bad5 — the recall gap
  ]);
  for (const f of detect(ACCEPTANCE)) {
    assert.equal(f.rule, rule);
    assert.equal(f.severity, 'critical');
  }
});

test('acceptance fixture: no GOOD case is reported', () => {
  // Asserted by line RANGE rather than by count, so that a future regression
  // reports which correct handler it started flagging. Each range is the whole
  // function, `catch` line included.
  const good = {
    good1_status500: [92, 100],
    good2_reAruncare: [108, 116],
    good3_semnaturaInvalida: [119, 127],
    good5_idempotentaConditionala: [139, 153],
    good4_lant503: [156, 164],
  };
  const lines = detect(ACCEPTANCE).map((f) => f.line);
  for (const [name, [from, to]] of Object.entries(good)) {
    const hit = lines.find((l) => l >= from && l <= to);
    assert.equal(hit, undefined, `${name} (lines ${from}-${to}) was reported at line ${hit}`);
  }
});

// ── fix #1: a 2xx under a condition that inspects the error ─────────────────
//
// The exemption has two halves and BOTH are required. A 2xx answered on a branch
// that recognises a specific error is discrimination, not swallowing — but only
// when the catch also has a way out that does not answer 2xx. A catch whose
// every exit is a guarded 2xx swallows what the guard matches and what it does
// not, and stays reported.

/** A webhook handler around `body`, as the catch block of a Stripe route. */
const handler = (body, binding = '(err)') =>
  [
    'export async function POST(req) {',
    '  try {',
    '    await stripe.webhooks.constructEvent(await req.text(), sig, secret);',
    `  } catch ${binding} {`,
    ...body.map((l) => `    ${l}`),
    '  }',
    '}',
  ].join('\n');

const scan = (body, binding) =>
  check({ path: 'app/api/stripe/webhook/route.ts', content: handler(body, binding) });

test('a 2xx guarded by a test on the caught error, with a fall-through, is silent', () => {
  // The idempotency pattern, in the four spellings that actually get written.
  const guarded = {
    'property compare': ["if (err.code === 'P2002') return NextResponse.json({ dup: true });", 'log(err);'],
    instanceof: ['if (err instanceof DuplicateError) return NextResponse.json({ dup: true });', 'log(err);'],
    'name compare': ["if (err.name === 'AlreadyProcessed') res.json({ dup: true });", 'log(err);'],
    'helper on the error': ['if (isDuplicate(err)) { res.status(200).json({ dup: true }); return; }', 'log(err);'],
    'else-if arm': [
      "if (err.code === 'P2001') { log(err); }",
      "else if (err.code === 'P2002') { return NextResponse.json({ dup: true }); }",
    ],
    switch: [
      'switch (err.code) {',
      "  case 'P2002': return NextResponse.json({ dup: true });",
      '  default: log(err);',
      '}',
    ],
    ternary: ["err.code === 'P2002' ? res.json({ dup: true }) : log(err);"],
  };
  for (const [label, body] of Object.entries(guarded)) {
    assert.deepEqual(scan(body), [], `${label}: a discriminating catch was reported`);
  }
});

test('a destructured binding is followed into the condition', () => {
  assert.deepEqual(
    scan(["if (code === 'P2002') return NextResponse.json({ dup: true });", 'log(code);'], '({ code })'),
    []
  );
});

// ── narrowing through a local ────────────────────────────────────────────────
//
// In TypeScript the caught value is `unknown`, so the condition usually tests a
// LOCAL derived from the error rather than the binding itself. Only the direct
// spelling was recognised, which meant the shape that appears most in real
// TypeScript was the shape reported. Found by C1 running 45fc147 against
// zpl-finance — 484 files, one critical, on correct code. The suite was green at
// 449 tests the whole time it was broken, which is why the negative cases below
// matter more than the positive ones: the fix REMOVES reports, and a fix that
// removes too many is indistinguishable from a green suite.

test('a condition on a local derived from the error is discrimination', () => {
  const narrowed = {
    'const, property read': [
      "const code = (err as { code?: string }).code;",
      "if (code === 'P2002') return NextResponse.json({ dup: true });",
      'log(err);',
    ],
    destructured: [
      'const { code } = err as { code?: string };',
      "if (code === 'P2002') return NextResponse.json({ dup: true });",
      'log(err);',
    ],
    'destructured and renamed': [
      'const { code: c } = err as { code?: string };',
      "if (c === 'P2002') return NextResponse.json({ dup: true });",
      'log(err);',
    ],
    'transitive chain': [
      'const e = err;',
      'const code = e.code;',
      "if (code === 'P2002') return NextResponse.json({ dup: true });",
      'log(err);',
    ],
    'declared after the guard it feeds': [
      // Source order must not decide: the widening runs to a fixpoint.
      "if (code === 'P2002') return NextResponse.json({ dup: true });",
      'const code = err.code;',
      'log(err);',
    ],
    'multi-line initialiser': [
      'const code = (',
      '  err as { code?: string }',
      ').code;',
      "if (code === 'P2002') return NextResponse.json({ dup: true });",
      'log(err);',
    ],
  };
  for (const [label, body] of Object.entries(narrowed)) {
    assert.deepEqual(scan(body), [], `${label}: a discriminating catch was reported`);
  }
});

test('a local NOT derived from the error opens no gate', () => {
  // The whole risk of the widening above. If any declaration could exempt a
  // 2xx, the loudest swallow there is hides behind `const ok = true`.
  const swallows = {
    'unrelated constant': [
      'const ok = true;',
      'if (ok) return NextResponse.json({ received: true });',
    ],
    'unrelated read': [
      'const mode = req.headers.get("x-mode");',
      "if (mode === 'test') return NextResponse.json({ received: true });",
      'return NextResponse.json({ received: true });',
    ],
    'derived name never tested': [
      // Bound from the error, but no condition inspects it — nothing is guarded.
      'const code = err.code;',
      'return NextResponse.json({ received: true });',
    ],
    'bare derived name': [
      // `if (code)` says the error HAS a code, not WHICH one — the same weakness
      // as `if (err)`, and exempted for the same reason: it is not discrimination.
      'const code = err.code;',
      'if (code) return NextResponse.json({ received: true });',
      'return NextResponse.json({ received: true });',
    ],
    'declaration inside a string': [
      // The lexer blanks it, so it can never bind. Belt and braces: if the mask
      // ever regresses, this test fails loudly instead of going quiet.
      'log("const code = err.code;");',
      "if (code === 'P2002') return NextResponse.json({ dup: true });",
      'return NextResponse.json({ received: true });',
    ],
  };
  for (const [label, body] of Object.entries(swallows)) {
    assert.equal(scan(body).length, 1, `${label}: the swallow was exempted`);
  }
});

test('narrowing through a local still needs a non-2xx way out', () => {
  // Both halves of fix #1 survive the widening: recognising a specific error
  // exempts nothing if every exit answers 2xx anyway.
  assert.equal(
    scan([
      'const code = err.code;',
      "if (code === 'P2002') return NextResponse.json({ dup: true });",
      'return NextResponse.json({ received: true });',
    ]).length,
    1
  );
});

test('a guarded 2xx whose catch has NO other way out is still reported', () => {
  // Both halves of the test, one failing each way. Every one of these answers
  // 2xx on every path the guard can take, so the guard exempts nothing.
  const swallows = {
    'both arms 2xx': [
      "if (err.code === 'P2002') { return NextResponse.json({ dup: true }); }",
      'return NextResponse.json({ received: true });',
    ],
    'guard then unconditional 2xx': [
      "if (err.code === 'P2002') res.json({ dup: true });",
      'else res.json({ received: true });',
    ],
    'guarded 2xx, unconditional bare return': [
      "if (err.code === 'P2002') { return res.json({ dup: true }); }",
      'log(err);',
      'return;',
    ],
  };
  for (const [label, body] of Object.entries(swallows)) {
    assert.equal(scan(body).length, 1, `${label}: the swallow was exempted`);
  }
});

test('a condition that does not inspect the caught error exempts nothing', () => {
  // `retries` is not the binding, so this is not discrimination — it is a 2xx
  // answered on a condition that has nothing to do with which error occurred.
  assert.equal(scan(['if (retries > 3) return NextResponse.json({ ok: true });', 'log(err);']).length, 1);
  // `catch {}` binds nothing, so nothing can be shown to inspect the error.
  assert.equal(
    scan(["if (e.code === 'P2002') return NextResponse.json({ ok: true });", 'log(e);'], '').length,
    1
  );
});

test('`if (err)` is not discrimination — it is always true inside a catch', () => {
  for (const cond of ['if (err)', 'if (!err)', 'if ( err )']) {
    assert.equal(
      scan([`${cond} return NextResponse.json({ ok: true });`, 'log(err);']).length,
      1,
      `${cond} was accepted as a guard`
    );
  }
});

test('the binding must be named on the CODE channel, not in a string or comment', () => {
  // The guard reads masked text, so a condition that only mentions `err` inside
  // a literal or a comment is not a condition on the error.
  const inString = ["if (label === 'err') return NextResponse.json({ ok: true });", 'log(err);'];
  assert.equal(scan(inString).length, 1, 'a string mentioning the binding acted as a guard');
  const inComment = ['if (flag /* err */) return NextResponse.json({ ok: true });', 'log(err);'];
  assert.equal(scan(inComment).length, 1, 'a comment mentioning the binding acted as a guard');
});

test('an unguarded 2xx is reported even when a guarded one sits above it', () => {
  const findings = scan([
    "if (err.code === 'P2002') { return NextResponse.json({ dup: true }); }",
    'log(err);',
    'res.json({ received: true });',
  ]);
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].fix.remove, ['res.json({ received: true });']);
});

test('a non-2xx answer elsewhere in the catch is the other way out', () => {
  // A catch that returns 500 for everything it did not recognise: the provider
  // retries, nothing is lost, and the guarded 200 is correct.
  assert.deepEqual(
    scan([
      "if (err.code === 'P2002') return NextResponse.json({ dup: true });",
      "return NextResponse.json({ error: 'failed' }, { status: 500 });",
    ]),
    []
  );
  // …and so is handing the error to Express error middleware.
  assert.deepEqual(
    scan(["if (err.code === 'P2002') return res.json({ dup: true });", 'return next(err);']),
    []
  );
});

test('the exemption stops where the README says it stops', () => {
  // Three shapes the guard cannot read, pinned so the code and the "Known
  // limitations" section cannot drift apart. Each is a MISS, each applies only
  // to a 2xx that is already guarded, and the fourth case is the counterweight:
  // an unconditional 2xx in the same block is reported whatever the guard does.
  assert.deepEqual(
    scan(['if (err.code === "X") { log(err); }', 'else { return res.json({ ok: true }); }']),
    [],
    'the else arm of an error-inspecting if is exempted — documented miss'
  );
  assert.deepEqual(
    scan(['if (err.code === "X") { return res.json({ dup: true }); }', 'for (const x of xs) { if (x) return; }']),
    [],
    'a return nested in a loop reads as "control falls out" — documented miss'
  );
  assert.equal(
    scan(['isDup(err) && res.json({ dup: true });']).length,
    1,
    'a && short-circuit is not a guard and must stay reported'
  );
  assert.equal(
    scan(['if (err.code === "X") { return res.json({ dup: true }); }', 'res.json({ ok: true });']).length,
    1
  );
});

// ── fix #2: response objects and terminal methods ───────────────────────────

test('Fastify: reply.code(2xx).send() and a bare reply.send() are swallows', () => {
  for (const line of [
    'reply.code(204).send();',
    'reply.status(202).send();',
    'reply.send();',
    'return reply.code(200).send({ ok: true });',
  ]) {
    assert.equal(scan([line]).length, 1, `${line} was not read as a 2xx`);
  }
  // A non-2xx code on the same chain is correct and stays silent.
  for (const line of ['reply.code(500).send();', 'reply.status(400).send({ e: 1 });']) {
    assert.deepEqual(scan([line]), [], `${line} was reported`);
  }
});

test('the terminal methods that imply 200, on every receiver in the list', () => {
  for (const line of [
    'res.end();',
    'res.sendStatus(202);',
    'response.send({ ok: true });',
    'resp.end();',
    'ctx.json({ ok: true });',
  ]) {
    assert.equal(scan([line]).length, 1, `${line} was not read as a 2xx`);
  }
  assert.deepEqual(scan(['res.sendStatus(500);']), []);
});

test('the receiver list is explicit — an ordinary call is not a response', () => {
  // "any identifier + .send(" would report every one of these.
  for (const line of ['logger.send(err);', 'queue.end();', 'metrics.json({ err });', 'span.end();']) {
    assert.deepEqual(scan([line]), [], `${line} was read as an HTTP response`);
  }
});

test('reading a fetch body in a catch is not answering the provider', () => {
  // `.text()` is how a fetch response body is read, and `response`/`resp` are
  // what a fetch result gets called. Both spellings below are correct code.
  for (const line of [
    'const detail = await response.text();',
    'const body = await resp.json();',
    'const data = await response.json();',
  ]) {
    assert.deepEqual(scan([line]), [], `${line} was reported as a response`);
  }
});

test('Hono: c.text/c.html/c.body count only in a file that imports hono', () => {
  const honoRoute = (line) =>
    [
      "import { Hono } from 'hono';",
      'const app = new Hono();',
      "app.post('/webhook', async (c) => {",
      '  try {',
      '    await stripe.webhooks.constructEvent(await c.req.text(), sig, secret);',
      '  } catch (err) {',
      `    ${line}`,
      '  }',
      '});',
    ].join('\n');
  for (const line of ["return c.text('ok');", "return c.html('<b>ok</b>');", 'return c.body(null);', 'return c.json({ ok: true });']) {
    assert.equal(
      check({ path: 'app/webhook.ts', content: honoRoute(line) }).length,
      1,
      `${line} was not read as a Hono response`
    );
  }
  // Hono's status is POSITIONAL, and a correctly-written failure answer must
  // stay silent — C1 measured 67 false positives on a real repo from missing it.
  for (const line of ["return c.json({ error: 'failed' }, 500);", "return c.text('nope', 400);"]) {
    assert.deepEqual(check({ path: 'app/webhook.ts', content: honoRoute(line) }), [], line);
  }
  // Without the import, `c` is not a response object and `.text()` is a read.
  const noImport = handler(["const detail = await c.text();", 'log(err);']);
  assert.deepEqual(check({ path: 'app/api/stripe/webhook/route.ts', content: noImport }), []);
});

// ── the shared lexer ────────────────────────────────────────────────────────
//
// Both detectors read one character classification, and until this round it did
// not model regex literals. A regex whose BODY happened to contain a backtick
// pushed a template frame that was never popped, so every character from that
// line to end of file was classified not-code — and every search in both rules
// skips not-code. Three one-liners, all valid JavaScript, silenced whole files.

/** The offset of `needle` in `src`, asserted unique enough to be meaningful. */
const at = (src, needle) => src.indexOf(needle);

/** Is every character of `slice` classified the same way in `src`? */
function allMasked(src, slice, want) {
  const start = at(src, slice);
  assert.ok(start >= 0, `fixture must contain ${JSON.stringify(slice)}`);
  const mask = codeMask(src);
  for (let i = 0; i < slice.length; i++) {
    assert.equal(
      mask[start + i],
      want,
      `char ${JSON.stringify(slice[i])} of ${JSON.stringify(slice)} should be ${want ? 'code' : 'data'}`
    );
  }
}

test('a regex literal containing a backtick does not blind the rest of the file', () => {
  const src = ['const RE_TICK = /`/;', "const later = req.headers['x-forwarded-for'];"].join('\n');
  allMasked(src, 'const later', 1);
  allMasked(src, '/`/', 0); // the literal itself is data, exactly like a string
});

test('a regex whose character class holds a backtick does not blind the file', () => {
  const src = ['const RE_TICK2 = /[`]/;', 'const later = 1;'].join('\n');
  allMasked(src, 'const later', 1);
  allMasked(src, '/[`]/', 0);
});

test('a regex whose character class holds /* does not open a block comment', () => {
  const src = ['const RE_C = /[/*]/;', 'const later = 2;'].join('\n');
  allMasked(src, 'const later', 1);
  allMasked(src, '/[/*]/', 0);
});

test('division is not read as a regex — `const r = a / b / c;`', () => {
  // The failure this guards against is the expensive one: a `/` wrongly taken
  // for a regex opener swallows the rest of the line and can unbalance the
  // file. Every character of the expression stays on the code channel.
  const src = 'const r = a / b / c;\nconst after = 3;';
  allMasked(src, 'a / b / c', 1);
  allMasked(src, 'const after', 1);
});

test('the ambiguous positions resolve to division, not to a regex', () => {
  for (const expr of ['const q = (a) / b / c;', 'const q = xs[0] / y / z;', 'const q = i++ / 2 / 3;']) {
    const src = `${expr}\nconst after = 4;`;
    allMasked(src, 'const after', 1);
  }
});

test('a regex still opens where an expression may start', () => {
  const src = 'const re = /a\\/b/gi;\nconst after = 5;';
  allMasked(src, '/a\\/b/gi', 0);
  allMasked(src, 'const after', 1);
  // …and after a keyword that wants an operand.
  const kw = 'function f(s) { return /x`y/.test(s); }\nconst after = 6;';
  allMasked(kw, '/x`y/', 0);
  allMasked(kw, 'const after', 1);
});

test('stripComments keeps a regex body and does not read /* inside one', () => {
  const src = "const RE = /[/*]/;\nconst name = 'x-forwarded-for';";
  const out = stripComments(src);
  assert.equal(out.length, src.length);
  assert.ok(out.includes("'x-forwarded-for'"), 'the code after the regex must survive');
  assert.ok(out.includes('/[/*]/'), 'a regex body is data, but it is not a comment');
});

test('the real csv-export shape — a regex in a template interpolation — stays lit', () => {
  // Not adversarial: this is `zpl-finance/src/lib/csv-export.ts`, where ordinary
  // CSV quoting took the file dark from its line 11 to EOF.
  const src = [
    'function esc(str) {',
    '  return `"${str.replace(/"/g, \'""\')}"`;',
    '}',
    "const trailing = req.headers['x-forwarded-for'];",
  ].join('\n');
  allMasked(src, 'const trailing', 1);
});

// Each of the three mutes, as the webhook rule sees them: a swallowed 2xx that
// went unreported because the file above it had gone dark.
for (const [label, line] of Object.entries({
  'backtick regex': 'const RE_TICK = /`/;',
  'backtick class': 'const RE_TICK2 = /[`]/;',
  'comment class': 'const RE_C = /[/*]/;',
  'markdown fence': 'const FENCE = /`{3}/g;',
})) {
  test(`webhook: a swallowed 2xx below a ${label} is still reported`, () => {
    const src = [
      line,
      'export async function POST(req) {',
      '  try {',
      '    await handleStripeEvent(await req.json());',
      "    return new Response('ok', { status: 200 });",
      '  } catch (e) {',
      "    return new Response('ok', { status: 200 });",
      '  }',
      '}',
    ].join('\n');
    const findings = check({ path: 'stripe-webhook.ts', content: src });
    assert.equal(findings.length, 1, `"${line}" silenced the swallowed 2xx`);
    assert.equal(findings[0].severity, 'critical');
    assert.equal(findings[0].line, 6);
  });
}

// ── the lexer INVARIANT ─────────────────────────────────────────────────────
//
// Modelling regex literals did not close the class, it moved it. In a position
// where the lexer REFUSES a regex — after `)`, after `]`, after a division `/`
// — the body it declines to consume stays in the CODE channel, so a backtick or
// a `/*` in that body opens a frame of its own. The frame then runs either to
// EOF or to the next character that happens to close it, and everything it
// covers is not-code and therefore unsearchable.
//
// The invariant in _lexer.mjs forbids both endings. These tests generate the
// failure rather than enumerate the spellings that caused it: the assertion is
// that a sentinel line placed AFTER the poison is still on the code channel and
// still present in stripComments output, whatever the poison was.

/** A `/` position the lexer refuses a regex in, one line each. */
const REFUSED_POSITION = {
  'after )': (body) => `if (1) ${body}.test("x");`,
  'after ) of while': (body) => `while (false) ${body}.test("x");`,
  'after ) of for': (body) => `for (let zq = 0; zq < 0; zq++) ${body}.test("x");`,
  'after a division /': (body) => `const zqd = 4 / ${body}.source.length;`,
  'after ]': (body) => `const zqe = [1][0] / ${body}.source.length;`,
};

/** Regex bodies that carry a frame opener the code channel would act on. */
const FRAME_OPENING_BODY = {
  backtick: '/`/',
  'backtick in a class': '/[`]/',
  'block-comment opener': '/[/*]/',
  'single quote': "/'/",
  'double quote': '/"/',
};

/** What the frame finds below it: nothing, or a real closer of its own kind. */
const BELOW = {
  'nothing below': [],
  'a real template below': ['const zt = `a ${1} b`;'],
  'a real block comment below': ['/* a real comment */'],
  'a real string below': ["const zs = 'plain';"],
};

/**
 * The probe line. Deliberately all code — no string, no template — so that
 * "every character is 1" is the right assertion. A sentinel containing a
 * literal would be partly data by design and could only be checked loosely.
 */
const SENTINEL = 'const sentinelZz = 1;';

for (const [posLabel, wrap] of Object.entries(REFUSED_POSITION)) {
  for (const [bodyLabel, body] of Object.entries(FRAME_OPENING_BODY)) {
    for (const [belowLabel, tail] of Object.entries(BELOW)) {
      test(`invariant: ${bodyLabel} ${posLabel}, ${belowLabel}, leaves the tail lit`, () => {
        const src = [wrap(body), ...tail, SENTINEL, ''].join('\n');

        // (1) every character of the sentinel is on the code channel…
        const mask = codeMask(src);
        const start = src.indexOf(SENTINEL);
        assert.ok(start > 0, 'fixture must contain the sentinel');
        for (let i = 0; i < SENTINEL.length; i++) {
          assert.equal(
            mask[start + i],
            1,
            `char ${i} (${JSON.stringify(SENTINEL[i])}) of the sentinel went dark`
          );
        }

        // (2) …and stripComments did not blank it either. An unterminated block
        // comment silences that channel instead of the mask, and the rules read
        // both, so one guarantee without the other is not a guarantee.
        const stripped = stripComments(src);
        assert.equal(stripped.length, src.length, 'stripComments must preserve indices');
        assert.ok(stripped.includes(SENTINEL), 'the sentinel was blanked as a comment');
      });
    }
  }
}

test('invariant: an unclosed frame of any kind cannot reach EOF', () => {
  // The direct generator: each of these ends the file inside a frame. None may
  // take the line above it dark, because a mask whose tail is not-code is the
  // failure this invariant exists to forbid.
  const openers = {
    'bare backtick': 'const t = `never closed',
    'block comment': '/* never closed',
    'double quote': 'const s = "never closed',
    'single quote': "const s = 'never closed",
    'template interpolation': 'const t = `a ${1',
    'nested templates': 'const t = `a ${`b',
  };
  for (const [label, opener] of Object.entries(openers)) {
    const src = [SENTINEL, opener].join('\n');
    const mask = codeMask(src);
    for (let i = 0; i < SENTINEL.length; i++) {
      assert.equal(mask[i], 1, `${label}: the sentinel above it went dark at ${i}`);
    }
    // And the opener's own line is not allowed to be entirely not-code either:
    // something on it must survive, or the scan simply gave up on the tail.
    const tailMask = [...mask.slice(src.indexOf(opener))];
    assert.ok(tailMask.some((b) => b === 1), `${label}: the whole tail is not-code`);
  }
});

test('the recovery does not manufacture findings in ordinary code', () => {
  // Every frame kind, correctly written, plus the division shapes a wrong
  // recovery would misread. Nothing here is a webhook offence, and the file
  // must stay silent — a fail-open lexer that over-reports on ORDINARY code is
  // just a noisier kind of broken.
  const ordinary = [
    '/**',
    ' * A multi-line block comment mentioning a catch that returns 200.',
    ' * return new Response("ok", { status: 200 });',
    ' */',
    'const RE = /[/*]/;',
    'const FENCE = /`{3}/g;',
    'const ratio = a / b / c;',
    'const half = width / 2, label = \'x/y\';',
    'const tpl = `line one',
    'line two ${1 / 2 / 3} end`;',
    'export async function POST(req) {',
    '  try {',
    '    await handleStripeEvent(await req.json());',
    "    return new Response('ok', { status: 200 });",
    '  } catch (e) {',
    '    logger.error(e);',
    '    throw e;',
    '  }',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'webhook/ordinary.ts', content: ordinary }), []);

  // The block comment really is a comment: its 200 must not reach the searches.
  const stripped = stripComments(ordinary);
  assert.ok(!stripped.includes('A multi-line block comment'), 'the JSDoc survived stripComments');
  // …while the code below it survives untouched.
  assert.ok(stripped.includes('export async function POST'));
});

test('invariant: a backslash-newline continuation cannot carry a literal off its line', () => {
  // `'a\` + newline is a legal LINE CONTINUATION in JavaScript, and honouring
  // it let one appended line swallow everything down to the next quote in the
  // file — an unclosed frame that never reaches EOF, so clause (1) cannot see
  // it. Strings and regex literals are confined to their own line here; only
  // templates and block comments may span one.
  const BS = String.fromCharCode(92);
  for (const opener of [`const z = 'a${BS}`, `const z = "a${BS}`, `const z = /a${BS}`]) {
    const src = [opener, SENTINEL, "const q = 'closing';"].join('\n');
    const mask = codeMask(src);
    const start = src.indexOf(SENTINEL);
    for (let i = 0; i < SENTINEL.length; i++) {
      assert.equal(mask[start + i], 1, `${JSON.stringify(opener)} carried past its line`);
    }
  }
});

test('a long division span on one line is NOT overturned into a regex', () => {
  // Clause (2) asks whether a frame outlived the LINE of the disputed `/`. A
  // minified bundle has no newlines, which makes that test vacuous — so the
  // clause also has to be worth it: overturning must put LESS text on the data
  // channel than leaving the division alone. Without that second test, plain
  // division in tsx's `dist/cli.mjs` was promoted to a 39,468-character "regex"
  // and took all of it off the code channel.
  const filler = 'zz'.repeat(400);
  const minified = `const a=(x)-(y)/n(${filler})>=k;const t=\`tpl\`;const b=1/2/3;`;
  const mask = codeMask(minified);
  // The division operands stay on the code channel: no giant literal appeared.
  const at = minified.indexOf(filler);
  assert.equal(mask[at], 1, 'a long division span was swallowed as a regex body');
  assert.equal(mask[minified.indexOf('const b=1/2/3;')], 1);
});

test('a regex is allowed after `throw` and after `default`', () => {
  // Both legitimately precede a regex and both were missing from EXPR_KEYWORD,
  // so the literal was read as division and its backtick opened a frame. The
  // assertion is that the literal is DATA — i.e. it was read as a regex.
  const thrown = 'function f() { throw /`/; }\nconst after = 1;';
  allMasked(thrown, '/`/', 0);
  allMasked(thrown, 'const after', 1);

  const exported = 'export default /`/;\nconst after = 2;';
  allMasked(exported, '/`/', 0);
  allMasked(exported, 'const after', 1);
});

// The nine refused-position one-liners, as the webhook rule sees them: each is
// valid JavaScript, `node --check` clean and semantically inert, and each took
// the file below it dark before the invariant existed.
for (const [label, line] of Object.entries({
  'if + backtick': 'if (1) /`/.test("x");',
  'while + backtick': 'while (false) /`/.test("x");',
  'for + backtick': 'for (let zq = 0; zq < 0; zq++) /`/.test("x");',
  'throw + backtick': 'function zft() { throw /`/; }',
  'division + backtick': 'const zqd = 4 / /`/.source.length;',
  'if + block-comment opener': 'if (1) /[/*]/.test("x");',
  'while + block-comment opener': 'while (false) /[/*]/.test("x");',
  'throw + block-comment opener': 'function zfb() { throw /[/*]/; }',
  'division + block-comment opener': 'const zqb = 4 / /[/*]/.source.length;',
})) {
  test(`webhook: a swallowed 2xx below "${label}" is still reported`, () => {
    const src = [
      line,
      'export async function POST(req) {',
      '  try {',
      '    await handleStripeEvent(await req.json());',
      '  } catch (e) {',
      "    return new Response('ok', { status: 200 });",
      '  }',
      '}',
      // A real template and a real block comment below, so the loose frame has
      // something to pair with. That is the round-11 half: the frame CLOSES,
      // the scan balances, and only the middle of the file goes dark.
      'const zt = `done ${1}`;',
      '/* trailing */',
    ].join('\n');
    const findings = check({ path: 'stripe-webhook.ts', content: src });
    assert.equal(findings.length, 1, `"${line}" silenced the swallowed 2xx`);
    assert.equal(findings[0].severity, 'critical');
    assert.equal(findings[0].line, 5);
  });
}

// ── clause (2), unconditional ───────────────────────────────────────────────
//
// The three mechanisms that falsified the conditional version of the clause.
// Each is valid JavaScript, `node --check` clean, semantically inert, and each
// took the offence below or beside it dark while the scan ended perfectly
// balanced — so clause (1) saw nothing, and the conditions on clause (2) were
// exactly what let them through:
//
//   M1  the frame the disputed `/` lets loose OPENS AND CLOSES on that `/`'s
//       own line, so both `lineEnd` tests are vacuously false;
//   M2  the disputed span is padded until `frameCostsMore` declines the
//       overturn, which used to leave the darkness standing with no fallback;
//   M3  a quote in the refused regex body opens no second frame at all — it
//       inverts STRING PARITY for the rest of the line.
//
// The assertion is the finding, not the mask: a lexer claim nobody can check
// from the rule's output is not the claim that matters.

const TICK = String.fromCharCode(96);

/** The canonical bypass: a limiter keyed on a header any client can set. */
const LIMITER_HEAD = [
  "import { RateLimiterMemory } from 'rate-limiter-flexible';",
  'const apiLimiter = new RateLimiterMemory({ points: 5, duration: 60 });',
];

for (const [label, source, atLine] of [
  [
    'M1 — a frame that opens and closes on the disputed `/`’s own line',
    [
      ...LIMITER_HEAD,
      'export async function POST(req) {',
      // The refused `/` of /`/ leaves a backtick loose; it pairs with the `t`
      // template at the end of THIS line, so the header read between them is
      // template text. Nothing outlives the line and nothing reaches EOF.
      `  if (1) /${TICK}/.test("x"); const ip = req.headers['x-forwarded-for']; const zz = ${TICK}t${TICK};`,
      '  await apiLimiter.consume(ip);',
      "  return new Response('ok');",
      '}',
    ].join('\n'),
    4,
  ],
  [
    'M2 — a disputed span long enough that the cost guard declines',
    [
      ...LIMITER_HEAD,
      // 1,000 characters of padding make the regex reading more expensive than
      // the frame, so `frameCostsMore` says no. Round 11 then did nothing at
      // all and the template frame below ran over the whole route.
      `if (1) /${'a'.repeat(1000)}${TICK}/.test('x');`,
      'export async function POST(req) {',
      "  const ip = req.headers['x-forwarded-for'];",
      '  await apiLimiter.consume(ip);',
      "  return new Response('ok');",
      '}',
      `const label = ${TICK}done${TICK};`,
    ].join('\n'),
    5,
  ],
  [
    'M3 — a quote in the refused body re-phases the rest of the line',
    [
      ...LIMITER_HEAD,
      'export async function POST(req) {',
      "  if (1) /'/.test('x'); const ip = req.headers['x-forwarded-for'];",
      '  await apiLimiter.consume(ip);',
      "  return new Response('ok');",
      '}',
    ].join('\n'),
    4,
  ],
  [
    'a minified single-line file, where "the rest of the line" is the whole file',
    `${LIMITER_HEAD.join('')}if(1)/${TICK}/.test("x");export async function POST(req){const ip=req.headers["x-forwarded-for"];await apiLimiter.consume(ip);}const L=${TICK}d${TICK};`,
    1,
  ],
]) {
  test(`clause (2): ${label}`, () => {
    const findings = rateLimitCheck({ path: 'app/api/x/route.ts', content: source });
    assert.equal(findings.length, 1, 'the bypass was silenced');
    assert.equal(findings[0].severity, 'high');
    assert.equal(findings[0].line, atLine);
  });
}

test('clause (2): inline JSX SVG — two `/>` on one line leave that line lit', () => {
  // This one is not adversarial, it is what five icons in
  // zpl-finance/src/app/dashboard/layout.tsx already look like. The `/` of the
  // first `/>` is a refused regex whose span reaches the second `/>`, and every
  // attribute string of the second tag opens a frame inside that span. 826
  // characters of that one file used to be classified not-code on the strength
  // of the guess; the whole line is code now.
  const line =
    '    <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" /><rect x="14" y="3" width="7" /></svg>';
  const src = ['export function Icon() {', '  return (', line, '  );', '}', ''].join('\n');
  const mask = codeMask(src);
  const start = src.indexOf(line);

  // Before the first `/>` nothing is disputed, so `viewBox="0 0 24 24"` and the
  // first tag's attributes are ordinary strings and stay on the data channel.
  // From that `/` on, every character belongs to a disputed span or to a frame
  // one let loose, and the whole run is code.
  const disputed = line.indexOf('/>');
  assert.ok(disputed > 0, 'fixture must contain a self-closing tag');
  assert.equal(mask[start + line.indexOf('0 0 24 24')], 0, 'the viewBox string is not disputed');
  for (let i = disputed; i < line.length; i++) {
    assert.equal(mask[start + i], 1, `char ${i} (${JSON.stringify(line[i])}) of the SVG line is dark`);
  }

  // …and the same shape cannot hide a header read that shares its line.
  const withRead = [
    ...LIMITER_HEAD,
    'export async function POST(req) {',
    `    const icon = <svg><rect x="3" /><rect x="14" /></svg>; const ip = req.headers['x-forwarded-for'];`,
    '  await apiLimiter.consume(ip);',
    '}',
  ].join('\n');
  const findings = rateLimitCheck({ path: 'app/api/x/route.tsx', content: withRead });
  assert.equal(findings.length, 1, 'the JSX line swallowed the header read');
  assert.equal(findings[0].line, 4);
});

test('clause (2) manufactures no findings in ordinary code', () => {
  // Failing open can only ADD candidate code, so the risk it carries is
  // spurious findings. Every shape below puts a frame inside a disputed span —
  // a trailing comment after a division, a quoted path, JSX attributes, a
  // template in an interpolation — and none of them is an offence.
  const ordinary = [
    "import { RateLimiterMemory } from 'rate-limiter-flexible';",
    'const apiLimiter = new RateLimiterMemory({ points: 5, duration: 60 });',
    'const half = total / 2; // half of the total, nothing more',
    "const path = base / 2 + '/x-forwarded-for/'; // a URL fragment, not a read",
    'const ratio = (a + b) / c / d;',
    'const pct = `${count / total / 1} %`;',
    'export async function POST(req) {',
    '  await apiLimiter.consume(req.ip);',
    "  return new Response('ok');",
    '}',
  ].join('\n');
  assert.deepEqual(rateLimitCheck({ path: 'app/api/x/route.ts', content: ordinary }), []);
  assert.deepEqual(check({ path: 'app/api/x/route.ts', content: ordinary }), []);

  // The trailing comments really are comments to the reader; what the failing
  // open costs is that their text is searchable. That is the whole price, and
  // it is stated rather than hidden: the mask is fail-open, the finding set is
  // unchanged.
  const mask = codeMask(ordinary);
  assert.equal(mask[ordinary.indexOf('half of the total')], 1);
});

// ── CLI ─────────────────────────────────────────────────────────────────────

test('CLI --json on the webhook fixtures reports exactly the seven positives', () => {
  const r = runCli([FIXTURES, '--json']);
  assert.equal(r.status, 1); // critical findings, default threshold high

  const payload = JSON.parse(r.stdout); // throws if the JSON is invalid
  assert.equal(payload.schemaVersion, 1);
  // Two hand-written fixtures plus the five BAD cases of the adopted C1
  // fixture. Its four GOOD cases are the other half of the number: a total of
  // 7 rather than 11 is the assertion that they stayed silent.
  assert.equal(payload.summary.total, 7);
  assert.equal(payload.summary.critical, 7);
  assert.equal(payload.summary.high, 0);
  assert.equal(payload.scan.filesScanned, 5);
  assert.ok(payload.scan.durationMs >= 0);

  const files = payload.findings.map((f) => f.file).sort();
  assert.deepEqual(files, [
    'app/api/stripe/webhook/route.ts',
    'github-webhook.mjs',
    'webhook-examples.ts',
    'webhook-examples.ts',
    'webhook-examples.ts',
    'webhook-examples.ts',
    'webhook-examples.ts',
  ]);
  for (const f of payload.findings) {
    assert.equal(f.rule, rule);
    assert.equal(f.severity, 'critical');
    assert.ok(Number.isInteger(f.line) && f.line >= 1);
  }
});

test('CLI --fail-on never reports findings but exits 0', () => {
  const r = runCli([FIXTURES, '--json', '--fail-on', 'never']);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).summary.total, 7);
});

test('CLI exits 2 on a nonexistent path', () => {
  const r = runCli(['definitely-not-a-real-dir-xyz']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /prodcheck:/);
});

test('CLI --help exits 0 and prints usage', () => {
  const r = runCli(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /USAGE/);
  assert.match(r.stdout, /--fail-on/);
});

// ── scan scope ──────────────────────────────────────────────────────────────
//
// The extension list is the whole of what a scan can see, and `.cts` was
// missing from it while `.mts` was present. Renaming `route.mts` to `route.cts`
// therefore dropped the file from the walk with the bug untouched. This runs in
// a temp tree rather than tests/fixtures so it cannot move the exact counts the
// fixture-tree assertions depend on.

const SWALLOWER = [
  'export async function POST(req) {',
  '  try {',
  '    await handleStripeEvent(await req.json());',
  '  } catch (e) {',
  "    return new Response('ok', { status: 200 });",
  '  }',
  '}',
].join('\n');

test('.cts and .mts are both scanned, and produce the identical finding', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'prodcheck-scope-'));
  try {
    writeFileSync(path.join(dir, 'webhook-route.mts'), SWALLOWER);
    writeFileSync(path.join(dir, 'webhook-route.cts'), SWALLOWER);

    const payload = JSON.parse(runCli([dir, '--json']).stdout);
    assert.equal(payload.scan.filesScanned, 2, 'renaming .mts to .cts must not drop the file');

    const byFile = Object.fromEntries(payload.findings.map((f) => [f.file, f]));
    assert.deepEqual(Object.keys(byFile).sort(), ['webhook-route.cts', 'webhook-route.mts']);
    assert.equal(byFile['webhook-route.cts'].line, byFile['webhook-route.mts'].line);
    assert.equal(byFile['webhook-route.cts'].severity, 'critical');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an unscanned extension is a filesScanned drop, never a clean report', () => {
  // The point of documenting the scope: every way a file leaves the scan is
  // VISIBLE. `.es6` is not in the list, so the file is never opened — and the
  // scan says so by reporting one file fewer, not by reporting it clean.
  const dir = mkdtempSync(path.join(os.tmpdir(), 'prodcheck-scope-'));
  try {
    writeFileSync(path.join(dir, 'webhook-route.cts'), SWALLOWER);
    writeFileSync(path.join(dir, 'webhook-route.es6'), SWALLOWER);

    const payload = JSON.parse(runCli([dir, '--json']).stdout);
    assert.equal(payload.scan.filesScanned, 1);
    assert.deepEqual(
      payload.findings.map((f) => f.file),
      ['webhook-route.cts']
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
