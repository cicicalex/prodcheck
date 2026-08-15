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

test('CLI --json on the webhook fixtures reports exactly the two positives', () => {
  const r = runCli([FIXTURES, '--json']);
  assert.equal(r.status, 1); // critical findings, default threshold high

  const payload = JSON.parse(r.stdout); // throws if the JSON is invalid
  assert.equal(payload.schemaVersion, 1);
  assert.equal(payload.summary.total, 2);
  assert.equal(payload.summary.critical, 2);
  assert.equal(payload.summary.high, 0);
  assert.equal(payload.scan.filesScanned, 4);
  assert.ok(payload.scan.durationMs >= 0);

  const files = payload.findings.map((f) => f.file).sort();
  assert.deepEqual(files, ['app/api/stripe/webhook/route.ts', 'github-webhook.mjs']);
  for (const f of payload.findings) {
    assert.equal(f.rule, rule);
    assert.equal(f.severity, 'critical');
    assert.ok(Number.isInteger(f.line) && f.line >= 1);
  }
});

test('CLI --fail-on never reports findings but exits 0', () => {
  const r = runCli([FIXTURES, '--json', '--fail-on', 'never']);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).summary.total, 2);
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
