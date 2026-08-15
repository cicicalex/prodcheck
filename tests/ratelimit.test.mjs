/**
 * Tests for the rate-limit-bypass detector and the multi-check registry.
 * node:test + node:assert only — the zero-dependency rule covers dev-time too.
 *
 * Fixture layout: every detector owns one subdirectory of tests/fixtures/, and
 * the per-detector CLI test below scans only its own — tests/fixtures/ratelimit/.
 * That is what keeps its exact counts true forever: fixtures added for rules
 * #3-#7 land in sibling directories and cannot move these numbers. The single
 * test that looks at the whole tree is the aggregation test at the bottom, and
 * it asserts per-rule subsets rather than global totals.
 *
 * tests/fixtures/ratelimit/crossfile/ is a fixture TREE rather than a flat file,
 * because the bug it holds only exists between modules: a lib/ helper, the route
 * that keys a limiter with it, the route that only logs it, a validating variant
 * of the same pair that must stay silent, and a module both phases reach —
 * which must still be reported once.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { check, collect, finalize, rule } from '../src/checks/rate-limit-bypass.mjs';
import * as webhookSwallows from '../src/checks/webhook-swallows-2xx.mjs';
import { checks, LOCKED_PAID_CHECKS } from '../src/checks/index.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(HERE, 'fixtures'); // every detector's fixtures
const FIXTURES = path.join(FIXTURES_ROOT, 'ratelimit'); // this detector's own
const CROSSFILE = path.join(FIXTURES, 'crossfile'); // the multi-file tree
const CLI = path.join(HERE, '..', 'src', 'cli.mjs');

/**
 * The exact remediation prodcheck prints, duplicated here on purpose. Importing
 * the constant would make every assertion about it tautological, and this text
 * is a contract with the reader: the previous value named a helper that does
 * not exist AND carried both tokens of the trust suppression, so pasting it
 * silenced the rule that printed it. A change to these lines should have to be
 * made twice.
 */
const FIX_ADD = [
  "app.set('trust proxy', <hops you control>)  // once, at app setup",
  'const ip = req.ip  // the address the framework resolved, not the raw header',
];

/** Run the detector on one fixture, addressed by its POSIX-relative path. */
function detect(relPosix) {
  const content = readFileSync(path.join(FIXTURES, ...relPosix.split('/')), 'utf8');
  return check({ path: relPosix, content });
}

function runCli(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

/** Phase 1 over an inline {path: source} tree, exactly as the CLI runs it. */
function collectAll(tree) {
  const facts = new Map();
  for (const [relPosix, content] of Object.entries(tree)) {
    const collected = collect({ path: relPosix, content });
    if (collected) facts.set(relPosix, collected); // the CLI stores no nulls
  }
  return facts;
}

/** The same, over real fixture files addressed relative to tests/fixtures/ratelimit. */
function collectFixtures(...relPaths) {
  const tree = {};
  for (const rel of relPaths) tree[rel] = readFileSync(path.join(FIXTURES, ...rel.split('/')), 'utf8');
  return collectAll(tree);
}

/**
 * Assert the single finding a source earns, at a severity and a line.
 *
 * HIGH means "no socket-level source is in scope for this identity, so nothing
 * could have rescued it". MEDIUM means "one is, and prodcheck cannot prove what
 * it governs" — and a MEDIUM must always name the line it saw, because that
 * line is the whole of what the reader has to go and check.
 */
function one(findings, severity, line, socketAt) {
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.severity, severity);
  assert.equal(f.line, line);
  if (severity === 'medium') {
    assert.ok(
      f.impact.includes(`A socket-level fallback is present at ${socketAt},`),
      `expected the impact to name the socket source at ${socketAt}, got: ${f.impact}`
    );
    assert.ok(f.impact.includes('Confirm manually.'));
  } else {
    assert.ok(!f.impact.includes('socket-level fallback'));
  }
  return f;
}

// ── detector ────────────────────────────────────────────────────────────────

test('flags a keyGenerator that reads x-forwarded-for (Next.js middleware)', () => {
  const findings = detect('middleware.ts');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'high');
  assert.equal(f.file, 'middleware.ts');
  assert.equal(f.line, 10); // the line of the header read
  assert.deepEqual(f.fix.remove, [
    `keyGenerator: (req) => req.headers.get('x-forwarded-for') ?? '127.0.0.1',`,
  ]);
  assert.deepEqual(f.fix.add, FIX_ADD);
  assert.ok(f.impact.includes('fresh bucket'));
});

test('the printed remediation is not itself a mute, and needs no helper', () => {
  // The old value was `const ip = getClientIp(req, { trustProxy: TRUSTED_PROXIES })`
  // and it was the worst line in the rule: it named a helper that does not
  // exist — whose obvious stub is the bypass — and it carried both tokens of
  // the trust suppression, so pasting prodcheck's own fix silenced prodcheck.
  const printed = FIX_ADD.join('\n');
  assert.ok(!/getClientIp/.test(printed), 'must not point at a helper that does not exist');
  assert.ok(/req\.ip/.test(printed), 'must resolve through the framework');

  // And the patch, pasted into a live bypass by someone who forgot to delete
  // the old read, must not silence it. This is what the old FIX_ADD did.
  const src = [
    'const limiter = createRateLimiter();',
    `app.set('trust proxy', 2);`,
    'export async function handler(req, res) {',
    '  const ip = req.ip;',
    `  const key = req.headers['x-forwarded-for'];`,
    '  await limiter.consume(key);',
    '}',
  ].join('\n');
  const findings = check({ path: 'pasted-fix.js', content: src });
  assert.equal(findings.length, 1, 'pasting the remediation must not silence the rule');
  assert.equal(findings[0].line, 5);
});

test('flags a header-fed variable that reaches limiter.consume (Express)', () => {
  const findings = detect('express-consume.js');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'high');
  assert.equal(f.line, 10);
  assert.deepEqual(f.fix.remove, [
    `const ip = req.headers['x-forwarded-for'].split(',')[0].trim();`,
  ]);
});

// ── configured proxy trust is not a defence for a hand-rolled read ──────────
//
// A trust-proxy gate used to sit at the top of `check` and return early. It was
// the last one-line mute in the rule: `TRUST_HINT` was a case-insensitive
// substring over the code channel, and `TRUST_SETTING` was matched against
// source with string literals kept. Neither asked where the marker was, what it
// was set TO, or whether it ran. A ~10,500-run mutation sweep drove 78 of 78
// loud files to total silence through it.
//
// It is gone, and the consequence is deliberate: reading X-Forwarded-For by
// hand is reported even when proxy trust IS configured, because correct code in
// that case does not read the header — it reads the address the framework
// resolved from the hops it was told to trust.

test('a file that configures trust proxy and then hand-parses the header is HIGH', () => {
  // express-trust-proxy.js sets `app.set('trust proxy', 1)` and then, four
  // lines later, splits X-Forwarded-For by hand and keys the limiter on it.
  // The setting is real; the code walks straight past it. `req.ip` is the whole
  // point of having set it, and this file never asks for `req.ip`. There is no
  // socket-level source in the handler either, so nothing could have rescued
  // the identity: HIGH.
  const findings = detect('express-trust-proxy.js');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.severity, 'high');
  assert.equal(f.line, 12);
  assert.deepEqual(f.fix.remove, [
    `const ip = req.headers['x-forwarded-for'].split(',')[0].trim();`,
  ]);
  // The report has to say this out loud, or the reader files it as a false
  // positive on sight — they can see the trust setting right there.
  assert.match(f.impact, /reports this read even in a file where trust is configured/);
});

test('the same file goes silent only when the read itself goes away', () => {
  // The discriminating half: keep the trust setting, delete the hand-parse, use
  // the resolved address. THAT is the fix, and it is the only thing that earns
  // silence.
  const src = readFileSync(path.join(FIXTURES, 'express-trust-proxy.js'), 'utf8').replace(
    `const ip = req.headers['x-forwarded-for'].split(',')[0].trim();`,
    'const ip = req.ip;'
  );
  assert.deepEqual(check({ path: 'express-trust-proxy-fixed.js', content: src }), []);
});

// ── the trust suppression read code, not prose — and that was not enough ────
// Matched against source with string literals kept, one log message containing
// the words "trust proxy" silenced every finding in its file. Moving it to the
// code channel only narrowed the mute; it did not close it, because an
// identifier is as easy to write as a string.

test('flags a live bypass in a file whose only "trust proxy" is a log message', () => {
  const findings = detect('trust-words-in-string.js');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'high');
  assert.equal(f.file, 'trust-words-in-string.js');
  assert.equal(f.line, 23); // the header read, not the log line
  assert.deepEqual(f.fix.remove, [
    `const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;`,
  ]);
});

test('a thrown error mentioning trust proxy does not suppress either', () => {
  const src = [
    'const limiter = createRateLimiter();',
    'async function guard(req) {',
    `  if (!process.env.EDGE) throw new Error('set trust proxy before deploying');`,
    `  const ip = req.headers['x-forwarded-for'];`,
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  const findings = check({ path: 'thrown.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 4);
});

test('a trust marker in CODE does not suppress either — an allowlist, an option', () => {
  // A declared allowlist and a framework option are the two markers that were
  // defended longest, on the grounds that they are "configuration facts". They
  // are declarations. Neither says the value was consulted on the path that
  // produced this identity, and an EMPTY allowlist or `trustProxy: false` reads
  // exactly the same to a substring test.
  const allowlist = [
    'const TRUSTED_PROXIES = new Set([process.env.EDGE_IP]);',
    'async function guard(req) {',
    `  const ip = req.headers['x-forwarded-for'];`,
    '  await rateLimiter.consume(ip);',
    '}',
  ].join('\n');
  const option = [
    'const app = Fastify({ trustProxy: true });',
    'async function guard(req) {',
    `  const ip = req.headers['x-forwarded-for'];`,
    '  await rateLimiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'allowlist.js', content: allowlist }), 'high', 3);
  one(check({ path: 'option.js', content: option }), 'high', 3);
});

test('app.enable(\'trust proxy\') does not suppress — a setter key is still not a defence', () => {
  // Express's own configuration API, spelled exactly right, in a real call, on
  // a real app. It is still a file that enables hop validation and then ignores
  // it: `req.ip` is what `enable('trust proxy')` exists to make correct, and
  // this handler never asks for it.
  const src = [
    'const limiter = createRateLimiter();',
    'module.exports = function register(app) {',
    `  app.enable('trust proxy');`,
    '  app.use(async (req, res, next) => {',
    `    const ip = req.headers['x-forwarded-for'];`,
    '    await limiter.consume(ip);',
    '  });',
    '};',
  ].join('\n');
  one(check({ path: 'enable.js', content: src }), 'high', 5);
});

// ── the fourteen one-line mutes, all of them closed ─────────────────────────
//
// Each of these silenced an ENTIRE file, from anywhere in it, for as long as
// the trust gates existed. They are kept as a table because the property under
// test is not any one of them — it is that no grep-visible token is an escape
// hatch. A regression here is a regression to a rule that teaches attackers and
// ordinary developers the same trick.
//
// The bypass below is complete and untouched by every line inserted into it:
// the forwarded header is the limiter's key, and none of these mutations
// changes that.

const LIVE_BYPASS = [
  'const limiter = createRateLimiter();',
  '__MUTATION__',
  'export async function handler(req, res) {',
  `  const ip = req.headers['x-forwarded-for'];`,
  '  await limiter.consume(ip);',
  '  return res.json({ ok: true });',
  '}',
];

const MUTES = [
  ['dead app.set', `if (false) { app.set('trust proxy', 1); }`],
  ['set on an unrelated object', `notAnApp.set('trust proxy', 1);`],
  ['the setting inside a string', `const HINT = "TODO: app.set('trust proxy', 1)";`],
  ['the setting inside a template', 'const DOC = `see app.set(\'trust proxy\', 1)`;'],
  ['dead app.enable', `if (0) app.enable('trust proxy');`],
  ['trust explicitly OFF', 'const trustProxy = false;'],
  ['an EMPTY allowlist', 'const TRUSTED_PROXIES = [];'],
  ['"untrusted prox" matched "trusted prox"', 'let untrustedProxyHits = 0;'],
  ['and so did "distrust prox"', 'const distrustProxyMetrics = null;'],
  ['an option set to false', 'const cfg = { trustProxy: false };'],
  ['a function name', 'function trustProxyTODO() {}'],
  ['an import binding', `import { trustProxy } from './nowhere.js';`],
  // The one that names the bug it hides.
  ['a constant naming the header', `export const TRUSTED_PROXY_HEADER = 'x-forwarded-for';`],
  // The worst of them: prodcheck's OWN former remediation carried both tokens.
  ['prodcheck\'s old printed fix', 'const q = getClientIp(req, { trustProxy: TRUSTED_PROXIES });'],
];

for (const [label, mutation] of MUTES) {
  test(`no longer muted by one line: ${label}`, () => {
    const src = LIVE_BYPASS.join('\n').replace('__MUTATION__', mutation);
    const findings = check({ path: 'muted.js', content: src });
    assert.equal(findings.length, 1, `"${mutation}" silenced a live bypass`);
    assert.equal(findings[0].line, 4);
    assert.equal(findings[0].severity, 'high');
  });
}

test('no longer muted by a TypeScript type alias erased at build time', () => {
  // `type TrustProxy = never` does not exist at runtime at all. It matched the
  // trust substring, so it silenced the file — a mute that compiles to nothing.
  const src = LIVE_BYPASS.join('\n').replace('__MUTATION__', 'type TrustProxy = never;');
  one(check({ path: 'muted.ts', content: src }), 'high', 4);
});

test('the mutes are inert in every position, not just above the read', () => {
  // The sweep that found them inserted at three anchors. Position never
  // mattered to a file-wide substring test, and it must not matter now either.
  const bypass = LIVE_BYPASS.filter((l) => l !== '__MUTATION__');
  for (const [, mutation] of MUTES) {
    for (const at of [0, bypass.length]) {
      const lines = [...bypass];
      lines.splice(at, 0, mutation);
      const findings = check({ path: 'positioned.js', content: lines.join('\n') });
      assert.equal(findings.length, 1, `"${mutation}" at index ${at} silenced the bypass`);
    }
  }
});

// ── the Express accessors ───────────────────────────────────────────────────
//
// `req.header('x-forwarded-for')` and `req.get('x-forwarded-for')` are the two
// most idiomatic Express spellings of this read, and both were SILENT: the
// header-read pattern demanded a receiver containing the token `headers`, and
// `req` does not contain it. Undocumented recall misses, not a design decision.

test('req.header(name) fed to a limiter fires', () => {
  const src = [
    'const limiter = createRateLimiter();',
    'export async function handler(req, res) {',
    `  const ip = req.header('x-forwarded-for');`,
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'req-header.js', content: src }), 'high', 3);
});

test('req.get(name) fed to a limiter fires', () => {
  const src = [
    'const limiter = createRateLimiter();',
    'export async function handler(req, res) {',
    `  const ip = req.get('X-Forwarded-For');`,
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'req-get.js', content: src }), 'high', 3);
});

test('both accessors work on x-real-ip, on any receiver, through optional chaining', () => {
  for (const read of [
    `ctx.req.header('x-real-ip')`,
    `request?.get('x-real-ip')`,
    `req.header('X-Real-IP')`,
  ]) {
    const src = [
      'const limiter = createRateLimiter();',
      'export async function handler(req, res) {',
      `  const ip = ${read};`,
      '  await limiter.consume(ip);',
      '}',
    ].join('\n');
    one(check({ path: 'accessor.js', content: src }), 'high', 3);
  }
});

test('the accessors are a READ, so a two-argument call is not one', () => {
  // The single-argument shape is what separates reading a header from writing
  // one. `res.header(name, value)` and `headers.set(name, value)` SET the
  // header — they cannot key a limiter, and flagging them would be noise on
  // every proxy in the world.
  const src = [
    'const limiter = createRateLimiter();',
    'export async function handler(req, res) {',
    `  res.header('x-forwarded-for', upstreamIp);`,
    `  res.headers.set('x-real-ip', upstreamIp);`,
    '  await limiter.consume(req.ip);',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'setter.js', content: src }), []);
});

test('a plain .get() on something unrelated is not dragged in by the widening', () => {
  // The receiver constraint is gone for the accessor forms, so the header NAME
  // is the whole gate. A `.get()` keyed on anything else stays invisible.
  const src = [
    'const limiter = createRateLimiter();',
    'export async function handler(req, res) {',
    `  const ip = cache.get('user-agent');`,
    `  const tier = plans.get('enterprise');`,
    '  await limiter.consume(ip + tier);',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'unrelated-get.js', content: src }), []);
});

// ── the fix that fixes nothing ──────────────────────────────────────────────

test('prodcheck\'s own former remediation, pasted with a stub helper, is reported', () => {
  // The end state of the old advice, reproduced exactly. A developer reads
  // `const ip = getClientIp(req, { trustProxy: TRUSTED_PROXIES })`, writes the
  // helper the only obvious way, and ships. The line contains both suppression
  // tokens, so the file went silent — over a bypass that is byte-for-byte the
  // one they started with.
  const src = [
    `import { RateLimiterMemory } from 'rate-limiter-flexible';`,
    `const rl = new RateLimiterMemory({ points: 5, duration: 60 });`,
    'const TRUSTED_PROXIES = [];',
    'function getClientIp(req, _opts) {',
    `  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();`,
    '}',
    'export async function handler(req, res) {',
    '  const ip = getClientIp(req, { trustProxy: TRUSTED_PROXIES });',
    '  try { await rl.consume(ip); } catch { return res.status(429).end(); }',
    '  return res.json({ ok: true });',
    '}',
  ].join('\n');
  const findings = check({ path: 'badfix.js', content: src });
  assert.equal(findings.length, 1);
  // Reported at the helper's own header read — where the fix actually goes.
  assert.equal(findings[0].line, 5);
  assert.equal(findings[0].severity, 'high');
  // And the remediation it now prints cannot recreate this shape.
  assert.ok(!findings[0].fix.add.join('\n').includes('getClientIp'));
});

test('does not flag a forwarded-header read that only feeds a log line', () => {
  assert.deepEqual(detect('log-only.js'), []);
});

test('does not flag express-rate-limit running on the default req.ip', () => {
  assert.deepEqual(detect('defaults.js'), []);
});

test('x-real-ip resolved via a TRUSTED_PROXIES-gated helper is MEDIUM, not silence', () => {
  // Genuinely defensive code: the header is believed only when the PEER address
  // is one of ours, and the peer address is what the function falls back to.
  // That fallback is a socket-level source in scope for the identity, so the
  // MEDIUM tier is what carries it — a MEDIUM does not fail a build under the
  // default `--fail-on high`. It is no longer silent, because "TRUSTED_PROXIES
  // appears in this file" was never the reason it was safe; the socket-level
  // return is.
  one(detect('real-ip-trusted.js'), 'medium', 12, 'real-ip-trusted.js:14');
});

test('flags an x-real-ip read passed straight into a limiter call', () => {
  const src = [
    'const limiter = createRateLimiter();',
    `const ip = req.headers.get('X-Real-IP');`,
    'await limiter.consume(ip);',
  ].join('\n');
  const findings = check({ path: 'inline.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
});

test('ignores a header read in a file with no rate-limit vocabulary at all', () => {
  const src = `const ip = req.headers['x-forwarded-for'];\nlogRequest(ip);\n`;
  assert.deepEqual(check({ path: 'audit-log.js', content: src }), []);
});

test('reads a header off a bound Headers object, not just off req.headers', () => {
  // `const headersList = headers()` is the App Router idiom, and
  // `headersList.get('x-forwarded-for')` is the same read as
  // `req.headers.get(...)`. Anchoring on the exact token `headers` saw only the
  // second spelling and missed every route written the first way.
  const src = [
    'const buckets = new Map();',
    'function checkRateLimit(ip) { return !buckets.has(ip); }',
    'export async function POST() {',
    '  const headersList = headers();',
    `  const clientIp = headersList.get('x-forwarded-for') ?? 'unknown';`,
    `  if (!checkRateLimit(clientIp)) return new Response('no', { status: 429 });`,
    '}',
  ].join('\n');
  const findings = check({ path: 'app/api/contact/route.ts', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 5);
});

// ── reachability is scoped to the function, exactly like the suppression ────
// (B) matched the assigned variable NAME against every limiter call in the
// file. A name means nothing outside the scope that declares it, so one
// function's limiter answered for another function's variable and a debug log
// was reported as a bypass. The two halves now share one boundary: the
// enclosing FUNCTION body of the read.

test('does not flag a logging-only read that merely shares a name with a limiter key', () => {
  assert.deepEqual(detect('log-only-collision.js'), []);
});

test('renaming the colliding variable changes nothing — the finding was never real', () => {
  // The same file with debugOnly's `ip` renamed to `fwd`. A finding that
  // disappears when an unrelated variable is renamed was reporting the name,
  // not the bug; both spellings must be silent, and for the same reason.
  const src = [
    `const { RateLimiterMemory } = require('rate-limiter-flexible');`,
    'const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });',
    'async function guarded(req) {',
    '  const ip = req.ip;',
    '  await apiLimiter.consume(ip);',
    '}',
    'async function debugOnly(req) {',
    `  const fwd = req.headers['x-forwarded-for'];`,
    `  console.log('chain claims %s', fwd);`,
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'renamed.js', content: src }), []);
});

test('KNOWN FALSE POSITIVE: at module top level the "function" is the whole file', () => {
  // The per-function scoping above is what makes a log-only read safe from a
  // name collision — and a read at MODULE TOP LEVEL has no enclosing function,
  // so the scope it falls back to is the file. There the collision is live
  // again: this `ip` only feeds a console.log, and it is reported because a
  // handler further down keys a limiter on an unrelated variable of the same
  // name. Renaming the top-level `ip` makes it vanish, which is the signature.
  //
  // Asserted rather than fixed: closing it needs the scope table this detector
  // does not have, and module-level request handling is rare. The README
  // discloses it. If a future change gives top-level reads a real scope, this
  // test is the one to invert.
  const src = [
    `const ip = req.headers['x-forwarded-for'];`,
    `console.log('caller', ip);`,
    '',
    'export async function POST(req) {',
    '  const ip = getClientIp(req);',
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'toplevel-collision.js', content: src }), 'high', 1);
});

test('a limiter key above the read still counts — reachability is position-insensitive', () => {
  // The scoping fix bounds the search by FUNCTION, never by position. A key
  // mentioned before the read is as reachable as one after it: a loop or a
  // hoisted call gets there either way, and ordering the two would be a guess
  // about control flow this rule does not model.
  const src = [
    'async function guard(req) {',
    '  let ip;',
    '  const bucket = () => rateLimiter.consume(ip);',
    `  ip = req.headers['x-forwarded-for'];`,
    '  await bucket();',
    '}',
  ].join('\n');
  const findings = check({ path: 'hoisted.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 4);
});

// ── the identity resolved in a helper (cross-function reach) ────────────────
// getClientIp(req) is how real code resolves a client address, and it splits
// the bug in half: the helper reads a forgeable header and returns it, the
// caller keys a limiter with the result. Neither half is a finding on its own.

test('flags a header read returned by a getClientIp helper whose result keys a limiter', () => {
  const findings = detect('helper-getclientip.ts');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'high');
  assert.equal(f.file, 'helper-getclientip.ts');
  // Reported at the header read INSIDE the helper — where the forgeable value
  // enters the program and where the trusted-proxy check belongs — not at the
  // call site, which is only where the consequence shows up.
  assert.equal(f.line, 19);
  assert.deepEqual(f.fix.remove, [`const forwarded = headersList.get('x-forwarded-for');`]);
});

test('follows the return through a line-local variable and an expression built from it', () => {
  const src = [
    'const buckets = new Map();',
    'function checkRateLimit(ip) { return !buckets.has(ip); }',
    'function getIp(req) {',
    `  const forwarded = req.headers.get('x-forwarded-for');`,
    `  if (forwarded) return forwarded.split(',')[0].trim();`,
    `  return 'unknown';`,
    '}',
    'export async function POST(req) {',
    '  const who = getIp(req);',
    `  if (!checkRateLimit(who)) return new Response('no', { status: 429 });`,
    '}',
  ].join('\n');
  const findings = check({ path: 'helper-var.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 4);
});

test('follows a helper call sitting directly inside the limiter arguments', () => {
  const src = [
    'function getIp(req) {',
    `  return req.headers.get('x-forwarded-for');`,
    '}',
    'export async function POST(req) {',
    '  const rl = rateLimit(`login:${getIp(req)}`, 5, 60_000);',
    `  if (!rl.success) return new Response('slow', { status: 429 });`,
    '}',
  ].join('\n');
  const findings = check({ path: 'helper-inline.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
});

test('downgrades to MEDIUM when the helper rescues the identity from the socket', () => {
  // Same two-part shape, but the header only survives inside the helper when a
  // condition independent of it says so. Socket-level code is in scope for that
  // identity, so this is not the confident finding — and it is not silence
  // either, because proving the rescue governs the read is dataflow.
  one(detect('helper-socket-rescue.js'), 'medium', 21, 'helper-socket-rescue.js:22');
});

test('stays silent when the helper returns something other than the header', () => {
  // describeHop's result really does key the limiter — the reach path must
  // follow the RETURNED value, not the bare fact that a helper was called.
  assert.deepEqual(detect('helper-returns-other.js'), []);
});

test('a helper whose result never reaches a limiter is not a finding', () => {
  const src = [
    'const limiter = createRateLimiter();',
    'function getIp(req) {',
    `  return req.headers.get('x-forwarded-for');`,
    '}',
    `console.log('caller is %s', getIp(req));`,
  ].join('\n');
  assert.deepEqual(check({ path: 'helper-unused.js', content: src }), []);
});

test('follows the return value through TWO helpers to the limiter', () => {
  // The path used to stop after one hop, so collapsing the two helpers into
  // one fired while this — the same code after an ordinary refactor — did not.
  const findings = detect('helper-chain-two-hops.js');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'high');
  assert.equal(f.file, 'helper-chain-two-hops.js');
  assert.equal(f.line, 15); // the read inside forwardedChain, two hops away
  assert.deepEqual(f.fix.remove, [
    `return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();`,
  ]);
});

test('the chain terminates: three helpers that never reach a limiter stay silent', () => {
  // Iterating to a fixed point must not turn "keeps being passed along" into
  // evidence of anything. Nothing here consumes an identity.
  const src = [
    'const limiter = createRateLimiter();',
    `function a(req) { return req.headers.get('x-forwarded-for'); }`,
    'function b(req) { const v = a(req); return v; }',
    'function c(req) { const v = b(req); return v; }',
    `console.log('caller is %s', c(req));`,
  ].join('\n');
  assert.deepEqual(check({ path: 'chain-unused.js', content: src }), []);
});

test('mutually recursive helpers terminate instead of looping forever', () => {
  const src = [
    'const buckets = new Map();',
    'function checkRateLimit(ip) { return !buckets.has(ip); }',
    `function ping(req, n) { return n > 0 ? pong(req, n - 1) : req.headers.get('x-forwarded-for'); }`,
    'function pong(req, n) { return ping(req, n); }',
    'export async function POST(req) {',
    '  const who = ping(req, 2);',
    `  if (!checkRateLimit(who)) return new Response('no', { status: 429 });`,
    '}',
  ].join('\n');
  const findings = check({ path: 'mutual.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 3);
});

test('a helper call is not credited when a LOCAL binding shadows its name', () => {
  // The cross-function twin of the name collision step (B) is scoped against.
  // The module-level getClientIp feeds analytics; inside the handler a local
  // arrow of the same name keys the limiter on the peer address of the socket,
  // which no client can choose. Matching the helper NAME file-wide reported the
  // analytics helper for what the local arrow does.
  const src = [
    'const buckets = new Map();',
    'function checkRateLimit(ip) { return !buckets.has(ip); }',
    'export function getClientIp(req) {',
    `  return String(req.headers['x-forwarded-for'] || '').trim();`,
    '}',
    'export function logRequest(req) {',
    `  track('request', { ip: getClientIp(req) });`,
    '}',
    'export async function handler(req, res) {',
    '  const getClientIp = () => req.socket.remoteAddress;',
    '  if (!checkRateLimit(getClientIp())) return res.status(429).end();',
    '  logRequest(req);',
    '  return res.json({ ok: true });',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'shadowed-helper.js', content: src }), []);
});

test('an unshadowed helper of the same shape still fires', () => {
  // The discriminating half: remove the local binding and the very same
  // module-level helper is the one keying the limiter.
  const src = [
    'const buckets = new Map();',
    'function checkRateLimit(ip) { return !buckets.has(ip); }',
    'export function getClientIp(req) {',
    `  return String(req.headers['x-forwarded-for'] || '').trim();`,
    '}',
    'export async function handler(req, res) {',
    '  if (!checkRateLimit(getClientIp(req))) return res.status(429).end();',
    '  return res.json({ ok: true });',
    '}',
  ].join('\n');
  const findings = check({ path: 'unshadowed-helper.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 4);
});

// ── the return path's own confidence question ───────────────────────────────
// A read bound to no variable leaves by return, so its identity is whatever the
// function hands back. A socket source in any of that function's returns is
// socket-level code in the identity's scope: MEDIUM, never HIGH and never
// silence. Which return, and whether it dominates the read, is the dataflow
// question this rule stopped guessing at.

test('a helper that returns the peer address behind a guard clause is MEDIUM', () => {
  // The peer is read from the socket first and the header is never read at all
  // unless the request physically arrived from an edge node. Correct code — and
  // an honest "I cannot tell", not a confident accusation.
  one(
    detect('helper-guard-clause-return.js'),
    'medium',
    26,
    'helper-guard-clause-return.js:25'
  );
});

test('renaming the allowlist changes nothing — the answer is the data, not the name', () => {
  // The same helper with EDGE_NODES spelled TRUSTED_PROXIES. It used to be
  // silenced by that spelling while its twin was a MEDIUM, which meant the
  // verdict turned on a symbol's NAME. Both are MEDIUM now, on identical
  // evidence: a socket-level source in scope for the identity. Renaming a
  // variable is not a security control.
  const src = readFileSync(
    path.join(FIXTURES, 'helper-guard-clause-return.js'),
    'utf8'
  ).replace(/EDGE_NODES/g, 'TRUSTED_PROXIES');
  const renamed = check({ path: 'renamed-allowlist.js', content: src });
  const original = detect('helper-guard-clause-return.js');
  assert.equal(renamed.length, 1);
  assert.equal(renamed[0].severity, 'medium');
  assert.equal(renamed[0].line, original[0].line);
  assert.equal(renamed[0].severity, original[0].severity);
});

test('a ternary return that discards the forwarded value is MEDIUM', () => {
  // `return cond ? xff : req.socket.remoteAddress` — a condition chooses, so
  // the forged header never gets to stand alone. Identical in meaning to
  // ternary-validated.js, minus the variable in the middle.
  one(detect('helper-ternary-return.js'), 'medium', 21, 'helper-ternary-return.js:22');
});

test('the same helper with a || instead of a ternary still fires', () => {
  // The near-twin, one character of meaning apart: behind `||` the socket
  // address is only what is left when the header is missing, and an attacker
  // is never the absent-header case.
  const src = [
    'const buckets = new Map();',
    'function checkRateLimit(ip) { return !buckets.has(ip); }',
    'function resolveClientIp(req) {',
    `  return String(req.headers['x-forwarded-for'] || '').trim() || req.socket.remoteAddress;`,
    '}',
    'export async function handler(req, res) {',
    '  if (!checkRateLimit(resolveClientIp(req))) return res.status(429).end();',
    '  return res.json({ ok: true });',
    '}',
  ].join('\n');
  const findings = check({ path: 'helper-or-return.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 4);
});

test('a nested coalesce is not the outer choice', () => {
  // `String(xff || '')` defaults that ARGUMENT; it says nothing about what the
  // expression as a whole yields, and the ternary around it is plainly a
  // condition choosing. So the socket address IS in scope for this identity and
  // the finding is MEDIUM. Counting the nested `||` as the outer choice instead
  // would erase the socket source altogether and call this a confident HIGH.
  const src = [
    'const limiter = createRateLimiter();',
    'async function guard(req) {',
    `  let ip = arrivedViaEdge(req) ? String(req.headers['x-forwarded-for'] || '').trim() : req.socket.remoteAddress;`,
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'nested-coalesce.js', content: src }), 'medium', 3, 'nested-coalesce.js:3');
});

test('a coalesce at the top level of the same expression is HIGH, not MEDIUM', () => {
  // One character of meaning apart from the test above. Behind `||` the socket
  // address is only what is left when the header is missing, and an attacker is
  // never the absent-header case — so there is no socket source in scope at all
  // and the finding is the confident one.
  const src = [
    'const limiter = createRateLimiter();',
    'async function guard(req) {',
    `  let ip = String(req.headers['x-forwarded-for'] || '').trim() || req.socket.remoteAddress;`,
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'outer-coalesce.js', content: src }), 'high', 3);
});

test('an anonymous helper body has no name a caller could use, and does not fire', () => {
  // The deliberate edge of the return path: without a resolvable name there is
  // no call site to follow, so this stays silent rather than guessing.
  const src = [
    'const limiter = createRateLimiter();',
    'const ips = reqs.map(function (req) {',
    `  return req.headers.get('x-forwarded-for');`,
    '});',
    'await limiter.consume(ips[0]);',
  ].join('\n');
  assert.deepEqual(check({ path: 'anon-helper.js', content: src }), []);
});

// ── no mute survives ────────────────────────────────────────────────────────
// Seven rounds of adversarial testing produced the same result in six
// spellings: a socket "rescue" on a branch the read never travels — a CORS
// preflight, a catch block, a sibling switch case, a zero-iteration loop, a
// vacuous null check, a default hoisted above the read — muted a live, complete
// bypass with one line that protects no real request. Every attempt to tell
// those apart from a genuine rescue was itself one line wide in the other
// direction. So none of them is silence any more: each is a MEDIUM naming the
// line, beside the correct code it must not be confused with, which is a MEDIUM
// too. A finding can be downgraded; it can no longer be hidden.

const LIMITER_PRELUDE = [
  'const buckets = new Map();',
  'function checkRateLimit(ip) { return !buckets.has(ip); }',
];

const CALLS_RESOLVER = (fn) => [
  'export async function handler(req, res) {',
  `  if (!checkRateLimit(${fn}(req))) return res.status(429).end();`,
  '  return res.json({ ok: true });',
  '}',
];

test('an unrelated early return does not mute the read below it', () => {
  // The one-line mute, on the return path. `req.method === 'OPTIONS'` protects
  // no request an attacker would ever send: every real request still gets its
  // bucket key straight from X-Forwarded-For.
  const src = [
    ...LIMITER_PRELUDE,
    'function forwardedChain(req) {',
    `  if (req.method === 'OPTIONS') return req.socket.remoteAddress;`,
    `  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();`,
    '}',
    ...CALLS_RESOLVER('forwardedChain'),
  ].join('\n');
  one(check({ path: 'preflight-return.js', content: src }), 'medium', 5, 'preflight-return.js:4');
});

test('a guard the CONNECTION decides is a MEDIUM too, braces or none', () => {
  // The correct code the mute above imitates: the condition consults the peer
  // address of the socket, so the header is believed only when the request
  // physically arrived from an edge node. Prodcheck cannot tell the two apart
  // without a control-flow graph — so it says so, at MEDIUM, in both.
  const src = [
    ...LIMITER_PRELUDE,
    `const EDGE_NODES = new Set(['10.0.0.1']);`,
    'function resolveClientIp(req) {',
    '  const peer = req.socket.remoteAddress;',
    '  if (!EDGE_NODES.has(peer)) {',
    '    return peer;',
    '  }',
    `  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || peer;`,
    '}',
    ...CALLS_RESOLVER('resolveClientIp'),
  ].join('\n');
  one(check({ path: 'braced-guard.js', content: src }), 'medium', 9, 'braced-guard.js:7');
});

test('a guard lifted into its own boolean is not a false HIGH', () => {
  // `const trusted = EDGE_NODES.has(peer); if (!trusted) return peer;` — what a
  // linter that dislikes long conditions asks for, and what happens the moment
  // the check is used twice. Requiring the socket expression to appear inside
  // the `if (...)` itself turned this ordinary refactor of correct code into a
  // HIGH. Presence, not shape: the peer address is in scope, so it is MEDIUM.
  const src = [
    ...LIMITER_PRELUDE,
    `const EDGE_NODES = new Set(['10.0.0.1']);`,
    'function resolveClientIp(req) {',
    '  const peer = req.socket.remoteAddress;',
    '  const trusted = EDGE_NODES.has(peer);',
    '  if (!trusted) return peer;',
    `  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || peer;`,
    '}',
    ...CALLS_RESOLVER('resolveClientIp'),
  ].join('\n');
  one(check({ path: 'lifted-guard.js', content: src }), 'medium', 8, 'lifted-guard.js:7');
});

test('a mixed helper is HIGH on the branch nothing guards, and reported there', () => {
  // A fast path for one header spelling beside a careful path for another is
  // how these functions actually rot. The x-real-ip read binds a NAME, and that
  // name is never given a socket address anywhere in the function — a different
  // identity from the `peer` two lines down, and a confident finding. The
  // function earns one row, and it is this read's.
  const src = [
    ...LIMITER_PRELUDE,
    `const EDGE_NODES = new Set(['10.0.0.1']);`,
    'export function resolveIdentity(req) {',
    `  const realIp = req.headers['x-real-ip'];`,
    '  if (realIp) return String(realIp).trim();',
    '  const peer = req.socket.remoteAddress;',
    '  if (!EDGE_NODES.has(peer)) return peer;',
    `  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || peer;`,
    '}',
    ...CALLS_RESOLVER('resolveIdentity'),
  ].join('\n');
  one(check({ path: 'mixed-helper.js', content: src }), 'high', 5); // the x-real-ip branch
});

test('the branch a connection test selected is a MEDIUM, not silence', () => {
  // The same check written the other way round: the header is read only inside
  // the branch the socket test chose, and the branch it did not choose hands
  // back the peer address. Correct — and indistinguishable, lexically, from
  // `if (req.socket.remoteAddress) { return forwarded }`, which decides nothing
  // at all because that string is non-empty on every TCP connection.
  const src = [
    ...LIMITER_PRELUDE,
    `const EDGE_NODES = new Set(['10.0.0.1']);`,
    'function resolveClientIp(req) {',
    '  if (EDGE_NODES.has(req.socket.remoteAddress)) {',
    `    return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();`,
    '  }',
    '  return req.socket.remoteAddress;',
    '}',
    ...CALLS_RESOLVER('resolveClientIp'),
  ].join('\n');
  one(check({ path: 'selected-branch.js', content: src }), 'medium', 6, 'selected-branch.js:8');
});

test('the vacuous socket condition that mutes nothing any more', () => {
  // `if (req.socket.remoteAddress)` consults the connection and decides nothing:
  // the peer address is a non-empty string on every connection Node hands a
  // handler, so the `if` is always taken and the raw header owns the bucket.
  // Crediting a condition merely for mentioning a socket made this a one-line
  // mute of the discriminator that existed to catch one-line mutes.
  const src = [
    ...LIMITER_PRELUDE,
    'function resolveClientIp(req) {',
    '  if (req.socket.remoteAddress) {',
    `    return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();`,
    '  }',
    '  return req.socket.remoteAddress;',
    '}',
    ...CALLS_RESOLVER('resolveClientIp'),
  ].join('\n');
  one(check({ path: 'vacuous-guard.js', content: src }), 'medium', 5, 'vacuous-guard.js:7');
});

test('a socket binding in a sibling branch does not mute the identity', () => {
  // The same one-line mute on the per-variable path. That `const ip` dies at
  // the closing brace three lines above and never reaches the limiter; the one
  // the limiter consumes is the forwarded chain. Reported — at MEDIUM, because
  // proving the binding is a different one needs a scope table.
  const src = [
    'const rl = createRateLimiter();',
    'export async function guard(req, res) {',
    `  if (req.method === 'OPTIONS') {`,
    '    const ip = req.socket.remoteAddress;',
    `    req.log.debug({ ip }, 'preflight');`,
    '    return res.status(204).end();',
    '  }',
    `  const ip = String(req.headers['x-forwarded-for'] || '').trim();`,
    '  await rl.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'sibling-binding.js', content: src }), 'medium', 8, 'sibling-binding.js:4');
});

test('the socket default hoisted ABOVE the read is reported too', () => {
  // The reorder mute: `let ip = req.socket.remoteAddress` is dead by the time
  // the limiter runs, because the read below overwrites it on every request
  // that carries the header. Direction is exactly what a lexical pass cannot
  // establish, so it no longer tries — and no longer goes quiet.
  const src = [
    'const rl = createRateLimiter();',
    'export async function guard(req, res) {',
    '  let ip = req.socket.remoteAddress;',
    `  if (req.method === 'POST') {`,
    `    ip = String(req.headers['x-forwarded-for'] || '').trim();`,
    '  }',
    '  await rl.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'hoisted-default.js', content: src }), 'medium', 5, 'hoisted-default.js:3');
});

test('a rescue in a catch block, which a header read cannot reach, is reported', () => {
  // Reading a header off a plain object does not throw, so the catch body runs
  // on no request an attacker sends. A `try` around the read plus a socket
  // fallback in the handler is a two-line, entirely natural-looking diff.
  const src = [
    'const rl = createRateLimiter();',
    'export async function guard(req, res) {',
    `  let ip = 'unknown';`,
    '  try {',
    `    ip = String(req.headers['x-forwarded-for'] || '').trim();`,
    '  } catch (err) {',
    '    ip = req.socket.remoteAddress;',
    '  }',
    '  await rl.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'catch-rescue.js', content: src }), 'medium', 5, 'catch-rescue.js:7');
});

test('a rescue in a sibling switch case is reported', () => {
  // `switch` cases are labels inside ONE brace block, so a sibling branch there
  // is not a sibling block: any dominance test drawn with brace matching alone
  // read "earlier in the same block" as "dominates" and went silent.
  const src = [
    'const rl = createRateLimiter();',
    'export async function guard(req, res) {',
    '  let ip;',
    '  switch (req.method) {',
    `    case 'OPTIONS':`,
    '      ip = req.socket.remoteAddress;',
    '      break;',
    '    default:',
    `      ip = String(req.headers['x-forwarded-for'] || '').trim();`,
    '  }',
    '  await rl.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'switch-rescue.js', content: src }), 'medium', 9, 'switch-rescue.js:6');
});

test('a rescue in a body that may run zero times is reported', () => {
  // A loop over an empty diagnostics queue never executes, so `ip` stays what
  // the client sent on every ordinary request.
  const src = [
    'const rl = createRateLimiter();',
    'export async function guard(req, res) {',
    `  let ip = String(req.headers['x-forwarded-for'] || '').trim();`,
    '  for (const probe of pendingProbes) {',
    '    ip = req.socket.remoteAddress;',
    '  }',
    '  await rl.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'loop-rescue.js', content: src }), 'medium', 3, 'loop-rescue.js:5');
});

test('the same assignment one level OUT is a MEDIUM, like every other rescue', () => {
  // The distinction the old dominance test drew, at its smallest. It is not
  // drawn any more: an enclosing block, a sibling block and a loop body all read
  // the same way, because which of them the limiter actually sees is a dataflow
  // question. What changed is the cost of not knowing — a MEDIUM, not silence.
  const src = [
    'const rl = createRateLimiter();',
    'export async function guard(req, res) {',
    `  let ip = String(req.headers['x-forwarded-for'] || '').trim();`,
    `  if (!arrivedViaEdge(req)) ip = req.socket.remoteAddress;`,
    '  await rl.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'enclosing-rescue.js', content: src }), 'medium', 3, 'enclosing-rescue.js:4');
});

// ── one finding per function ────────────────────────────────────────────────
// A helper resolving its identity from two headers in a row is one bug with
// one fix. Reported per line it was two rows and two identical diffs, while the
// same helper reached across files was one — the cross-file phase has always
// counted per function, and now both do.

test('two forgeable reads in one function are one finding, at the first', () => {
  const src = [
    ...LIMITER_PRELUDE,
    'function getClientIp(headersList) {',
    `  const forwarded = headersList.get('x-forwarded-for');`,
    `  if (forwarded) return forwarded.split(',')[0].trim();`,
    `  return headersList.get('x-real-ip') || 'unknown';`,
    '}',
    'export async function POST(req) {',
    '  const clientIp = getClientIp(req.headers);',
    '  if (!checkRateLimit(clientIp)) return new Response(null, { status: 429 });',
    '  return Response.json({ ok: true });',
    '}',
  ].join('\n');
  const findings = check({ path: 'two-reads.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 4); // the first read, where the fix goes
  assert.deepEqual(findings[0].fix.remove, [
    `const forwarded = headersList.get('x-forwarded-for');`,
  ]);
  // …and the row says the line below it needs the same treatment.
  assert.match(findings[0].impact, /2 forgeable header reads in this function/);
});

test('reads in DIFFERENT functions are still separate findings', () => {
  // The grouping is per function, not per file: two handlers keying two
  // limiters on two forgeable identities are two things to fix.
  const src = [
    'const rl = createRateLimiter();',
    'async function login(req) {',
    `  const ip = req.headers['x-forwarded-for'];`,
    '  await rl.consume(ip);',
    '}',
    'async function api(req) {',
    `  const caller = req.headers['x-real-ip'];`,
    '  await rl.consume(caller);',
    '}',
  ].join('\n');
  const findings = check({ path: 'two-handlers.js', content: src });
  assert.deepEqual(findings.map((f) => f.line), [3, 7]);
  for (const f of findings) assert.ok(!/forgeable header reads in this function/.test(f.impact));
});

// ── bare-function limiter calls ─────────────────────────────────────────────
// A hand-rolled limiter is invoked as `checkRateLimit(ip)`, with no receiver to
// corroborate the verb — and it is exactly the kind with no `trust proxy`
// setting anywhere near it.

test('flags an identity consumed by a bare checkRateLimit(ip) call', () => {
  const findings = detect('bare-check-ratelimit.js');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.file, 'bare-check-ratelimit.js');
  assert.equal(f.line, 23);
  assert.deepEqual(f.fix.remove, [`const ip = req.headers['x-forwarded-for'];`]);
});

test('flags a bare rateLimit(key, limit, windowMs) call keyed on a template', () => {
  const src = [
    `import { rateLimit } from './rate-limit';`,
    'export async function POST(req) {',
    `  const ip = req.headers.get('x-forwarded-for');`,
    '  const rl = rateLimit(`login:${ip}`, 5, 60_000);',
    `  if (!rl.success) return new Response('slow', { status: 429 });`,
    '}',
  ].join('\n');
  const findings = check({ path: 'login/route.ts', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 3);
});

test('a bare check() or limit() call is too generic to be a limiter', () => {
  // The noise bar for bare calls is higher than for methods, because there is
  // no receiver to agree with the verb. The limiter-ish word has to be in the
  // callee name itself.
  const src = [
    'const rateLimiterReady = true;',
    'async function handler(req) {',
    `  const ip = req.headers['x-forwarded-for'];`,
    '  if (!check(ip)) return;',
    '  limit(ip);',
    '  console.log(ip);',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'generic-calls.js', content: src }), []);
});

test('a limiter DEFINITION is not a limiter call', () => {
  // `function rateLimit(key, limit, windowMs)` is where the limiter is written,
  // not where an identity is handed to it. Reading its parameter list as an
  // argument list put `key` into the reachability search, so every file that
  // defined a limiter and read a header anywhere reported itself.
  const src = [
    'export function rateLimit(key, limit, windowMs) {',
    '  return { key, limit, windowMs };',
    '}',
    `const key = req.headers['x-forwarded-for'];`,
    `console.log('chain %s', key);`,
  ].join('\n');
  assert.deepEqual(check({ path: 'limiter-def.js', content: src }), []);
});

test('method shorthand is a DEFINITION too, keyword or no keyword', () => {
  // `rateLimitKey(ip) { ... }` in an object literal defines a key builder; its
  // parameter list is not an argument list. Read as a call, the parameter name
  // `ip` entered the reachability search and the logging-only read two lines
  // above it — same function, same name — reported itself.
  assert.deepEqual(detect('method-shorthand-definition.js'), []);
});

test('a class method named like a limiter is not a call either', () => {
  const src = [
    'class Bucket {',
    '  rateLimit(key) {',
    '    return this.map.get(key);',
    '  }',
    '}',
    'function logForwarded(req) {',
    `  const key = req.headers['x-forwarded-for'];`,
    `  console.log('chain %s', key);`,
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'class-method.js', content: src }), []);
});

test('a real bare call whose result is destructured still counts', () => {
  // The `{` test looks only at what FOLLOWS the parameter list, so a call whose
  // arguments or result involve braces is untouched.
  const src = [
    `import { rateLimit } from './rate-limit';`,
    'export async function POST(req) {',
    `  const ip = req.headers.get('x-forwarded-for');`,
    '  const { success } = rateLimit({ key: ip, max: 5 });',
    `  if (!success) return new Response('slow', { status: 429 });`,
    '}',
  ].join('\n');
  const findings = check({ path: 'destructured.ts', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 3);
});

test('constructing a limiter is not consuming an identity', () => {
  // `new RateLimiterMemory({ points: 10 })` configures a limiter; it never
  // receives a caller's identity. Counting it as a call made the config object
  // an argument list, and any variable sharing a name with an option key —
  // `points` here — reached a limiter that never saw it.
  const src = [
    `const points = req.headers['x-real-ip'];`,
    'const limiter = new RateLimiterMemory({ points: 10, duration: 60 });',
    'console.log(points);',
  ].join('\n');
  assert.deepEqual(check({ path: 'limiter-new.js', content: src }), []);
});

// ── which variable the read lands in ────────────────────────────────────────

test('binds the read to the declarator nearest it in a comma-separated list', () => {
  // `const a = 1, ip = <read>` binds the read to `ip`. Matching only the
  // declarator that directly follows the keyword answered `a`, which never
  // appears near a limiter — so the read reached nothing, and this file, a
  // straightforward bypass, produced no finding at all.
  const src = [
    'const limiter = createRateLimiter();',
    `const a = 1, ip = req.headers['x-forwarded-for'];`,
    'await limiter.consume(ip);',
  ].join('\n');
  const findings = check({ path: 'multi-declarator.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
});

test('a single-declarator declaration still binds the read to its own name', () => {
  // The near-twin of the case above, and the shape that already worked: the
  // fix for declaration lists must not disturb it.
  const src = [
    'const limiter = createRateLimiter();',
    `const ip = req.headers['x-forwarded-for'];`,
    'await limiter.consume(ip);',
  ].join('\n');
  const findings = check({ path: 'single-declarator.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
});

test('a declaration list whose nearest declarator is rescued is MEDIUM, not HIGH', () => {
  // Same list shape, now with the rescue `ip` genuinely gets. Binding the read
  // to the right variable has to work in both directions, or the fix above
  // would just be trading a false negative for a false positive: bound to `a`,
  // this would find no socket source at all and claim HIGH.
  const src = [
    'const limiter = createRateLimiter();',
    'async function guard(req) {',
    `  let a = 1, ip = req.headers['x-forwarded-for'];`,
    '  if (!fromGateway(req)) ip = req.socket.remoteAddress;',
    '  await limiter.consume(ip, a);',
    '}',
  ].join('\n');
  one(
    check({ path: 'multi-declarator-rescued.js', content: src }),
    'medium',
    3,
    'multi-declarator-rescued.js:4'
  );
});

// ── the socket-source confidence decision ───────────────────────────────────
// The identity is *given* an address the client cannot forge somewhere in the
// enclosing function. That is evidence the untrusted header may have been
// handled — evidence that survives renaming, unlike the trust-hint name match —
// and it downgrades the finding to MEDIUM. It never silences one, because
// proving that write governs this read needs the control-flow graph this rule
// does not build.
//
// Two things that look like it and are not, and both stay HIGH. A `||`, `??` or
// `||=` fallback reaches the socket address only when the header is absent, and
// the attacker is never the absent-header case. And a socket assignment to a
// DIFFERENT name — in another function, or to another variable in this one — is
// a different identity. The tests below pair each shape with its near-twin.

test('an identity reassigned from req.socket.remoteAddress is MEDIUM', () => {
  // The validator here is named isBehindKnownGateway: no trust-flavoured
  // substring anywhere in the file, so nothing but the data decides this.
  one(detect('socket-fallback.js'), 'medium', 20, 'socket-fallback.js:21');
});

test('still flags the same shape when the socket fallback is missing', () => {
  const findings = detect('socket-fallback-absent.js');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'high');
  assert.equal(f.file, 'socket-fallback-absent.js');
  assert.equal(f.line, 19);
  assert.deepEqual(f.fix.remove, [
    `let ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();`,
  ]);
});

test('flags an identity whose only socket source is a ||= fallback on req.ip', () => {
  // `ip ||= req.ip` runs only when the header produced nothing. An attacker
  // always sends the header, so for them the line never executes and the
  // forgeable value keys the bucket unchallenged — this is the bug, not a fix.
  const src = [
    'const limiter = createRateLimiter();',
    `let ip = req.headers.get('x-forwarded-for');`,
    'ip ||= req.ip;',
    'await limiter.consume(ip);',
  ].join('\n');
  const findings = check({ path: 'coalesce.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
});

test('flags a ||-fallback identity bound to a variable and then consumed', () => {
  const findings = detect('or-fallback.js');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'high');
  assert.equal(f.file, 'or-fallback.js');
  assert.equal(f.line, 13);
  assert.deepEqual(f.fix.remove, [
    `const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;`,
  ]);
});

test('flags a ??-fallback identity — nullish changes what counts as missing, not who decides', () => {
  const findings = detect('nullish-fallback.js');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'nullish-fallback.js');
  assert.equal(findings[0].line, 11);
  assert.deepEqual(findings[0].fix.remove, [
    `const ip = req.headers['x-forwarded-for'] ?? req.socket.remoteAddress;`,
  ]);
});

test('flags a ||= fallback written as its own statement', () => {
  const findings = detect('coalesce-assign.js');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 12); // the x-real-ip read, not the ||= line
  assert.deepEqual(findings[0].fix.remove, [`let ip = req.headers['x-real-ip'];`]);
});

test('a ?? fallback inside a keyGenerator is still the header, not the socket', () => {
  const src = [
    'const limiter = rateLimit({',
    `  keyGenerator: (req) => req.headers['x-forwarded-for'] ?? req.socket.remoteAddress,`,
    '});',
  ].join('\n');
  const findings = check({ path: 'kg-fallback.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
});

test('the decision stops at the function: a rescued handler does not cover its neighbour', () => {
  // safeRoute assigns its own local `ip` from req.socket.remoteAddress. That
  // says nothing about unsafeRoute, which reuses the name and validates nothing:
  // that one is HIGH, with no socket source in its scope at all. Searching the
  // file instead of the function would downgrade a confident finding to MEDIUM
  // on the strength of an unrelated handler.
  const findings = detect('scope-collision.js');
  assert.equal(findings.length, 2);
  const [safe, unsafe] = findings;
  assert.equal(safe.severity, 'medium');
  assert.equal(safe.line, 20);
  assert.equal(unsafe.severity, 'high');
  assert.equal(unsafe.line, 26);
  assert.ok(!unsafe.impact.includes('socket-level fallback'));
  assert.deepEqual(unsafe.fix.remove, [`const ip = req.headers['x-forwarded-for'];`]);
});

test('the scope is the whole function: a rescue in a nested block counts', () => {
  // The `if` body is inside the function that holds the read, so it is in
  // range — and an `if` is not a function, so it is not cut out as a nested
  // scope either.
  const src = [
    'async function guard(req) {',
    `  let ip = req.headers['x-forwarded-for'];`,
    '  if (!fromGateway(req)) {',
    '    ip = req.socket.remoteAddress;',
    '  }',
    '  await rateLimiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'nested.js', content: src }), 'medium', 2, 'nested.js:4');
});

// ── the scope is the function body, not the block ───────────────────────────
// The block a read sits in is smaller than the identity it resolves: a rescue
// one level out is in the same function and belongs to the same identity. The
// function is the unit for the same reason a variable name is — it is what
// bounds the binding.

test('reads whose rescue sits in an ancestor scope are MEDIUM, not HIGH', () => {
  // Reads inside if/else bodies, override one level out in the handler body.
  // Anchored on the read's own block that override is invisible, and this
  // correct file drew two confident findings.
  const findings = detect('ancestor-scope-rescue.js');
  one(findings, 'medium', 27, 'ancestor-scope-rescue.js:31');
});

test('a rescue above the read in the same function body still counts', () => {
  // The ancestor case at its smallest: nothing nested at all, the override
  // simply precedes the block the read sits in.
  const src = [
    'async function guard(req) {',
    '  let ip = req.socket.remoteAddress;',
    '  if (fromGateway(req)) {',
    `    ip = req.headers['x-forwarded-for'];`,
    '  }',
    '  await rateLimiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'rescue-above.js', content: src }), 'medium', 4, 'rescue-above.js:2');
});

// ── closures: two shapes prodcheck genuinely cannot tell apart ──────────────
// A closure that DECLARES its own `ip` rescues nothing; a closure that ASSIGNS
// the enclosing `ip` rescues it outright. They differ by one keyword and the
// scope table this detector does not have. Excluding nested bodies made the
// first a HIGH and the second a false HIGH; including them makes both a MEDIUM,
// which is exactly what prodcheck knows about either.

test('a socket assignment shadowed in a nested closure is MEDIUM', () => {
  // auditPeer declares its OWN `ip`. Different variable, same spelling.
  const findings = detect('nested-closure-shadow.js');
  one(findings, 'medium', 18, 'nested-closure-shadow.js:21');
  assert.deepEqual(findings[0].fix.remove, [`const ip = req.headers['x-forwarded-for'];`]);
});

test('a nested function body counts whichever way it is spelled', () => {
  // The arrow of the fixture, plus `function () {}` and method shorthand.
  const src = [
    'async function handler(req) {',
    `  const ip = req.headers['x-forwarded-for'];`,
    '  const audit = function () { const ip = req.socket.remoteAddress; log(ip); };',
    '  const tools = { peer(req) { const ip = req.connection.remoteAddress; return ip; } };',
    '  audit(); tools.peer(req);',
    '  await rateLimiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'shadow-forms.js', content: src }), 'medium', 2, 'shadow-forms.js:3');
});

test('a closure that ASSIGNS the outer identity is no longer a false HIGH', () => {
  // This closure writes the handler's `ip` rather than declaring its own, so
  // the rescue is real and a HIGH here was a false alarm the README used to
  // document. It is a MEDIUM now, alongside the shadowing case above — and
  // there is nothing left to document, because both answers are honest.
  const src = [
    'async function handler(req) {',
    `  let ip = req.headers['x-forwarded-for'];`,
    '  const pin = () => { ip = req.socket.remoteAddress; };',
    '  if (!fromGateway(req)) pin();',
    '  await rateLimiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'closure-assign.js', content: src }), 'medium', 2, 'closure-assign.js:3');
});

test('an identity chosen by a ternary rather than a fallback is MEDIUM', () => {
  one(detect('ternary-validated.js'), 'medium', 20, 'ternary-validated.js:21');
});

test('the ternary shape `ip = trusted ? xff : req.socket.remoteAddress` is MEDIUM', () => {
  const src = [
    'const limiter = createRateLimiter();',
    `let ip = req.headers['x-forwarded-for'];`,
    'ip = fromGateway(req) ? ip : req.socket.remoteAddress;',
    'await limiter.consume(ip);',
  ].join('\n');
  one(check({ path: 'ternary.js', content: src }), 'medium', 2, 'ternary.js:3');
});

test('an identity overwritten unconditionally from the socket is MEDIUM', () => {
  one(detect('socket-override.js'), 'medium', 11, 'socket-override.js:13');
});

test('optional-chained socket reads in override position are MEDIUM', () => {
  // `req.socket?.remoteAddress` behind a condition, and `req?.socket?.…`
  // outright. The `?.` must not read as the `??` that marks a fallback — read
  // as one, the socket source would vanish and both of these would be HIGH.
  const findings = detect('optional-chain-override.js');
  assert.equal(findings.length, 2);
  for (const f of findings) assert.equal(f.severity, 'medium');
  assert.deepEqual(
    findings.map((f) => f.line),
    [21, 27]
  );
});

test('the confidence decision is per-variable, not per-file', () => {
  const src = [
    'const loginLimiter = new RateLimiterMemory({ points: 5 });',
    'const apiLimiter = new RateLimiterMemory({ points: 100 });',
    '',
    'async function login(req) {',
    `  let who = req.headers['x-forwarded-for'];`,
    '  if (!fromGateway(req)) who = req.socket.remoteAddress;',
    '  await loginLimiter.consume(who);',
    '}',
    '',
    'async function api(req) {',
    `  const caller = req.headers['x-forwarded-for'];`,
    '  await apiLimiter.consume(caller);',
    '}',
  ].join('\n');
  const findings = check({ path: 'two-limiters.js', content: src });
  assert.equal(findings.length, 2);
  assert.equal(findings[0].severity, 'medium'); // `who`, rescued somewhere
  assert.equal(findings[0].line, 5);
  assert.equal(findings[1].severity, 'high'); // `caller`, nothing near it
  assert.equal(findings[1].line, 11);
});

test('a socket read that never feeds the identity does not suppress', () => {
  // req.socket.remoteAddress appears in the file, but only as an argument to a
  // helper — `ip` itself is never assigned from it, so the finding stands.
  const src = [
    'const limiter = createRateLimiter();',
    'const region = lookupRegion(req.socket.remoteAddress);',
    `const ip = req.headers['x-forwarded-for'];`,
    'await limiter.consume(ip);',
  ].join('\n');
  const findings = check({ path: 'decoy.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 3);
});

test('a socket assignment quoted inside a string does not suppress', () => {
  const src = [
    'const limiter = createRateLimiter();',
    `let ip = req.headers['x-forwarded-for'];`,
    `logger.debug('ip = req.socket.remoteAddress');`,
    'await limiter.consume(ip);',
  ].join('\n');
  const findings = check({ path: 'quoted.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
});

// ── cross-file: the seam between a lib/ helper and its routes ───────────────
// The canonical layout — `lib/rate-limit.ts` exports getIp, `routes/**` key a
// limiter with it — split the bug across two files, and a check that sees one
// file at a time saw neither half. Phase 1 (`collect`) writes down the halves,
// phase 2 (`finalize`) joins them.

const CROSSFILE_HELPER = 'crossfile/lib/rate-limit.js';
const HELPER_READ_LINE = 34; // the x-forwarded-for read inside getIp

test('collect records an exported helper that hands a forgeable header back', () => {
  const facts = collect({
    path: CROSSFILE_HELPER,
    content: readFileSync(path.join(FIXTURES, 'crossfile', 'lib', 'rate-limit.js'), 'utf8'),
  });
  // One helper, not one per read: getIp reads x-forwarded-for AND x-real-ip,
  // and both are the same bug with the same one line to fix. The second read is
  // still counted — the finding says how much of the function the fix covers.
  assert.equal(facts.helpers.length, 1);
  assert.deepEqual(facts.helpers[0], {
    name: 'getIp',
    line: HELPER_READ_LINE,
    source: `const forwarded = req.headers.get('x-forwarded-for');`,
    reads: 2,
    // 0 means "no socket source in this helper" — the fact that makes the
    // cross-file finding HIGH. `finalize` no longer has the body to ask.
    socketLine: 0,
  });
  assert.ok(facts.exports.includes('getIp'));
});

test('collect records the limiter-reaching call, and not the logging one', () => {
  const consuming = collect({
    path: 'crossfile/routes/register.js',
    content: readFileSync(path.join(CROSSFILE, 'routes', 'register.js'), 'utf8'),
  });
  assert.ok(consuming.calls.includes('getIp'));

  // audit.js imports the same helper from the same module and runs a limiter —
  // but keys it on the authenticated account, and only logs the address.
  const decoy = collect({
    path: 'crossfile/routes/audit.js',
    content: readFileSync(path.join(CROSSFILE, 'routes', 'audit.js'), 'utf8'),
  });
  assert.ok(!decoy.calls.includes('getIp'));
});

test('finalize reports the helper once, at its own header read', () => {
  const findings = finalize(collectFixtures(CROSSFILE_HELPER, 'crossfile/routes/register.js'));
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'high');
  // The helper's file and line — where the forgeable value enters the program
  // and where the trusted-proxy check belongs — never the route that consumes it.
  assert.equal(f.file, CROSSFILE_HELPER);
  assert.equal(f.line, HELPER_READ_LINE);
  assert.deepEqual(f.fix.remove, [`const forwarded = req.headers.get('x-forwarded-for');`]);
  assert.deepEqual(f.fix.add, FIX_ADD);
  assert.ok(f.impact.includes('fresh bucket'));
  // getIp reads x-forwarded-for and then x-real-ip. One row, one fix — and the
  // row says so, exactly as the single-file rule now does for the same shape.
  assert.match(f.impact, /2 forgeable header reads in this function/);
});

test('neither half of the pair is a finding on its own', () => {
  // The whole reason the rule was blind to this: `check` is right about both
  // files, and the bug is only in the seam.
  assert.deepEqual(detect(CROSSFILE_HELPER), []);
  assert.deepEqual(detect('crossfile/routes/register.js'), []);
});

test('the decoy route that only logs the helper causes no finding', () => {
  const findings = finalize(collectFixtures(CROSSFILE_HELPER, 'crossfile/routes/audit.js'));
  assert.deepEqual(findings, []);
});

test('the validating helper is a MEDIUM across files, not a silence', () => {
  // Same two-file shape, same import, same limiter — but the identity is the
  // peer address unless the request really arrived through an edge node. The
  // helper is recorded, carrying the line of the socket source `collect` saw in
  // its body: `finalize` never has that body, so the confidence has to travel
  // with the fact. Recording nothing was the cross-file spelling of the mute
  // the single-file path gave up — one `if (req.method === 'OPTIONS') return
  // req.socket.remoteAddress` in an exported helper silenced every route.
  const facts = collectFixtures(
    'crossfile/safe/lib/client-ip.js',
    'crossfile/safe/routes/login.js'
  );
  const [helper] = facts.get('crossfile/safe/lib/client-ip.js').helpers;
  assert.equal(helper.name, 'resolveClientIp');
  assert.equal(helper.socketLine, 24); // `if (!EDGE_NODES.has(peer)) return peer;`

  one(finalize(facts), 'medium', 25, 'crossfile/safe/lib/client-ip.js:24');
});

// ── the join is by module, not by name ──────────────────────────────────────
// Matching a bare name across a repository would be the collision noise the
// per-function scoping fought, at repository scale.

const HELPER_MODULE = [
  'export function getIp(req) {',
  `  const forwarded = req.headers.get('x-forwarded-for');`,
  `  if (forwarded) return forwarded.split(',')[0].trim();`,
  `  return 'unknown';`,
  '}',
].join('\n');

/** A route that keys a limiter on `local(req)`, importing it from `spec`. */
function route(spec, local = 'getIp', imported = local) {
  const clause = imported === local ? local : `${imported} as ${local}`;
  return [
    `import { rateLimit, ${clause} } from '${spec}';`,
    'export async function POST(req) {',
    '  const rl = rateLimit(`register:${' + local + '(req)}`, 5, 60_000);',
    `  if (!rl.success) return new Response('slow', { status: 429 });`,
    `  return new Response('ok');`,
    '}',
  ].join('\n');
}

test('one finding however many call sites import the helper', () => {
  // The zpl-finance shape: eleven routes, one helper, one line to change.
  const tree = { 'lib/rate-limit.js': HELPER_MODULE };
  for (let i = 0; i < 11; i++) tree[`app/api/r${i}/route.js`] = route('../../../lib/rate-limit.js');

  const findings = finalize(collectAll(tree));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'lib/rate-limit.js');
  assert.equal(findings[0].line, 2);
});

test('a relative specifier resolves to the helper it names', () => {
  const findings = finalize(
    collectAll({ 'lib/ip.js': HELPER_MODULE, 'routes/login.js': route('../lib/ip.js') })
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'lib/ip.js');
});

test('a path alias resolves to the helper it names', () => {
  // `@/lib/ip` is how every Next.js and tsconfig-paths project spells it.
  const findings = finalize(
    collectAll({ 'lib/ip.js': HELPER_MODULE, 'app/api/x/route.ts': route('@/lib/ip') })
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'lib/ip.js');
});

test('an alias import is credited to the name the module exports', () => {
  const findings = finalize(
    collectAll({
      'lib/ip.js': HELPER_MODULE,
      'routes/login.js': route('../lib/ip.js', 'clientIp', 'getIp'),
    })
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'lib/ip.js');
});

test('the same name imported from a DIFFERENT module is not credited', () => {
  // safe-net's getIp resolves the peer address; the vulnerable helper of the
  // same name is in another module entirely and nothing imports it.
  const findings = finalize(
    collectAll({
      'lib/ip.js': HELPER_MODULE,
      'lib/safe-net.js': 'export function getIp(req) { return req.socket.remoteAddress; }',
      'routes/login.js': route('../lib/safe-net.js'),
    })
  );
  assert.deepEqual(findings, []);
});

test('a bare call in the same package is credited when nothing contradicts it', () => {
  const consumer = [
    'export async function POST(req) {',
    '  const rl = rateLimit(`register:${getIp(req)}`, 5, 60_000);',
    `  if (!rl.success) return new Response('slow', { status: 429 });`,
    `  return new Response('ok');`,
    '}',
  ].join('\n');
  const findings = finalize(
    collectAll({ 'lib/ip.js': HELPER_MODULE, 'routes/login.js': consumer })
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'lib/ip.js');
});

test('a bare call is NOT credited when two modules export the name', () => {
  // With no import to disambiguate, `getIp` names nothing in particular.
  const consumer = [
    'export async function POST(req) {',
    '  const rl = rateLimit(`register:${getIp(req)}`, 5, 60_000);',
    `  if (!rl.success) return new Response('slow', { status: 429 });`,
    '}',
  ].join('\n');
  const findings = finalize(
    collectAll({
      'lib/ip.js': HELPER_MODULE,
      'lib/safe-net.js': 'export function getIp(req) { return req.socket.remoteAddress; }',
      'routes/login.js': consumer,
    })
  );
  assert.deepEqual(findings, []);
});

test('a bare call in ANOTHER package is not credited', () => {
  // Nothing in packages/web can reach packages/auth without an import.
  const consumer = [
    'export async function POST(req) {',
    '  const rl = rateLimit(`register:${getIp(req)}`, 5, 60_000);',
    `  if (!rl.success) return new Response('slow', { status: 429 });`,
    '}',
  ].join('\n');
  const findings = finalize(
    collectAll({
      'packages/auth/src/ip.js': HELPER_MODULE,
      'packages/web/routes/login.js': consumer,
    })
  );
  assert.deepEqual(findings, []);
});

test('a CJS destructured require is a binding, not a local definition', () => {
  // `const { getIp } = require('./ip')` reads, to `declaresBinding`, exactly
  // like the local `const { getIp } = require('./safe-net')` that is meant to
  // SHADOW an import — a pattern read whole. So every destructured `require`
  // call site was dropped as "defined here", and the CJS half of
  // `importBindings` could never contribute a finding: the branch existed, was
  // documented, and was unreachable. The names a file binds from a module are
  // now exempt from that test, whichever module system spells them.
  const helper = [
    'module.exports.getIp = function getIp(req) {',
    `  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();`,
    '};',
  ].join('\n');
  const consumer = [
    `const { getIp } = require('../lib/ip');`,
    `const { checkRateLimit } = require('./limiter');`,
    'module.exports = async function login(req, res) {',
    '  const ip = getIp(req);',
    '  if (!checkRateLimit(ip)) return res.status(429).end();',
    '  return res.json({ ok: true });',
    '};',
  ].join('\n');

  const facts = collectAll({ 'lib/ip.js': helper, 'routes/login.js': consumer });
  assert.deepEqual(facts.get('routes/login.js').calls, ['getIp']);
  assert.deepEqual(facts.get('routes/login.js').imports, [
    { imported: 'getIp', local: 'getIp', spec: '../lib/ip' },
  ]);
  one(finalize(facts), 'high', 2); // the header read inside the helper
});

test('an unexported helper is not joined to anything', () => {
  // A module-local function is not a thing another file can call, whatever it
  // happens to be named.
  const findings = finalize(
    collectAll({
      'lib/ip.js': HELPER_MODULE.replace('export function', 'function'),
      'routes/login.js': route('../lib/ip.js'),
    })
  );
  assert.deepEqual(findings, []);
});

test('a helper whose own file keys the limiter is check(), not finalize()', () => {
  // One file, both halves: `check` already reports it, and finalize must not
  // report it a second time from a different angle.
  const src = [
    'const buckets = new Map();',
    'function checkRateLimit(ip) { return !buckets.has(ip); }',
    'export function getClientIp(req) {',
    `  return String(req.headers['x-forwarded-for'] || '').trim();`,
    '}',
    'export async function handler(req, res) {',
    '  if (!checkRateLimit(getClientIp(req))) return res.status(429).end();',
    '  return res.json({ ok: true });',
    '}',
  ].join('\n');
  assert.equal(check({ path: 'both-halves.js', content: src }).length, 1);
  assert.deepEqual(finalize(collectAll({ 'both-halves.js': src })), []);
});

test('a helper in a trust-proxy-configured file IS recorded, and reported', () => {
  // The suppression used to wrap this half too, and it hid more here than
  // anywhere: a helper is a bypass once per route that consumes it, so one
  // `trustProxy: true` in the helper's own module silenced every consumer at
  // once. It cannot be right that a helper handing its caller a raw
  // X-Forwarded-For is safe because of a line in ITS file — the routes are
  // where the identity is used, and this helper gives all of them the same
  // forgeable string. `return 'unknown'` is not a socket source, so: HIGH.
  const helper = [
    'const app = Fastify({ trustProxy: true });',
    'export function getIp(req) {',
    `  const forwarded = req.headers.get('x-forwarded-for');`,
    `  if (forwarded) return forwarded.split(',')[0].trim();`,
    `  return 'unknown';`,
    '}',
  ].join('\n');
  const facts = collectAll({ 'lib/ip.js': helper, 'routes/login.js': route('../lib/ip.js') });
  assert.equal(facts.get('lib/ip.js').helpers.length, 1);
  const findings = finalize(facts);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'lib/ip.js');
  assert.equal(findings[0].line, 3);
  assert.equal(findings[0].severity, 'high');
});

test('finalize on an empty tree, and on facts with no consumers, is silent', () => {
  assert.deepEqual(finalize(new Map()), []);
  assert.deepEqual(finalize(collectAll({ 'lib/ip.js': HELPER_MODULE })), []);
});

// ── CommonJS, and the shapes of it that do and do not join ──────────────────
//
// The `require` half of the join is easy to believe dead and hard to check, so
// it is checked here shape by shape. `module.exports = getIp` was the gap: a
// module whose ONLY export is a bare identifier exported nothing as far as
// `exportedNames` was concerned, so no helper was recorded for it and every
// route requiring it joined to nothing — and that is how a single-function
// CommonJS module is spelled.

/** The same helper, exported the way each module system spells it. */
const CJS_HELPER = [
  'function getIp(req) {',
  `  const forwarded = req.headers.get('x-forwarded-for');`,
  `  if (forwarded) return forwarded.split(',')[0].trim();`,
  `  return 'unknown';`,
  '}',
].join('\n');

/** A CommonJS route that keys a limiter on `local(req)`. */
const cjsRoute = (binding) =>
  [
    `const { RateLimiterMemory } = require('rate-limiter-flexible');`,
    'const apiLimiter = new RateLimiterMemory({ points: 5, duration: 60 });',
    binding,
    'async function POST(req) {',
    '  await apiLimiter.consume(getIp(req));',
    '}',
    'module.exports = { POST };',
  ].join('\n');

for (const [label, helperTail, binding] of [
  ['module.exports = { getIp } + destructured require', 'module.exports = { getIp };', `const { getIp } = require('../lib/ip');`],
  ['exports.getIp = getIp + destructured require', 'exports.getIp = getIp;', `const { getIp } = require('../lib/ip');`],
  ['module.exports = getIp + whole-module require', 'module.exports = getIp;', `const getIp = require('../lib/ip');`],
  ['module.exports = { getIp } + whole-module require', 'module.exports = { getIp };', `const getIp = require('../lib/ip');`],
]) {
  test(`CommonJS cross-file join: ${label}`, () => {
    const findings = finalize(
      collectAll({
        'lib/ip.js': `${CJS_HELPER}\n${helperTail}\n`,
        'routes/login.js': cjsRoute(binding),
      })
    );
    assert.equal(findings.length, 1, 'the require-bound call site did not join');
    assert.equal(findings[0].file, 'lib/ip.js');
    assert.equal(findings[0].line, 2);
    assert.equal(findings[0].severity, 'high');
  });
}

test('`export default getIp` is an export too, and joins the same way', () => {
  const findings = finalize(
    collectAll({
      'lib/ip.js': `${CJS_HELPER}\nexport default getIp;\n`,
      'routes/login.js': [
        `import { RateLimiterMemory } from 'rate-limiter-flexible';`,
        'const apiLimiter = new RateLimiterMemory({ points: 5, duration: 60 });',
        `import getIp from '../lib/ip.js';`,
        'export async function POST(req) {',
        '  await apiLimiter.consume(getIp(req));',
        '}',
      ].join('\n'),
    })
  );
  assert.deepEqual(findings.map((f) => `${f.file}:${f.line}:${f.severity}`), ['lib/ip.js:2:high']);
});

test('the bare-identifier export does not swallow the forms around it', () => {
  // `export default function f`, `export default class C` and
  // `module.exports = require('./x')` all continue past the identifier with
  // something other than a statement end, and none of them may be read as an
  // export named `function`, `class` or `require`.
  const facts = collect({
    path: 'lib/net.js',
    content: [
      'export default function resolve(req) { return req.ip; }',
      'const other = 1;',
    ].join('\n'),
  });
  assert.deepEqual(facts.exports.sort(), ['resolve']);

  const reexport = collect({
    path: 'lib/barrel.js',
    content: `module.exports = require('./ip');\nexport const getIp = (req) => req.ip;\n`,
  });
  assert.deepEqual(reexport.exports.sort(), ['getIp']);
});

test('KNOWN FALSE POSITIVE: a whole-module binding credits any helper in it', () => {
  // `const x = require('./m')` and `import x from './m'` both bind under the
  // name `default`, and the join treats that as a wildcard over the module's
  // exports. So a limiter keyed on the TENANT — which no header can move — is
  // reported against a header-reading helper that merely shares the module.
  // Documented rather than fixed: narrowing it would also drop the legitimate
  // default import, and this is the direction the tool is allowed to be wrong.
  const lib = [
    CJS_HELPER,
    'function tenantOf(req) { return String(req.auth && req.auth.tenantId); }',
    'module.exports = { getIp, tenantOf };',
  ].join('\n');
  const wildcard = finalize(
    collectAll({ 'lib/ip.js': lib, 'routes/login.js': cjsRoute(`const getIp = require('../lib/ip');`) })
  );
  assert.equal(wildcard.length, 1, 'the wildcard binding stopped crediting the module');

  // The named binding carries a name, and checking it is what keeps the join
  // honest: reach the SAFE helper by name and nothing is reported.
  const named = finalize(
    collectAll({
      'lib/ip.js': lib,
      'routes/login.js': [
        `const { RateLimiterMemory } = require('rate-limiter-flexible');`,
        'const apiLimiter = new RateLimiterMemory({ points: 5, duration: 60 });',
        `const { tenantOf } = require('../lib/ip');`,
        'async function POST(req) {',
        '  await apiLimiter.consume(tenantOf(req));',
        '}',
        'module.exports = { POST };',
      ].join('\n'),
    })
  );
  assert.deepEqual(named, []);
});

test('path aliases whose marker also names a directory resolve one level short', () => {
  // `@/lib/x` and `~/lib/x` resolve to `lib/x`, which is right. `$lib/x`,
  // `$app/x` and `#lib/x` resolve to `x`, which is not: the resolver drops the
  // first path segment whatever it is, and for these three the marker IS a
  // directory. Asserted so the limitation cannot quietly change meaning.
  const routeFrom = (spec) =>
    [
      `import { rateLimit, getIp } from '${spec}';`,
      'export async function POST(req) {',
      '  const rl = rateLimit(`register:${getIp(req)}`, 5, 60_000);',
      '  if (!rl.success) return new Response("too many", { status: 429 });',
      '  return new Response("ok");',
      '}',
    ].join('\n');
  const joins = (spec, helperPath) =>
    finalize(collectAll({ [helperPath]: HELPER_MODULE, 'routes/login.js': routeFrom(spec) })).length;

  for (const spec of ['@/lib/ip', '~/lib/ip', '@@/lib/ip']) {
    assert.equal(joins(spec, 'lib/ip.js'), 1, `${spec} should resolve to lib/ip`);
  }
  for (const spec of ['$lib/ip', '$app/ip']) {
    assert.equal(joins(spec, 'lib/ip.js'), 0, `${spec} unexpectedly resolved to lib/ip`);
    assert.equal(joins(spec, 'ip.js'), 1, `${spec} should resolve to the project root`);
  }
  // Node's subpath imports, which the comment on ALIAS_PREFIX used to name as
  // supported, resolve to NOTHING: `specifierKeys` strips a `?query`/`#fragment`
  // suffix before consulting the pattern, and on a specifier beginning with `#`
  // that deletes the whole string. The `#` alternative in ALIAS_PREFIX is dead
  // both ways round. Quieter than resolving it wrongly, and asserted so that
  // reviving it is a deliberate act.
  for (const spec of ['#lib/ip', '#/lib/ip']) {
    assert.equal(joins(spec, 'lib/ip.js'), 0, `${spec} unexpectedly resolved`);
    assert.equal(joins(spec, 'ip.js'), 0, `${spec} unexpectedly resolved`);
  }
});

// ── the two-phase contract itself ───────────────────────────────────────────

test('webhook-swallows-2xx exports neither phase and is untouched', () => {
  assert.equal(webhookSwallows.collect, undefined);
  assert.equal(webhookSwallows.finalize, undefined);
  assert.equal(typeof webhookSwallows.check, 'function');
});

test('collect returns null for a file with nothing to contribute', () => {
  assert.equal(collect({ path: 'unrelated.js', content: 'const sum = (a, b) => a + b;\n' }), null);
});

test('a file with no rate-limit vocabulary still contributes its export names', () => {
  // Not because it could be a finding — it carries neither half — but because
  // a second module exporting `getIp` is what makes a bare-name join ambiguous,
  // and such a module has no reason to mention rate limiting.
  const facts = collect({ path: 'lib/net.js', content: 'export const getIp = (req) => req.ip;\n' });
  assert.deepEqual(facts, { helpers: [], exports: ['getIp'], imports: [], calls: [] });
});

test('CLI --json on the crossfile tree reports each helper exactly once', () => {
  const r = runCli([CROSSFILE, '--json']);
  assert.equal(r.status, 1);

  const payload = JSON.parse(r.stdout);
  assert.equal(payload.scan.filesScanned, 7); // the walk is unchanged by phase 2
  assert.ok(payload.scan.durationMs >= 0);
  assert.equal(payload.summary.total, 3);
  assert.equal(payload.summary.high, 2);
  assert.equal(payload.summary.medium, 1);

  // Three helpers, one finding each: the pure cross-file one, the one both
  // phases reach independently, and the validating twin at MEDIUM.
  assert.deepEqual(
    payload.findings.map((f) => `${f.file}:${f.line}:${f.severity}`),
    [
      'lib/rate-limit.js:34:high',
      'safe/lib/client-ip.js:25:medium',
      'selfuse/lib/limiter.js:25:high',
    ]
  );
  for (const f of payload.findings) assert.equal(f.rule, rule);

  // The default gate is HIGH, so the MEDIUM does not on its own fail a build.
  assert.equal(runCli([path.join(CROSSFILE, 'safe'), '--json']).status, 0);
});

test('a finding both phases produce independently is reported once', () => {
  // selfuse/lib/limiter.js keys a limiter with its own helper AND exports it to
  // routes/search.js, so `check` and `finalize` arrive at the same read from
  // opposite directions. Both are right; the developer has one line to change.
  const helper = 'crossfile/selfuse/lib/limiter.js';
  const route = 'crossfile/selfuse/routes/search.js';
  const source = (rel) => readFileSync(path.join(FIXTURES, ...rel.split('/')), 'utf8');

  const single = check({ path: helper, content: source(helper) });
  assert.deepEqual(single.map((f) => `${f.file}:${f.line}`), [`${helper}:25`]);

  const cross = finalize(collectFixtures(helper, route));
  assert.deepEqual(cross.map((f) => `${f.file}:${f.line}`), [`${helper}:25`]);

  // …and the CLI, which runs both, emits it once.
  const payload = JSON.parse(runCli([path.join(CROSSFILE, 'selfuse'), '--json']).stdout);
  assert.equal(payload.summary.total, 1);
  assert.equal(payload.findings[0].file, 'lib/limiter.js');
  assert.equal(payload.findings[0].line, 25);
});

// ── the lexer: a regex literal must not blind the file ──────────────────────
//
// The code channel did not model regex literals, so a regex whose BODY looked
// like a template or a comment opener put every character below it on the data
// channel — and every search in this rule skips the data channel. The file
// reported clean with the bypass fully intact. These are the exact one-liners,
// each valid JavaScript under `node --check`.

/** A complete, live bypass. Whatever is prepended must not silence it. */
const REGEX_BYPASS = [
  "import { RateLimiterMemory } from 'rate-limiter-flexible';",
  'const apiLimiter = new RateLimiterMemory({ points: 50, duration: 60 });',
  'export async function limitByIp(req, res, next) {',
  "  const ip = req.headers['x-forwarded-for'];",
  '  await apiLimiter.consume(ip);',
  '  next();',
  '}',
];

for (const [label, mute] of Object.entries({
  'a regex holding a backtick': 'const RE_TICK = /`/;',
  'a backtick in a character class': 'const RE_TICK2 = /[`]/;',
  'a /* inside a character class': 'const RE_C = /[/*]/;',
  'a markdown fence stripper': 'const FENCE = /`{3}/g;',
  'a regex holding a double quote': `const RE_Q = /"/g;`,
})) {
  test(`no longer blinded by ${label}`, () => {
    const src = [mute, ...REGEX_BYPASS].join('\n');
    const findings = check({ path: 'muted.js', content: src });
    assert.equal(findings.length, 1, `"${mute}" classified the whole file as not-code`);
    assert.equal(findings[0].severity, 'high');
    assert.equal(findings[0].line, 5);
  });
}

test('the A/B pair from the report: a fence four lines up, and its new RegExp twin', () => {
  // Identical programs, one written with a regex literal and one with the
  // constructor. Before the lexer modelled regex literals the first reported
  // nothing and the second reported HIGH.
  const gap = ['', '', ''];
  const literal = ['const FENCE = /`{3}/g;', ...gap, ...REGEX_BYPASS].join('\n');
  const constructed = ['const FENCE = new RegExp("`{3}", "g");', ...gap, ...REGEX_BYPASS].join('\n');

  const a = check({ path: 'a.js', content: literal });
  const b = check({ path: 'b.js', content: constructed });
  assert.equal(a.length, 1);
  assert.equal(b.length, 1);
  assert.deepEqual(
    a.map((f) => [f.severity, f.line]),
    b.map((f) => [f.severity, f.line])
  );
});

test('a header name INSIDE a regex is data, and does not read as a header read', () => {
  // The other half of modelling regex literals: a literal is data exactly like
  // a string, so vocabulary inside one cannot match. This file has no read.
  const src = [
    'const XFF_RE = /x-forwarded-for/i;',
    'export async function handler(req, res) {',
    '  const ip = req.ip;',
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'regex-name.js', content: src }), []);
});

test('division stays division: `const r = a / b / c;` above a live bypass', () => {
  // A `/` wrongly read as a regex opener would swallow the rest of the line and
  // could unbalance the file — the failure mode this fix exists to remove. The
  // bypass below must still be found, at its own line.
  const src = ['const r = a / b / c;', ...REGEX_BYPASS].join('\n');
  const findings = check({ path: 'division.js', content: src });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 5);
});

// ── the lexer INVARIANT: a REFUSED regex must not blind the file either ─────
//
// Round 10 modelled regex literals and moved this hole rather than closing it.
// The lexer prefers division wherever it cannot tell, and in a refused position
// the regex's own body stays on the CODE channel — so a backtick or a `/*` in
// that body opens a frame the source never intended. A 32,631-run harness put
// 1,310 total silences through exactly this, from the nine lines below, over
// every loud file at every insertion anchor.
//
// Each is valid JavaScript, `node --check` clean, and does nothing at runtime.

const REFUSED_REGEX_LINES = {
  'a regex after `if (…)`': 'if (1) /`/.test("x");',
  'a regex after `while (…)`': 'while (false) /`/.test("x");',
  'a regex after `for (…)`': 'for (let zq = 0; zq < 0; zq++) /`/.test("x");',
  'a regex after `throw`': 'function zft() { throw /`/; }',
  'a regex after a division `/`': 'const zqd = 4 / /`/.source.length;',
  'a /* class after `if (…)`': 'if (1) /[/*]/.test("x");',
  'a /* class after `while (…)`': 'while (false) /[/*]/.test("x");',
  'a /* class after `throw`': 'function zfb() { throw /[/*]/; }',
  'a /* class after a division `/`': 'const zqb = 4 / /[/*]/.source.length;',
};

for (const [label, mute] of Object.entries(REFUSED_REGEX_LINES)) {
  test(`no longer blinded by ${label} in a refused position`, () => {
    const src = [mute, ...REGEX_BYPASS].join('\n');
    const findings = check({ path: 'refused.js', content: src });
    assert.equal(findings.length, 1, `"${mute}" classified the file below it as not-code`);
    assert.equal(findings[0].severity, 'high');
    assert.equal(findings[0].line, 5);
  });

  test(`${label}: still lit when a real frame closer follows it`, () => {
    // The half a pure end-of-file invariant cannot see. With a genuine template
    // and a genuine `*/` below, the loose frame CLOSES against them: the scan
    // ends perfectly balanced and only the middle of the file — the bypass —
    // went dark. This is the shape that survived the first fix.
    const src = [
      mute,
      ...REGEX_BYPASS,
      'const zt = `closing ${1} backtick`;',
      '/* closing block comment */',
    ].join('\n');
    const findings = check({ path: 'refused-paired.js', content: src });
    assert.equal(findings.length, 1, `"${mute}" went dark against a later frame closer`);
    assert.equal(findings[0].severity, 'high');
    assert.equal(findings[0].line, 5);
  });
}

test('`throw` and `default` are expression positions, so the regex is DATA there', () => {
  // Both were missing from EXPR_KEYWORD. The header name inside the literal
  // must not read as a header read — which it only does if the literal was
  // recognised as a regex rather than left in the code channel.
  const thrown = [
    'function boom() { throw /x-forwarded-for/; }',
    'export async function handler(req) {',
    '  const ip = req.ip;',
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'throw-regex.js', content: thrown }), []);

  const exported = [
    'export default /x-forwarded-for/i;',
    'export async function handler(req) {',
    '  const ip = req.ip;',
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'default-regex.js', content: exported }), []);
});

test('the fail-open recovery does not manufacture findings in ordinary code', () => {
  // A correct file carrying every frame kind, plus the division shapes a
  // careless recovery would misread as regex openers. It resolves its address
  // from the framework and must stay SILENT. A lexer that fails open on broken
  // input but also over-reports on ordinary input has just traded one bug for
  // a noisier one.
  const src = [
    '/**',
    ' * Rate limiting for the public API.',
    " * Historically this read req.headers['x-forwarded-for'] — do not go back.",
    ' */',
    "import { RateLimiterMemory } from 'rate-limiter-flexible';",
    'const RE_FENCE = /`{3}/g;',
    'const RE_CLASS = /[/*]/;',
    'const ratio = totalRequests / windowSeconds / 2;',
    "const half = windowSeconds / 2, label = 'ms/req';",
    'const banner = `usage',
    '  ${totalRequests / 2 / 1} per window`;',
    'const apiLimiter = new RateLimiterMemory({ points: 50, duration: 60 });',
    'export async function limitByIp(req, res, next) {',
    '  const ip = req.ip;',
    '  await apiLimiter.consume(ip);',
    '  next();',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'ordinary.js', content: src }), []);
});

test('a genuine multi-line block comment is still a comment after the recovery', () => {
  // The recovery must not reach for the line-bounded fallback on ordinary code:
  // if it did, the second line of every JSDoc would become code and every
  // header name mentioned in prose would read as a live header read.
  const src = [
    '/*',
    " * const ip = req.headers['x-forwarded-for'];",
    ' * await limiter.consume(ip);',
    ' */',
    'export async function handler(req) {',
    '  const ip = req.ip;',
    '  await limiter.consume(ip);',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'jsdoc.js', content: src }), []);
});

// ── the limiter side: `?.`, parentheses, and construction ───────────────────

test('an optional-chained limiter receiver is the same call', () => {
  // `await limiter?.consume(ip)` is a routine defensive edit and was a total
  // mute, while HEADER_READ and SOCKET_SOURCE had allowed `?.` for rounds.
  const src = [
    'const limiter = getLimiter();',
    'export async function handler(req, res) {',
    "  const ip = req.headers['x-forwarded-for'];",
    '  await limiter?.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'optional-receiver.js', content: src }), 'high', 3);
});

test('a parenthesised limiter receiver is the same call', () => {
  const src = [
    'const limiter = getLimiter();',
    'export async function handler(req, res) {',
    "  const ip = req.headers['x-forwarded-for'];",
    '  await (limiter).consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'paren-receiver.js', content: src }), 'high', 3);
});

test('a parenthesised receiver that is not a plain name is not resolved', () => {
  // `(await getLimiter()).consume(ip)` names something this rule cannot resolve
  // to a variable, and guessing would put every `x().consume()` in the report.
  const src = [
    'export async function handler(req, res) {',
    "  const ip = req.headers['x-forwarded-for'];",
    '  await (await buildStore()).consume(ip);',
    '}',
    'const rateLimitWindow = 60;',
  ].join('\n');
  assert.deepEqual(check({ path: 'paren-expr.js', content: src }), []);
});

test('a CONSTRUCTED limiter is a limiter whatever the variable is called', () => {
  // `const guard = …` was silent and `const limiter = …` was HIGH, on the same
  // program. Code written the first way from the start was never checked.
  const src = [
    "import { RateLimiterMemory } from 'rate-limiter-flexible';",
    'const guard = new RateLimiterMemory({ points: 5, duration: 60 });',
    'export async function handler(req, res) {',
    "  const ip = req.headers['x-forwarded-for'];",
    '  await guard.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'constructed.js', content: src }), 'high', 4);
});

test('the same file with the limiter renamed reports identically', () => {
  const body = (name) =>
    [
      "import { RateLimiterMemory } from 'rate-limiter-flexible';",
      `const ${name} = new RateLimiterMemory({ points: 5, duration: 60 });`,
      'export async function handler(req, res) {',
      "  const ip = req.headers['x-forwarded-for'];",
      `  await ${name}.consume(ip);`,
      '}',
    ].join('\n');
  const named = check({ path: 'n.js', content: body('limiter') });
  const unnamed = check({ path: 'u.js', content: body('guard') });
  assert.deepEqual(
    named.map((f) => [f.severity, f.line]),
    unnamed.map((f) => [f.severity, f.line])
  );
});

test('the other constructor and factory spellings are recognised too', () => {
  const cases = {
    'new Ratelimit': "const gate = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(5, '1 m') });",
    'new RateLimiterRedis': 'const gate = new RateLimiterRedis({ storeClient: redis });',
    'rateLimit factory': 'const gate = rateLimit({ windowMs: 60000, max: 5 });',
    'slowDown factory': 'const gate = slowDown({ windowMs: 60000, delayAfter: 5 });',
  };
  for (const [label, decl] of Object.entries(cases)) {
    const src = [
      decl,
      'export async function handler(req, res) {',
      "  const ip = req.headers['x-forwarded-for'];",
      '  await gate.consume(ip);',
      '}',
    ].join('\n');
    const findings = check({ path: 'ctor.js', content: src });
    assert.equal(findings.length, 1, `${label} was not recognised as a limiter`);
    assert.equal(findings[0].line, 3);
  }
});

test('a predicate that merely MENTIONS rate limiting does not bind a limiter', () => {
  // `const allowed = checkRateLimit(ip)` yields a boolean. Treating `allowed`
  // as a limiter receiver would widen the receiver gate on nothing at all.
  const src = [
    'export async function handler(req, res) {',
    '  const allowed = checkRateLimit(req.ip);',
    "  const forwarded = req.headers['x-forwarded-for'];",
    '  logger.info({ forwarded });',
    '  await allowed.check(forwarded);',
    '}',
  ].join('\n');
  // `allowed` is not a limiter, so `allowed.check(forwarded)` is not a limiter
  // call and the forwarded read reaches nothing. Crediting the predicate would
  // have made this a HIGH on a file whose only limiter runs on `req.ip`.
  assert.deepEqual(check({ path: 'predicate.js', content: src }), []);
});

// ── the header side: destructuring, and a name held in a constant ───────────

test('array destructuring binds the identity — `const [ip] = …split(",")`', () => {
  // One of the two most common spellings in the wild, and a total mute: the
  // read landed in no name, so nothing connected it to the limiter below.
  const src = [
    "import { RateLimiterMemory } from 'rate-limiter-flexible';",
    'const apiLimiter = new RateLimiterMemory({ points: 50, duration: 60 });',
    'export async function limitByIp(req, res, next) {',
    "  const [ip] = String(req.headers['x-forwarded-for'] || '').split(',');",
    '  await apiLimiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'array-destructure.js', content: src }), 'high', 4);
});

test('object destructuring binds the identity — `const { "x-forwarded-for": ip }`', () => {
  const src = [
    "import { RateLimiterMemory } from 'rate-limiter-flexible';",
    'const apiLimiter = new RateLimiterMemory({ points: 50, duration: 60 });',
    'export async function limitByIp(req, res, next) {',
    "  const { 'x-forwarded-for': ip } = req.headers;",
    '  await apiLimiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'object-destructure.js', content: src }), 'high', 4);
});

test('an object literal mapping the header name is not a destructuring read', () => {
  // The lookahead is the whole gate: without a `} = …headers` after it, this is
  // a fixture, a mock or a test table, and not a read of anything.
  const src = [
    'const limiter = getLimiter();',
    "const FIXTURE = { 'x-forwarded-for': ip };",
    'export async function handler(req, res) {',
    '  await limiter.consume(req.ip);',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'fixture-object.js', content: src }), []);
});

test('a header name hoisted into a constant is still a header read', () => {
  const src = [
    "import { RateLimiterMemory } from 'rate-limiter-flexible';",
    "const XFF = 'x-forwarded-for';",
    'const apiLimiter = new RateLimiterMemory({ points: 50, duration: 60 });',
    'export async function limitByIp(req, res, next) {',
    '  const ip = req.headers[XFF];',
    '  await apiLimiter.consume(ip);',
    '}',
  ].join('\n');
  one(check({ path: 'name-const.js', content: src }), 'high', 5);
});

test('the constant form works through the accessor spellings too', () => {
  for (const read of ['req.headers.get(H)', 'req.header(H)', 'req.get(H)']) {
    const src = [
      "const H = 'x-real-ip';",
      'const limiter = getLimiter();',
      'export async function handler(req, res) {',
      `  const ip = ${read};`,
      '  await limiter.consume(ip);',
      '}',
    ].join('\n');
    const findings = check({ path: 'accessor-const.js', content: src });
    assert.equal(findings.length, 1, `${read} was not seen`);
    assert.equal(findings[0].line, 4);
  }
});

test('a constant holding an ORDINARY header name admits nothing', () => {
  // The binding is the entire gate: a name is admitted only because this file
  // was seen assigning it one of the two forgeable header strings.
  const src = [
    "const UA = 'user-agent';",
    'const limiter = getLimiter();',
    'export async function handler(req, res) {',
    '  const agent = req.headers[UA];',
    '  await limiter.consume(agent);',
    '}',
  ].join('\n');
  assert.deepEqual(check({ path: 'other-header-const.js', content: src }), []);
});

// ── registry ────────────────────────────────────────────────────────────────

test('registry lists the rules in rule-table order', () => {
  assert.deepEqual(
    checks.map((c) => c.rule),
    ['webhook-swallows-2xx', 'rate-limit-bypass', 'env-secret-fallback']
  );
});

test('registry entries all expose the same check surface', () => {
  for (const c of checks) {
    assert.equal(typeof c.rule, 'string');
    assert.ok(c.extensions instanceof Set && c.extensions.size > 0);
    assert.equal(typeof c.isCandidate, 'function');
    assert.equal(typeof c.check, 'function');
  }
});

test('the upsell arithmetic is true: shipping + locked is the whole design', () => {
  // The report's "→ N more checks" row is a claim about how many rules exist
  // beyond the ones that just ran. Three ship, so four are outstanding — the
  // number moved when env-secret-fallback was appended, and it moved by itself,
  // because LOCKED_PAID_CHECKS is derived from `checks.length` rather than
  // written down. It WAS written down once, as 4 while the README claimed three
  // shipped free, and the two disagreed for a release.
  assert.equal(checks.length, 3);
  assert.equal(LOCKED_PAID_CHECKS, 4);
  assert.equal(checks.length + LOCKED_PAID_CHECKS, 7);
});

// ── CLI ─────────────────────────────────────────────────────────────────────

test('CLI --json on the ratelimit fixtures reports exactly the fourteen HIGHs', () => {
  const r = runCli([FIXTURES, '--json']);
  assert.equal(r.status, 1); // high findings, default threshold high

  const payload = JSON.parse(r.stdout); // throws if the JSON is invalid
  assert.equal(payload.schemaVersion, 1);
  assert.equal(payload.summary.total, 27);
  assert.equal(payload.summary.high, 14);
  assert.equal(payload.summary.medium, 13);
  assert.equal(payload.summary.critical, 0);
  assert.equal(payload.scan.filesScanned, 34);

  // The HIGHs: no socket-level source in scope for the identity, so nothing
  // could have rescued it whatever the control flow.
  const high = payload.findings.filter((f) => f.severity === 'high').map((f) => f.file);
  assert.deepEqual(high.sort(), [
    'bare-check-ratelimit.js',
    'coalesce-assign.js',
    // Two HIGH entries for the seven-file crossfile/ tree: one exported helper
    // each, reported at its own header read, however many routes consume it.
    'crossfile/lib/rate-limit.js',
    'crossfile/selfuse/lib/limiter.js',
    'express-consume.js',
    // Trust IS configured in this one, and it hand-parses the header anyway.
    // Silent for eight rounds; the mute that hid it is gone.
    'express-trust-proxy.js',
    'helper-chain-two-hops.js',
    'helper-getclientip.ts',
    'middleware.ts',
    'nullish-fallback.js',
    'or-fallback.js',
    'scope-collision.js',
    'socket-fallback-absent.js',
    'trust-words-in-string.js',
  ]);
  for (const f of payload.findings) {
    assert.equal(f.rule, rule);
    assert.ok(f.severity === 'high' || f.severity === 'medium');
    assert.ok(Number.isInteger(f.line) && f.line >= 1);
  }

  // Every MEDIUM names the socket source it could not rule out. A MEDIUM that
  // did not would be an accusation with nothing behind it.
  for (const f of payload.findings.filter((x) => x.severity === 'medium')) {
    assert.match(f.impact, /A socket-level fallback is present at [^\s]+:\d+,/);
  }
});

test('--fail-on medium gates on the MEDIUMs the default lets through', () => {
  // The whole point of the tier: a correct helper never breaks a build on the
  // default threshold, and a team that wants to review every "I cannot tell"
  // asks for it explicitly.
  const safe = path.join(CROSSFILE, 'safe');
  assert.equal(runCli([safe, '--json']).status, 0);
  assert.equal(runCli([safe, '--fail-on', 'medium', '--json']).status, 1);
});

test('the emitted order is by file then line, phase 2 findings included', () => {
  // Phase 2 appends after the walk has moved on, so the CLI re-sorts. The
  // report's own severity-then-file sort is stable and inherits this
  // underneath, which is what keeps a file's findings in line order.
  const payload = JSON.parse(runCli([FIXTURES, '--json']).stdout);
  const keys = payload.findings.map((f) => `${f.file}:${String(f.line).padStart(6, '0')}`);
  assert.deepEqual(keys, [...keys].sort());
});

test('CLI -v prints the package version', () => {
  const pkg = JSON.parse(readFileSync(path.join(HERE, '..', 'package.json'), 'utf8'));
  const r = runCli(['-v']);
  assert.equal(r.status, 0);
  assert.equal(r.stdout, `${pkg.version}\n`);
});

// ── aggregation ─────────────────────────────────────────────────────────────

/**
 * The only test that scans the whole fixture tree, and it asserts PER-RULE
 * subsets: the exact file+line set each rule is responsible for, plus the fact
 * that the summary total is nothing more than their sum. A global filesScanned
 * or a global `high === 0` here is what made the tree unextendable before —
 * every new detector's fixtures broke assertions that had nothing to do with
 * it. Adding rule #3 now means adding one block to `expected`.
 */
test('CLI aggregates both rules in a single scan of the fixture tree', () => {
  const r = runCli([FIXTURES_ROOT, '--json']);
  assert.equal(r.status, 1);

  const payload = JSON.parse(r.stdout);
  const expected = {
    'webhook-swallows-2xx': [
      { file: 'webhook/app/api/stripe/webhook/route.ts', line: 12, severity: 'critical' },
      { file: 'webhook/github-webhook.mjs', line: 6, severity: 'critical' },
      // The five BAD cases of the acceptance fixture adopted from C1, at the
      // line of each `catch`. Its four GOOD cases contribute nothing, which is
      // the half of this list that matters: good5 is the conditional-idempotency
      // pattern taken from real production code, and it used to be reported.
      { file: 'webhook/webhook-examples.ts', line: 37, severity: 'critical' },
      { file: 'webhook/webhook-examples.ts', line: 48, severity: 'critical' },
      { file: 'webhook/webhook-examples.ts', line: 59, severity: 'critical' },
      { file: 'webhook/webhook-examples.ts', line: 70, severity: 'critical' },
      { file: 'webhook/webhook-examples.ts', line: 81, severity: 'critical' },
    ],
    'rate-limit-bypass': [
      { file: 'ratelimit/ancestor-scope-rescue.js', line: 27, severity: 'medium' },
      { file: 'ratelimit/bare-check-ratelimit.js', line: 23, severity: 'high' },
      { file: 'ratelimit/coalesce-assign.js', line: 12, severity: 'high' },
      // The cross-file findings: one entry per helper. The first is contributed
      // by `finalize` alone; the third is reached by both phases and deduped
      // to one by the CLI; the middle one is the validating twin at MEDIUM.
      { file: 'ratelimit/crossfile/lib/rate-limit.js', line: 34, severity: 'high' },
      { file: 'ratelimit/crossfile/safe/lib/client-ip.js', line: 25, severity: 'medium' },
      { file: 'ratelimit/crossfile/selfuse/lib/limiter.js', line: 25, severity: 'high' },
      { file: 'ratelimit/express-consume.js', line: 10, severity: 'high' },
      // `app.set('trust proxy', 1)` four lines above a hand-parse of the
      // header. The setting is real and the code ignores it.
      { file: 'ratelimit/express-trust-proxy.js', line: 12, severity: 'high' },
      { file: 'ratelimit/helper-chain-two-hops.js', line: 15, severity: 'high' },
      { file: 'ratelimit/helper-getclientip.ts', line: 19, severity: 'high' },
      { file: 'ratelimit/helper-guard-clause-return.js', line: 26, severity: 'medium' },
      { file: 'ratelimit/helper-socket-rescue.js', line: 21, severity: 'medium' },
      { file: 'ratelimit/helper-ternary-return.js', line: 21, severity: 'medium' },
      { file: 'ratelimit/middleware.ts', line: 10, severity: 'high' },
      { file: 'ratelimit/nested-closure-shadow.js', line: 18, severity: 'medium' },
      { file: 'ratelimit/nullish-fallback.js', line: 11, severity: 'high' },
      { file: 'ratelimit/optional-chain-override.js', line: 21, severity: 'medium' },
      { file: 'ratelimit/optional-chain-override.js', line: 27, severity: 'medium' },
      { file: 'ratelimit/or-fallback.js', line: 13, severity: 'high' },
      // A TRUSTED_PROXIES-gated helper that falls back to the peer address:
      // real socket-level code in scope, so MEDIUM carries it rather than the
      // name of the allowlist.
      { file: 'ratelimit/real-ip-trusted.js', line: 12, severity: 'medium' },
      { file: 'ratelimit/scope-collision.js', line: 20, severity: 'medium' },
      { file: 'ratelimit/scope-collision.js', line: 26, severity: 'high' },
      { file: 'ratelimit/socket-fallback-absent.js', line: 19, severity: 'high' },
      { file: 'ratelimit/socket-fallback.js', line: 20, severity: 'medium' },
      { file: 'ratelimit/socket-override.js', line: 11, severity: 'medium' },
      { file: 'ratelimit/ternary-validated.js', line: 20, severity: 'medium' },
      { file: 'ratelimit/trust-words-in-string.js', line: 23, severity: 'high' },
    ],
    // Rule #3's whole contribution to the tree, and the shape of the block a
    // rule #4 adds: seven fixtures, three findings. The other four fixtures are
    // the SILENT half — an empty fallback, `PORT`/`NODE_ENV`, the offending
    // line quoted in a comment, and a read with an explicit throw — and their
    // absence from this list is the assertion that matters most, because a
    // version of this rule that reported `process.env.PORT || 3000` would be
    // switched off before it found anything.
    'env-secret-fallback': [
      { file: 'envsecret/high-destructured-default.ts', line: 10, severity: 'high' },
      { file: 'envsecret/high-fetch-fallback.ts', line: 10, severity: 'high' },
      { file: 'envsecret/medium-no-outbound.js', line: 13, severity: 'medium' },
    ],
  };

  let counted = 0;
  for (const [ruleName, want] of Object.entries(expected)) {
    const got = payload.findings
      .filter((f) => f.rule === ruleName)
      .map((f) => ({ file: f.file, line: f.line, severity: f.severity }))
      .sort((a, b) => a.file.localeCompare(b.file));
    assert.deepEqual(got, want, `findings for ${ruleName}`);
    counted += want.length;
  }

  // Every finding belongs to one of the per-rule sets above — no strays.
  assert.equal(payload.summary.total, counted);
});
