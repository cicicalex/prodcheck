/**
 * Tests for the env-secret-fallback detector.
 * node:test + node:assert only — the zero-dependency rule covers dev-time too.
 *
 * Fixture layout: every detector owns one subdirectory of tests/fixtures/, and
 * the per-detector CLI test below scans only its own — tests/fixtures/envsecret/.
 * That is what keeps its exact counts true forever: fixtures added for the
 * remaining rules land in sibling directories and cannot move these numbers. The
 * single test that looks at the whole tree is the aggregation test at the bottom
 * of ratelimit.test.mjs, and it asserts per-rule subsets rather than global
 * totals.
 *
 * The rule has three outcomes and the fixtures are chosen to pin all three,
 * because the SILENT one is the half that decides whether anybody leaves the
 * rule switched on: `process.env.PORT || 3000` and `process.env.NODE_ENV ||
 * 'development'` are correct code, they are in every Node service ever written,
 * and a version of this rule that reports them is uninstalled the same day.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { check, rule } from '../src/checks/env-secret-fallback.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, 'fixtures', 'envsecret');
const CLI = path.join(HERE, '..', 'src', 'cli.mjs');

/** Run the detector on one fixture, addressed by its POSIX-relative path. */
function detect(relPosix) {
  const content = readFileSync(path.join(FIXTURES, ...relPosix.split('/')), 'utf8');
  return check({ path: relPosix, content });
}

function runCli(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

/** The detector over inline source, which is how the shape cases are written. */
const scan = (content, filePath = 'src/lib/client.ts') => check({ path: filePath, content });

/** A file whose only network call is a `fetch`, so severity is about the value. */
const withFetch = (...lines) => [...lines, "await fetch('https://api.example.com/v1/quote');"].join('\n');

// ── the three outcomes, on the fixtures ─────────────────────────────────────

test('HIGH: a real fallback in a file that calls out — the FMP shape', () => {
  const findings = detect('high-fetch-fallback.ts');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.rule, rule);
  assert.equal(f.severity, 'high');
  assert.equal(f.file, 'high-fetch-fallback.ts');
  assert.equal(f.line, 10);
  assert.deepEqual(f.fix.remove, ["const apiKey = process.env.FMP_API_KEY ?? 'demo';"]);
  // The patch is written with the finding's own variable name: a remediation
  // the reader has to adapt is one they paste wrong.
  assert.deepEqual(f.fix.add, [
    'const FMP_API_KEY = process.env.FMP_API_KEY  // read once, at module load',
    "if (!FMP_API_KEY) throw new Error('FMP_API_KEY is not set')  // fail fast; never default a credential",
  ]);
  // A HIGH names the outbound line, because that line is the evidence for the
  // claim that money leaves. An accusation with nothing behind it is noise.
  assert.match(f.impact, /calls out to the network at high-fetch-fallback\.ts:12,/);
  assert.ok(f.impact.includes('`FMP_API_KEY` falls back to `"demo"`'));
});

test('HIGH: the destructured default, which no accessor pattern can see', () => {
  const findings = detect('high-destructured-default.ts');
  assert.equal(findings.length, 1); // the second default on that line is empty
  const f = findings[0];
  assert.equal(f.severity, 'high');
  assert.equal(f.line, 10);
  assert.deepEqual(f.fix.remove, [
    "const { STRIPE_SECRET_KEY = 'sk_test_x', SIGNING_SECRET = '' } = process.env;",
  ]);
  assert.ok(f.impact.includes('`STRIPE_SECRET_KEY` falls back to `"sk_test_x"`'));
});

test('MEDIUM: a real fallback with no outbound call visible in the file', () => {
  const findings = detect('medium-no-outbound.js');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.severity, 'medium');
  assert.equal(f.line, 13);
  // The fallback is held in a constant one line up — resolved, because it is
  // resolvable in THIS file.
  assert.ok(f.impact.includes('`SESSION_SIGNING_KEY` falls back to `"dev-signing-key-do-not-use"`'));
  // A MEDIUM says what prodcheck does not know, rather than implying it does.
  assert.match(f.impact, /No outbound call is visible in this file/);
  assert.ok(!f.impact.includes('calls out to the network at'));
});

test('SILENT: an empty or placeholder fallback is the fix, not the bug', () => {
  assert.deepEqual(detect('silent-empty-fallback.js'), []);
});

test('SILENT: PORT and NODE_ENV are configuration, and stay configuration', () => {
  // The load-bearing negative. `API_BASE_URL` is in there too: a URL is not a
  // credential however much it looks like infrastructure.
  assert.deepEqual(detect('silent-config-default.js'), []);
});

test('SILENT: the offending line in a comment, or in a string, is not code', () => {
  assert.deepEqual(detect('silent-in-comment.js'), []);
});

test('SILENT: a build tool that declares the value public settles the question', () => {
  // This is the measured false positive, not an invented case. The shipped rule
  // reported three MEDIUMs on a-real-app's `sentry.*.config.ts`, each of the
  // shape `process.env.NEXT_PUBLIC_SENTRY_DSN ?? "https://…ingest.sentry.io/…"`.
  // `DSN` passes SECRET_NAME and is not a location suffix, so the gates fired
  // correctly and the answer was still wrong: Next.js inlines every
  // `NEXT_PUBLIC_*` value into the browser bundle, so the literal is public by
  // construction and neither consequence the finding claims can follow.
  assert.deepEqual(detect('silent-public-prefix.ts'), []);
});

test('the exemption is on the prefix, not on the rest of the name', () => {
  // `SENTRY_DSN` without the prefix still reports — the guarantee comes from the
  // build tool, not from the word `DSN`. Exempting `DSN` outright would silence
  // a server-side default too, where the same literal is a real (if low-value)
  // fallback. Inline sources so the pair differs by the prefix alone.
  const withPrefix = check({
    path: 'a.ts',
    content: 'export const d = process.env.NEXT_PUBLIC_SENTRY_DSN ?? "https://k@o1.ingest.sentry.io/2";\n',
  });
  const without = check({
    path: 'b.ts',
    content: 'export const d = process.env.SENTRY_DSN ?? "https://k@o1.ingest.sentry.io/2";\n',
  });
  assert.deepEqual(withPrefix, []);
  assert.equal(without.length, 1);
});

test('CLEAN: read once, throw when missing — no fallback to judge', () => {
  assert.deepEqual(detect('clean-explicit-throw.js'), []);
});

// ── the spellings the read actually has ─────────────────────────────────────

test('both operators, both quote styles, and the bracket accessor', () => {
  for (const read of [
    "process.env.API_KEY ?? 'demo'",
    'process.env.API_KEY || "demo"',
    "process.env['STRIPE_SECRET_KEY'] || 'sk_test_x'",
    'process.env["STRIPE_SECRET_KEY"] ?? `sk_test_x`',
    "process.env . API_KEY  ||  'demo'",
  ]) {
    const findings = scan(withFetch(`const k = ${read};`));
    assert.equal(findings.length, 1, `${read} was not detected`);
    assert.equal(findings[0].severity, 'high');
  }
});

test('a TypeScript non-null assertion between the read and the operator', () => {
  // `process.env.API_KEY!` changes the type and nothing else, and it is how
  // every strict-mode TS codebase spells this read.
  assert.equal(scan(withFetch("const k = process.env.API_KEY! ?? 'demo';")).length, 1);
});

test('the operand may sit on the next line, or behind a comment', () => {
  assert.equal(scan(withFetch("const k = process.env.API_KEY ||", "  'demo';")).length, 1);
  assert.equal(scan(withFetch("const k = process.env.API_KEY /* legacy */ || 'demo';")).length, 1);
});

test('a chain resolves at the read the literal actually belongs to', () => {
  // `A_KEY` falls back to another READ, not to a literal, so the finding is
  // `B_KEY`'s — which is the line whose default has to go.
  const findings = scan(withFetch("const k = process.env.A_KEY || process.env.B_KEY || 'demo';"));
  assert.equal(findings.length, 1);
  assert.ok(findings[0].impact.includes('`B_KEY` falls back'));
});

test('a constant fallback is resolved only when this file holds its value', () => {
  const resolved = ["const DEFAULT_KEY = 'demo';", 'const k = process.env.API_KEY || DEFAULT_KEY;'];
  assert.equal(scan(withFetch(...resolved)).length, 1);

  // Imported, or computed: this file cannot say what the value is, so it does
  // not guess. Hiding a literal one module over is not a spelling this rule
  // pretends to see through, and pretending would be the wrong direction —
  // an accusation about a value nobody in the report can check.
  const imported = ["import { DEFAULT_KEY } from './defaults';", 'const k = process.env.API_KEY || DEFAULT_KEY;'];
  assert.deepEqual(scan(withFetch(...imported)), []);
});

test('a call or a member expression is a lookup, not a default', () => {
  for (const operand of ['getSecret()', 'config.key', 'secrets[name]', 'vault?.key']) {
    assert.deepEqual(
      scan(withFetch(`const k = process.env.API_KEY || ${operand};`)),
      [],
      `${operand} was read as a literal fallback`
    );
  }
});

test('destructuring: plain, renamed, and with no default at all', () => {
  assert.equal(scan(withFetch("const { STRIPE_SECRET_KEY = 'sk_x' } = process.env;")).length, 1);
  // Renamed — the ENV name is what the secret-name gate is asked about, and the
  // fix is printed for the env name, not the local one.
  const renamed = scan(withFetch("const { STRIPE_SECRET_KEY: sk = 'sk_x' } = process.env;"));
  assert.equal(renamed.length, 1);
  assert.ok(renamed[0].fix.add[0].includes('process.env.STRIPE_SECRET_KEY'));
  // No default is no bug: `undefined` is what fails loudly downstream.
  assert.deepEqual(scan(withFetch('const { STRIPE_SECRET_KEY } = process.env;')), []);
});

// ── the name gate ───────────────────────────────────────────────────────────

test('every credential word in the list admits a finding', () => {
  const names = [
    'API_KEY',
    'STRIPE_SECRET_KEY',
    'GITHUB_TOKEN',
    'DB_PASSWORD',
    'MYSQL_PASSWD',
    'SERVICE_CREDENTIALS',
    'apiKey',
    'AUTH_HEADER',
    'SENTRY_DSN',
    'DATABASE_CONNECTION_STRING',
    'PRIVATE_SIGNING_MATERIAL',
  ];
  for (const name of names) {
    assert.equal(
      scan(withFetch(`const v = process.env.${name} || 'literal-value';`)).length,
      1,
      `${name} was not read as a credential`
    );
  }
});

test('configuration keeps its defaults, which is what makes the rule usable', () => {
  const names = ['PORT', 'NODE_ENV', 'LOG_LEVEL', 'AWS_REGION', 'API_BASE_URL', 'HTTP_TIMEOUT_MS'];
  for (const name of names) {
    assert.deepEqual(
      scan(withFetch(`const v = process.env.${name} || 'a-default';`)),
      [],
      `${name} was reported as a credential`
    );
  }
});

test('a name ending in a place is configuration, whatever it starts with', () => {
  // Measured, not theorised. The first run of this rule against a-real-app
  // produced nine findings and six of them were `process.env.AUTH_URL ??
  // "https://finance.zeropointlogic.io"` across five files — NextAuth's own
  // variable name, holding an origin, correctly defaulted, matched only because
  // `AUTH` is a substring of `AUTH_URL`. Two thirds of a report being one
  // benign spelling is the failure the name gate exists to prevent.
  for (const name of [
    'AUTH_URL',
    'authUrl',
    'auth-url',
    'NEXTAUTH_URL',
    'OAUTH_TOKEN_ENDPOINT',
    'SIGNING_KEY_PATH',
    'API_KEY_HOST',
    'PRIVATE_REGION',
  ]) {
    assert.deepEqual(
      scan(withFetch(`const v = process.env.${name} || 'https://example.com';`)),
      [],
      `${name} was reported as a credential`
    );
  }
});

test('the veto is LAST segment only — a secret that mentions a place is still a secret', () => {
  for (const name of ['URL_SECRET', 'ENDPOINT_API_KEY', 'HOST_PASSWORD', 'PATH_SIGNING_TOKEN']) {
    assert.equal(
      scan(withFetch(`const v = process.env.${name} || 'literal-value';`)).length,
      1,
      `${name} was vetoed by a segment that is not the last one`
    );
  }
});

test('the name gate is a substring test, and over-reports where it does', () => {
  // Documented in the module header and pinned here so it cannot drift into a
  // surprise: `AUTH` matches `AUTHOR_NAME`. This is the over-reporting
  // direction — one finding a reader dismisses in a second — and the version
  // that avoids it is a list of exact names that dies against the next
  // codebase.
  assert.equal(scan(withFetch("const a = process.env.AUTHOR_NAME || 'anon';")).length, 1);
});

// ── the value gate ──────────────────────────────────────────────────────────

test('fallbacks that fail loudly are the correct behaviour and stay silent', () => {
  for (const literal of [
    "''",
    '""',
    "'   '",
    "'undefined'",
    "'null'",
    "'CHANGEME'",
    "'change_me'",
    "'REPLACE_ME'",
    "'replace-me'",
    "'placeholder'",
    "'TODO'",
  ]) {
    assert.deepEqual(
      scan(withFetch(`const k = process.env.API_KEY || ${literal};`)),
      [],
      `${literal} was reported, but it fails fast`
    );
  }
});

test('a non-string default is not this rule’s bug', () => {
  for (const operand of ['3000', 'null', 'undefined', '{}', 'false']) {
    assert.deepEqual(scan(withFetch(`const k = process.env.API_KEY || ${operand};`)), []);
  }
});

test('an interpolated default is a computed credential, and is reported', () => {
  // Not a placeholder: it produces a real, usable value at runtime, so it hides
  // the missing variable exactly as a plain literal does.
  const findings = scan(withFetch('const k = process.env.API_KEY || `demo-${tenant}`;'));
  assert.equal(findings.length, 1);
});

// ── the outbound gate: severity only, never silence ─────────────────────────

test('each outbound spelling promotes the same finding to HIGH', () => {
  const READ = "const k = process.env.API_KEY || 'demo';";
  for (const call of [
    "await fetch('https://api.example.com');",
    "import axios from 'axios';",
    "got('https://api.example.com');",
    'https.request(options);',
    'http.request(options);',
    "client.post('https://api.example.com/v1/charge', body);",
    'httpClient.get(endpointUrl);',
  ]) {
    const findings = scan([READ, call].join('\n'));
    assert.equal(findings.length, 1, `${call}: the finding disappeared`);
    assert.equal(findings[0].severity, 'high', `${call} was not read as an outbound call`);
  }
});

test('an inbound route table does not promote a file to HIGH', () => {
  // `app.post('/api/charge', handler)` REGISTERS a route. Reading a leading `/`
  // as a destination would promote every Express app on the strength of its own
  // routing table, and the HIGH tier would stop meaning anything.
  const inbound = ["const k = process.env.API_KEY || 'demo';", "app.post('/api/charge', handler);"];
  const findings = scan(inbound.join('\n'));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'medium');

  // Same for the two method names that are ordinary map/header accessors.
  for (const call of ["const v = headers.get('accept');", "cache.get('user:1');"]) {
    const f = scan(["const k = process.env.API_KEY || 'demo';", call].join('\n'));
    assert.equal(f[0].severity, 'medium', `${call} was read as an outbound call`);
  }
});

// ── the code channel ────────────────────────────────────────────────────────

test('a fallback quoted in a comment or a string is not a fallback', () => {
  const inLine = ["// const k = process.env.API_KEY || 'demo';", "await fetch('https://x/y');"];
  assert.deepEqual(scan(inLine.join('\n')), []);

  const inBlock = ["/* const k = process.env.API_KEY || 'demo'; */", "await fetch('https://x/y');"];
  assert.deepEqual(scan(inBlock.join('\n')), []);

  // Strings are KEPT by stripComments — module names and header names live in
  // them — so it is the MASK, not the text, that rejects this one.
  const inString = ['const note = "process.env.API_KEY || \'demo\'";', "await fetch('https://x/y');"];
  assert.deepEqual(scan(inString.join('\n')), []);
});

test('the lexer invariant holds for this rule too', () => {
  // A refused regex literal whose body holds a backtick used to open a template
  // frame that ran to EOF, and every search in every rule skips not-code. The
  // invariant in _lexer.mjs forbids it; this is that guarantee asserted through
  // the finding, which is the only form of it anybody can check from the output.
  const TICK = String.fromCharCode(96);
  for (const poison of [
    `if (1) /${TICK}/.test("x");`,
    'if (1) /[/*]/.test("x");',
    `const RE = /${TICK}/;`,
    "if (1) /'/.test('x');",
  ]) {
    const src = [
      poison,
      "const k = process.env.API_KEY || 'demo';",
      "await fetch('https://api.example.com');",
      `const zt = ${TICK}done ${TICK};`,
      '/* trailing */',
    ].join('\n');
    const findings = scan(src);
    assert.equal(findings.length, 1, `"${poison}" silenced the fallback`);
    assert.equal(findings[0].line, 2);
  }
});

// ── granularity ─────────────────────────────────────────────────────────────

test('one finding per line, one line per variable', () => {
  // Two defaults on one line are one line to change.
  const oneLine = scan(
    withFetch("const a = process.env.A_KEY || 'x', b = process.env.B_KEY || 'y';")
  );
  assert.equal(oneLine.length, 1);

  // A config module defaulting three secrets earns three findings: each is a
  // separate variable with a separate fix, and collapsing them would hide two.
  const many = scan(
    withFetch(
      "const a = process.env.A_KEY || 'x';",
      "const b = process.env.B_TOKEN || 'y';",
      "const c = process.env.C_PASSWORD || 'z';"
    )
  );
  assert.deepEqual(
    many.map((f) => f.line),
    [1, 2, 3]
  );
});

test('a file that never reads the environment is never analysed', () => {
  assert.equal(check({ path: 'a.ts', content: "export const x = 'demo';" }).length, 0);
});

// ── CLI ─────────────────────────────────────────────────────────────────────

test('CLI --json on the envsecret fixtures reports exactly the two HIGHs', () => {
  const r = runCli([FIXTURES, '--json']);
  assert.equal(r.status, 1); // high findings, default threshold high

  const payload = JSON.parse(r.stdout); // throws if the JSON is invalid
  assert.equal(payload.schemaVersion, 1);
  assert.equal(payload.summary.total, 3);
  assert.equal(payload.summary.high, 2);
  assert.equal(payload.summary.medium, 1);
  assert.equal(payload.summary.critical, 0);
  // Eight fixtures, five of which are the silent half of the rule. That the
  // count of files is more than double the count of findings is the assertion
  // that matters most here — and the fifth silent case is the one measured on
  // real code: a `NEXT_PUBLIC_*` value the build tool already published.
  assert.equal(payload.scan.filesScanned, 8);

  assert.deepEqual(
    payload.findings.map((f) => `${f.file}:${f.line}:${f.severity}`),
    [
      'high-destructured-default.ts:10:high',
      'high-fetch-fallback.ts:10:high',
      'medium-no-outbound.js:13:medium',
    ]
  );
  for (const f of payload.findings) {
    assert.equal(f.rule, rule);
    assert.ok(Number.isInteger(f.line) && f.line >= 1);
    assert.ok(f.fix.add.length === 2 && f.fix.remove.length === 1);
  }
});

test('--fail-on medium gates on the MEDIUM the default lets through', () => {
  const medium = path.join(FIXTURES, 'medium-no-outbound.js');
  assert.equal(runCli([medium, '--json']).status, 0);
  assert.equal(runCli([medium, '--fail-on', 'medium', '--json']).status, 1);
});
