/**
 * env-secret-fallback
 *
 * Finds a CREDENTIAL read from the environment with a SILENT FALLBACK to a
 * literal — `process.env.FMP_API_KEY ?? 'demo'` — in a file that then calls out
 * to the internet.
 *
 * This rule exists because of one line in the author's own code — a health-check
 * route in a private repository:
 *
 *     const key = process.env.FMP_API_KEY || 'demo';
 *
 * The FMP key was deleted when the account was cancelled. Nothing broke.
 * `'demo'` is Financial Modeling Prep's public sandbox key, so every request
 * kept being built, kept being sent and kept being answered — against a shared
 * credential instead of a paid one. No exception, no 401, no log line, no alert.
 * The bug announced itself as a BILL.
 *
 * That is the shape of the whole class, and it is why the fallback is more
 * dangerous than the missing variable it hides:
 *
 *   - `process.env.X` alone is `undefined`. The SDK throws, the deploy fails,
 *     someone fixes it in four minutes. That is the correct behaviour.
 *   - `process.env.X ?? 'demo'` is a valid string. Everything downstream
 *     succeeds against the wrong identity, and success is invisible.
 *
 * A default credential is not a resilience feature. It is an error handler that
 * swallows the one error worth having.
 *
 * ── what is a secret, and why the name is the gate ──────────────────────────
 *
 * `process.env.PORT || 3000` and `process.env.NODE_ENV || 'development'` are the
 * two most common lines in this ecosystem, and both are correct: a port and an
 * environment ARE meant to have defaults, because neither authenticates
 * anything. A rule that flagged them would be turned off in a day, and a rule
 * nobody runs finds nothing.
 *
 * So the variable NAME is the gate, matched as a case-insensitive substring
 * (SECRET_NAME below). It is a heuristic and it is wrong in both directions, in
 * ways worth stating rather than hiding:
 *
 *   - `AUTH` matches `AUTHOR_NAME`, `KEY` matches `MONKEY_PATCH`. Both would be
 *     reported if they carried a literal fallback. That is the over-reporting
 *     direction and it costs one finding a reader dismisses in a second.
 *   - A secret named `process.env.FOO` is invisible here. Nothing lexical can
 *     know it is a secret, and widening the gate to "every environment variable
 *     with a string default" is the version that gets uninstalled.
 *
 * One over-report was too common to leave standing, and LOCATION_SUFFIX below
 * is the whole of the correction: `AUTH_URL` is NextAuth's own variable name,
 * it holds an origin rather than a credential, and it accounted for two thirds
 * of this rule's findings the first time it was run against a real repository.
 * A name whose LAST segment is a place — `URL`, `ENDPOINT`, `HOST`, `PATH` —
 * is configuration however the earlier segments read.
 *
 * ── three outcomes, and the fallback's own value decides ────────────────────
 *
 * The confidence contract is the one rate-limit-bypass already uses — a
 * severity, not a verdict — because the same question is unanswerable here for
 * the same reason: whether a particular credential reaches a particular request
 * is dataflow over a control-flow graph, and this tool has no parser (zero
 * runtime dependencies is a hard rule).
 *
 *   HIGH    the fallback is a real value AND this file makes an outbound call.
 *           Money leaves, or someone else's quota does. The outbound line is
 *           named in the finding so the reader can see the path themselves.
 *
 *   MEDIUM  the fallback is a real value and no outbound call is visible in
 *           this file. It is still a default credential compiled into the
 *           source — whoever imports it inherits it — but prodcheck cannot show
 *           where it is spent, so it does not claim to.
 *
 *   SILENT  the fallback is empty or a placeholder that fails loudly: `''`,
 *           `'undefined'`, `'CHANGEME'`, `'REPLACE_ME'`. Those are not this bug,
 *           they are the OPPOSITE of it. `''` is falsy, every SDK rejects it,
 *           and a request signed with `CHANGEME` comes back 401 on the first
 *           call in staging. Failing fast is the fix this rule prints; reporting
 *           somebody for having already applied it would be absurd.
 *
 * The outbound test is FILE-SCOPED and deliberately coarse: "does this file
 * reach the network at all". A tighter question — does THIS credential reach
 * THAT call — is the dataflow question again, and rate-limit-bypass spent seven
 * rounds establishing that a lexical approximation of it is wrong in both
 * directions by one line. Here the coarse answer only ever chooses between HIGH
 * and MEDIUM, and both are reported. Nothing is silenced by it.
 *
 * ── what this rule cannot see ───────────────────────────────────────────────
 *
 * It matches `??`, `||` and destructuring defaults on `process.env`, and
 * nothing else. A default expressed through a SCHEMA LIBRARY is invisible:
 *
 *     SECRET_KEY: z.string().min(32)                 correct, and invisible
 *     SECRET_KEY: z.string().default('dev-secret')   the same bug, and a MISS
 *
 * `a-real-backend/src/config.ts` is the first shape, and this rule correctly
 * reports nothing there — but it would report nothing about the second either,
 * and the second is this bug wearing zod. Covering it means knowing which
 * library a `.default(…)` belongs to and that its subject is an env var, which
 * is a per-library pattern rather than a general one. Worth doing; not done.
 *
 * ── no cross-file phase, and why ────────────────────────────────────────────
 *
 * This check exports `check` only — no `collect`/`finalize` (see the two-phase
 * contract in src/checks/index.mjs). The seam that phase exists for is a bug
 * SPLIT across two files, where each half is innocent. This bug is not split:
 * the offending line is complete on its own, and the fix goes exactly where the
 * fallback is written. A config module that defaults a key and a route that
 * spends it are already covered — the config module is reported at MEDIUM, on
 * its own line, which is the line that has to change either way.
 *
 * ── the channel every search reads ──────────────────────────────────────────
 *
 * Every match here must BEGIN on the code channel of ./_lexer.mjs. That is what
 * keeps a `process.env.API_KEY || 'demo'` quoted inside a log message, a README
 * string or a commented-out line from being read as code — and the lexer's
 * invariant is what keeps the opposite failure, a file gone dark and reported
 * clean, from happening at all. Read that module's header before touching
 * anything about masks here.
 */

import { codeMask, stripComments } from './_lexer.mjs';

export const rule = 'env-secret-fallback';

/**
 * File extensions worth reading at all. Identical to the other two checks: the
 * CLI takes the union across every registered check, so a gap here is a file
 * type the whole tool stops opening.
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

/**
 * A file is a candidate when it reads the environment at all, on the code
 * channel. Matched against comment-stripped source so a `// TODO: move this to
 * process.env` cannot drag a file into the analysis; strings are kept, because
 * everything this rule matches STARTS at a `process` token and the mask decides
 * the rest.
 */
const CONTENT_HINT = /process\s*\.\s*env\b/;

/**
 * Names that make an environment variable a CREDENTIAL rather than
 * configuration. Case-insensitive substring, which is the whole design: the
 * ecosystem spells the same secret `API_KEY`, `apiKey`, `NEXT_PUBLIC_API_KEY`
 * and `STRIPE_SECRET_KEY`, and no list of exact names survives contact with a
 * second codebase.
 *
 * `APIKEY`/`API_KEY` and `PASSWD` are redundant against `KEY` and `PASSWORD`
 * respectively; they are spelled out because this list is read as documentation
 * of what the rule considers a secret, and a reader should not have to derive
 * the coverage from substring arithmetic.
 *
 * What is deliberately ABSENT is as load-bearing as what is present: `PORT`,
 * `NODE_ENV`, `HOST`, `URL`, `REGION`, `LOG_LEVEL`, `TIMEOUT`. Those are
 * configuration, they are SUPPOSED to have defaults, and flagging them is what
 * would make this rule unusable.
 */
const SECRET_NAME =
  /KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|APIKEY|API_KEY|AUTH|DSN|CONNECTION_STRING|PRIVATE/i;

/**
 * Words that make a name a LOCATION rather than a credential, tested against
 * the name's LAST segment only.
 *
 * This exists because of one measurement. On a 421-file Next.js codebase — the
 * repository this rule was built from — the first version of the rule produced
 * 9 findings, and 6 of them were
 * `process.env.AUTH_URL ?? "<the site's own origin>"`, in five different files.
 * `AUTH_URL` is NextAuth's
 * standard variable name; it holds the site's own origin, it is not a secret,
 * and defaulting it to the production URL is deliberate and correct. It matched
 * only because `AUTH` is a substring of `AUTH_URL`.
 *
 * Two thirds of a report being one benign spelling is the failure mode the
 * whole name gate exists to prevent — the same failure as flagging
 * `process.env.PORT`, arriving one step later. So the last segment gets a veto:
 *
 *     AUTH_URL        AUTH matched, last segment URL   → not a credential
 *     API_KEY_PATH    KEY matched, last segment PATH   → a filename, not a key
 *     STRIPE_SECRET_KEY                last segment KEY → reported
 *     SENTRY_DSN                       last segment DSN → reported
 *     DATABASE_CONNECTION_STRING    last segment STRING → reported
 *
 * The veto is LAST-SEGMENT-ONLY on purpose. `URL_SECRET` is a secret that
 * happens to mention a URL and stays reported; only a name that ENDS in a
 * location word is one whose subject is a place.
 *
 * The cost is stated rather than hidden: a URL that carries its own credentials
 * — `REDIS_AUTH_URL` defaulting to a `redis://user:pass@…` literal — is now a
 * miss. That shape is real, and it is the price of the six. Deleting this set
 * restores the old behaviour in one line.
 */
const LOCATION_SUFFIX = new Set([
  'URL',
  'URI',
  'URLS',
  'ENDPOINT',
  'ENDPOINTS',
  'HOST',
  'HOSTNAME',
  'DOMAIN',
  'ORIGIN',
  'PATH',
  'DIR',
  'PORT',
  'REGION',
]);

/**
 * Prefixes by which a build tool DECLARES a variable public.
 *
 * These are not a heuristic like SECRET_NAME — they are a contract. Next.js
 * inlines every `NEXT_PUBLIC_*` value into the browser bundle at build time;
 * Vite does the same for `VITE_*`, Create React App for `REACT_APP_*`,
 * SvelteKit and Astro for `PUBLIC_*`. A value shipped to every visitor cannot
 * be a credential, whatever the rest of its name says.
 *
 * This closes a false positive measured on real code:
 *
 *     dsn: process.env.NEXT_PUBLIC_SENTRY_DSN ?? "https://…@…ingest.sentry.io/…"
 *
 * `DSN` passes SECRET_NAME and is not a LOCATION_SUFFIX, so the rule reported
 * it — correctly by its own gates, and wrongly in fact. A Sentry DSN is a
 * write-only ingest endpoint, the literal is the project's own, and the prefix
 * says it is already public. Neither consequence the finding claims — someone
 * authenticating as you, a bill on your account — can follow from it.
 *
 * The gate is on the PREFIX, not on `DSN`, deliberately. Exempting `DSN` would
 * also silence `SENTRY_DSN` in a server file, where the same literal is a real
 * (if low-value) default. The prefix is the part that carries the guarantee.
 *
 * Cost, stated rather than hidden: a genuine secret misnamed with a public
 * prefix — `NEXT_PUBLIC_STRIPE_SECRET_KEY` — is now a miss. That variable is
 * already compromised by its own name, since the build tool has published it;
 * a scanner reporting the fallback would be pointing at the smaller of two
 * problems.
 */
const PUBLIC_PREFIX = /^(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|EXPO_PUBLIC|GATSBY|NUXT_PUBLIC)_/i;

/**
 * The last segment of an environment variable name, upper-cased.
 *
 * Splits on `_`, `-` and `.`, and on camel humps first, so `AUTH_URL`,
 * `authUrl` and `auth-url` are one name in three costumes — which is how the
 * same variable is actually spelled across a `.env` file, a config module and a
 * TypeScript type.
 */
function lastSegment(name) {
  const parts = name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').split(/[_\-.]+/);
  return (parts[parts.length - 1] ?? '').toUpperCase();
}

/** Does this variable name read as a credential rather than as configuration? */
function isSecretName(name) {
  if (PUBLIC_PREFIX.test(name)) return false;
  return SECRET_NAME.test(name) && !LOCATION_SUFFIX.has(lastSegment(name));
}

/**
 * Fallback literals that FAIL LOUDLY, and are therefore not this bug.
 *
 * Compared after lowercasing and removing separators, so `REPLACE_ME`,
 * `replace-me` and `ReplaceMe` are one entry. An empty or whitespace-only
 * string is handled before the lookup: `''` is falsy, so every downstream SDK
 * rejects it and the deploy breaks — which is exactly the behaviour this rule
 * asks for.
 */
const FAIL_FAST_LITERAL = new Set([
  'undefined',
  'null',
  'changeme',
  'replaceme',
  'yourkeyhere',
  'yourapikeyhere',
  'placeholder',
  'todo',
  'tbd',
]);

/**
 * Evidence that this file talks to the network. Four spellings match on their
 * own — `fetch(`, anything mentioning `axios`, `got(`, and `http.request(` /
 * `https.request(` — and they are enough on their own because none of them has
 * a plausible non-network meaning in a file that also reads a credential.
 */
const OUTBOUND_DIRECT = /\bfetch\s*\(|\baxios\b|\bgot\s*\(|\bhttps?\s*\.\s*request\s*\(/gi;

/**
 * `.post(` and `.get(` are the fifth and sixth spellings and they need a second
 * gate, because both are ordinary method names — `headers.get(name)`,
 * `map.get(key)`, `app.post('/webhook', handler)`. So the ARGUMENT has to look
 * like a destination.
 *
 * "Looks like a destination" is an absolute URL in the argument text, or an
 * identifier carrying `url`/`uri`/`endpoint`/`host`. A leading `/` is
 * deliberately NOT enough: `app.post('/api/charge', handler)` registers an
 * INBOUND route, and reading it as an outbound call would promote every Express
 * app to HIGH on the strength of its own routing table.
 */
const OUTBOUND_VERB = /\.\s*(?:post|get)\s*\(/g;
const URLISH = /https?:\/\/|(?<![\w$])[\w$]*(?:url|uri|endpoint|host)[\w$]*(?![\w$])/i;

const IMPACT_HEAD =
  'A credential is read from the environment with a silent fallback to a ' +
  'literal. Delete the variable, rotate it, or mistype it in one deployment ' +
  'and nothing breaks: the fallback is a valid string, so whatever consumes ' +
  'this value carries on — authenticating as somebody else instead of failing. ' +
  'There is no error to notice, because there is no error.';

/**
 * The sentence that names the consequence, and the reason this rule was picked
 * out of six candidates: this is the one that costs money. It is spelled out
 * rather than left as "security risk" because the failure mode is a BILLING
 * event, not a stack trace, and a reader who does not know that will file the
 * finding as cosmetic.
 */
const IMPACT_TAIL =
  ' The failure surfaces weeks later and somewhere else: an invoice against an ' +
  'account you believed was cancelled, a rate limit you never configured, or ' +
  'another tenant\'s data arriving because the shared key resolved to their ' +
  'workspace.';

const REMEDIATION =
  ' Fail fast instead: read the variable ONCE at startup, throw when it is ' +
  'missing, and never default a credential. A deploy that stops is a four-' +
  'minute fix; a deploy that silently uses somebody else\'s key is found by ' +
  'accounting.';

/** How much of the fallback literal the impact text quotes back. */
const LITERAL_PREVIEW = 32;

/* ── small lexical helpers ─────────────────────────────────────────────────
 *
 * Deliberately local copies rather than shared machinery. Each is a handful of
 * lines, and the alternative — a `_util.mjs` every check imports — would make
 * one rule's convenience another rule's coupling. `_lexer.mjs` is shared
 * because it holds an INVARIANT that must be fixed in one place; brace matching
 * is not that.
 */

/** The line `index` sits on, 1-based. */
function lineNumberAt(src, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (src[i] === '\n') line += 1;
  return line;
}

/** The whole source line containing `index`, unindented by the caller. */
function sourceLineAt(src, index) {
  const start = src.lastIndexOf('\n', index - 1) + 1;
  let end = src.indexOf('\n', index);
  if (end === -1) end = src.length;
  return src.slice(start, end);
}

/** Advance past whitespace (comments are already blanked to spaces). */
function skipSpace(src, i) {
  let j = i;
  while (j < src.length && /\s/.test(src[j])) j += 1;
  return j;
}

/**
 * The string literal starting at `i`, as {text, end}, or null.
 *
 * Escapes are honoured so `'it\'s'` reads whole. A `'`/`"` literal may not span
 * a line — the same confinement _lexer.mjs applies, for the same reason — while
 * a template may, and a template carrying `${…}` still counts: an interpolated
 * default is not a placeholder, it is a computed credential, and it is reported.
 */
function stringLiteralAt(src, i) {
  const quote = src[i];
  if (quote !== "'" && quote !== '"' && quote !== '`') return null;
  let text = '';
  let j = i + 1;
  while (j < src.length) {
    const ch = src[j];
    if (ch === '\\') {
      text += src[j + 1] ?? '';
      j += 2;
      continue;
    }
    if (ch === quote) return { text, end: j + 1 };
    if (ch === '\n' && quote !== '`') return null; // unterminated on its line
    text += ch;
    j += 1;
  }
  return null;
}

/** The argument text of the call whose `(` sits at `open`, or null. */
function callArguments(src, mask, open) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (!mask[i]) continue;
    if (src[i] === '(') depth += 1;
    else if (src[i] === ')') {
      depth -= 1;
      if (depth === 0) return src.slice(open + 1, i);
    }
  }
  return null;
}

/* ── the analysis ──────────────────────────────────────────────────────────*/

/**
 * Where does this file call out to the network? The index of the first such
 * call, or -1.
 *
 * File-scoped on purpose — see the module header. The answer only ever chooses
 * between HIGH and MEDIUM, so being coarse costs precision in the severity
 * column and cannot cost a finding.
 */
function outboundCallAt(src, mask) {
  const direct = new RegExp(OUTBOUND_DIRECT.source, 'gi');
  let m;
  while ((m = direct.exec(src))) {
    if (mask[m.index]) return m.index;
  }

  const verb = new RegExp(OUTBOUND_VERB.source, 'g');
  while ((m = verb.exec(src))) {
    if (!mask[m.index]) continue;
    const args = callArguments(src, mask, m.index + m[0].length - 1);
    if (args !== null && URLISH.test(args)) return m.index;
  }
  return -1;
}

/**
 * The names this file binds to a plain string literal, as name -> text.
 *
 * This is what resolves `process.env.API_KEY || DEFAULT_KEY`: the fallback is
 * only a fallback we can judge when the constant's value is visible IN THIS
 * FILE. An imported default, or one computed at runtime, answers nothing and
 * the read is left alone — hiding a literal one module over is not a spelling
 * this rule pretends to see through.
 *
 * The LAST binding of a name wins, which is what a reader of the file would
 * conclude too.
 */
function stringConstants(src, mask) {
  const out = new Map();
  const re = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=\s*/g;
  let m;
  while ((m = re.exec(src))) {
    if (!mask[m.index]) continue;
    const lit = stringLiteralAt(src, m.index + m[0].length);
    if (lit) out.set(m[1], lit.text);
  }
  return out;
}

/**
 * The operand at `i`: a string literal, or a bare identifier that is not being
 * called or dereferenced. Anything else — a number, an object, `getSecret()`,
 * `config.key` — is not a literal fallback and answers null.
 *
 * `getSecret()` is excluded because a function call is a lookup, not a default:
 * whatever it returns is chosen at runtime and may well be the correct
 * fail-fast path. Rejecting it is the precision half of the same decision the
 * name gate makes.
 */
function operandAt(src, i) {
  const lit = stringLiteralAt(src, i);
  if (lit) return { kind: 'literal', text: lit.text };

  const id = /^[A-Za-z_$][\w$]*/.exec(src.slice(i, i + 128));
  if (!id) return null;
  const after = skipSpace(src, i + id[0].length);
  const ch = src[after];
  if (ch === '(' || ch === '.' || ch === '[' || (ch === '?' && src[after + 1] === '.')) return null;
  return { kind: 'ident', name: id[0] };
}

/**
 * Yield every `process.env.NAME ?? <operand>` / `|| <operand>` on the code
 * channel, as {index, name, operand}.
 *
 * Both accessor spellings are read — `process.env.NAME` and
 * `process.env['NAME']` — because they are the same read and a codebase mixes
 * them freely. The match ANCHORS at `process`, which is always code, so the
 * quoted name and the quoted fallback being on the data channel is expected and
 * is not a reason to skip.
 *
 * A TypeScript non-null assertion between the read and the operator
 * (`process.env.API_KEY! || 'demo'`) is stepped over: it changes the type and
 * nothing else.
 *
 * Chained reads resolve at the operand that is actually a literal.
 * `process.env.A || process.env.B || 'demo'` yields nothing for `A`, whose
 * operand is another read, and the finding for `B` — which is the correct
 * anchor, because `B` is the read the default belongs to.
 */
function* envFallbacks(src, mask) {
  const re =
    /process\s*\.\s*env\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*(['"`])([^'"`\n]*)\2\s*\])/g;
  let m;
  while ((m = re.exec(src))) {
    if (!mask[m.index]) continue;

    let j = skipSpace(src, m.index + m[0].length);
    if (src[j] === '!') j = skipSpace(src, j + 1); // TS non-null assertion

    const op = src.slice(j, j + 2);
    if ((op !== '??' && op !== '||') || !mask[j]) continue;

    const operand = operandAt(src, skipSpace(src, j + 2));
    if (operand) yield { index: m.index, name: m[1] ?? m[3], operand };
  }
}

/**
 * Yield every defaulted binding of `const { NAME = <operand> } = process.env`,
 * as {index, name, operand}.
 *
 * The destructured form is the one no accessor pattern can see, because there
 * is no accessor: the read is the pattern itself. It is also the spelling that
 * reads most like ordinary modern JavaScript, which is precisely why it ends up
 * in config modules holding six defaults at once.
 *
 * Renaming is followed — `const { STRIPE_SECRET_KEY: sk = 'sk_test_x' } =
 * process.env` defaults the same variable — and the ENV name, not the local
 * one, is what the secret-name gate is asked about. `[^{}]*` keeps the pattern
 * flat, so a nested destructuring is skipped rather than mis-parsed; nobody
 * nests `process.env`.
 */
function* destructuredFallbacks(src, mask) {
  const re = /\{([^{}]*)\}\s*(?::[^=;\n]+)?=\s*(?:await\s+)?process\s*\.\s*env\b/g;
  let m;
  while ((m = re.exec(src))) {
    if (!mask[m.index]) continue;

    const inner = m[1];
    const base = m.index + 1; // the first character inside the `{`
    const entry = /([A-Za-z_$][\w$]*)\s*(?::\s*[A-Za-z_$][\w$]*\s*)?=\s*/g;
    let d;
    while ((d = entry.exec(inner))) {
      const operand = operandAt(src, base + d.index + d[0].length);
      if (operand) yield { index: base + d.index, name: d[1], operand };
    }
  }
}

/**
 * Is this fallback the CORRECT behaviour — a value that fails loudly the first
 * time it is used?
 *
 * Empty is the important one and it is the most common: `process.env.API_KEY ||
 * ''` is falsy, so the SDK below it throws exactly as if the variable were
 * absent. The author wrote a fallback and got fail-fast semantics anyway.
 */
function failsFast(text) {
  const trimmed = text.trim();
  if (trimmed === '') return true;
  return FAIL_FAST_LITERAL.has(trimmed.toLowerCase().replace(/[\s_.-]/g, ''));
}

/** The fallback's literal text, or null when this file cannot resolve one. */
function literalOf(operand, constants) {
  if (operand.kind === 'literal') return operand.text;
  const held = constants.get(operand.name);
  return held === undefined ? null : held;
}

/** The fallback as the impact text quotes it: one line, bounded, escaped. */
function preview(text) {
  const flat = text.replace(/\s+/g, ' ');
  return flat.length > LITERAL_PREVIEW ? `${flat.slice(0, LITERAL_PREVIEW)}…` : flat;
}

/**
 * The impact for one finding. The MEDIUM sentence says exactly what prodcheck
 * does and does not know — the same honesty the rate-limit rule's MEDIUM tier
 * carries — and the HIGH sentence names the outbound line, because that line is
 * the evidence for the claim that money leaves.
 */
function impactFor(name, text, outboundAt) {
  const head = `\`${name}\` falls back to \`"${preview(text)}"\`. ${IMPACT_HEAD}`;
  const middle = outboundAt
    ? ` This file calls out to the network at ${outboundAt}, so the default is what that call is signed with: the request goes out, comes back 200, and the only trace of it is on somebody else's bill.`
    : ' No outbound call is visible in this file, so prodcheck cannot show where the default is spent and does not claim to — it is still a default credential compiled into the source, and every module importing this one inherits it.';
  return head + middle + IMPACT_TAIL + REMEDIATION;
}

/**
 * The printed patch: read once, throw when missing.
 *
 * Written with the finding's OWN variable name rather than a placeholder,
 * because a remediation the reader has to adapt is a remediation they paste
 * wrong. The two lines belong at module top level — the whole point is that the
 * process refuses to start, not that request 4,000 fails.
 */
function fixFor(name) {
  return [
    `const ${name} = process.env.${name}  // read once, at module load`,
    `if (!${name}) throw new Error('${name} is not set')  // fail fast; never default a credential`,
  ];
}

export function isCandidate(relPath, content) {
  return CONTENT_HINT.test(stripComments(content));
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

  const stripped = stripComments(content);
  const mask = codeMask(content);

  const constants = stringConstants(stripped, mask);
  const outbound = outboundCallAt(stripped, mask);
  const outboundAt = outbound === -1 ? null : `${relPath}:${lineNumberAt(content, outbound)}`;

  // Both spellings, in source order, so the report reads down the file.
  const candidates = [...envFallbacks(stripped, mask), ...destructuredFallbacks(stripped, mask)];
  candidates.sort((a, b) => a.index - b.index);

  // One finding per LINE. A config module defaulting six secrets earns six
  // findings, which is right — each is a separate variable with a separate fix
  // — but two reads sharing a line are one line to change.
  const seenLines = new Set();

  for (const { index, name, operand } of candidates) {
    if (!isSecretName(name)) continue; // configuration, not a credential

    const text = literalOf(operand, constants);
    if (text === null) continue; // no literal this file can resolve
    if (failsFast(text)) continue; // the correct behaviour, and the opposite bug

    const line = lineNumberAt(content, index);
    if (seenLines.has(line)) continue;
    seenLines.add(line);

    findings.push({
      severity: outboundAt ? 'high' : 'medium',
      rule,
      file: relPath,
      line,
      impact: impactFor(name, text, outboundAt),
      fix: {
        remove: [sourceLineAt(content, index).trim()],
        add: fixFor(name),
      },
    });
  }

  return findings;
}
