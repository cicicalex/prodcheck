/**
 * rate-limit-bypass
 *
 * Finds rate limiters keyed on a client-forgeable identity header —
 * X-Forwarded-For or X-Real-IP — with no sign of trusted-proxy validation.
 * Those headers are set by whoever opens the socket, so the "identity" the
 * limiter buckets on is chosen by the attacker: rotate the value and every
 * request lands in a fresh bucket; pin a victim's address and the victim's
 * bucket is exhausted for them.
 *
 * Deliberately a heuristic, not a parser. Zero runtime dependencies is a hard
 * rule for this tool, so instead of an AST we do a light lexical pass: find
 * every read of a forgeable header, then ask whether that read can reach a
 * limiter identity — inside a keyGenerator body, directly in the arguments of
 * a limiter-ish call, through a variable assigned from the read, or out of a
 * getClientIp-style helper that RETURNS the value to a caller who keys a
 * limiter with it.
 *
 * Each of those questions is answered inside the enclosing FUNCTION of the
 * read, never file-wide: a header read that only feeds a log line is not
 * flagged because a different function in the same file keys a limiter with a
 * variable of the same name. The one place that guarantee does not hold is
 * MODULE TOP LEVEL, where a read has no enclosing function and the "scope" it
 * falls back to is the whole file — there a top-level log-only read can still
 * collide by name with a limiter keyed elsewhere in the file. That case is a
 * known false positive, documented in the README rather than hidden here.
 *
 * ── two outcomes, and no way to reach silence ───────────────────────────────
 *
 * For seven rounds this rule decided BINARY: report, or stay silent because
 * some socket-level rescue was detected near the read. Each round closed the
 * known one-line mutes and each round opened new ones in a different spelling —
 * a rescue moved above the read, into a `catch`, into a sibling `switch` case,
 * into a zero-iteration `for` body, behind a vacuous `if (req.socket
 * .remoteAddress)`. Every one of those muted a live, complete bypass with a
 * single line that protects no real request. The last round also produced the
 * opposite failure: extracting a guard into `const trusted = EDGE_NODES.has(
 * peer)` turned correct defensive code into a HIGH finding.
 *
 * The reason is structural, not a missing case. Deciding whether a particular
 * socket write GOVERNS a particular header read is dataflow analysis over a
 * control-flow graph. A lexical pass does not have one and cannot buy one at
 * zero dependencies, so every approximation of "does this rescue reach that
 * read" is wrong in both directions, and both directions are one line wide.
 *
 * So the suppression stopped pretending, and the rule now answers with a
 * CONFIDENCE instead of a verdict:
 *
 *   HIGH — the forgeable identity reaches a limiter and NO socket-level source
 *     is present for that identity anywhere in the read's enclosing function
 *     (cross-file: anywhere in the helper). Nothing in scope could rescue it,
 *     whatever the control flow turns out to be. This is the confident finding.
 *
 *   MEDIUM — a socket-level source IS present for that identity, and prodcheck
 *     cannot prove it governs this read. Reported, with the line of the socket
 *     source named, and explicitly labelled as something to confirm by hand.
 *
 * There is no third outcome INSIDE THIS RULE. Silence is not something a file
 * can be argued into by anything the rule itself weighs; it is what a file with
 * no forgeable identity reaching a limiter gets.
 *
 * That sentence used to be written without the qualifier, and it was false
 * twice over, both times for the same reason: silence does not have to be
 * argued for at the rule's level when it can be taken at the LEXER's.
 *
 *   Round 10 found that the classifier did not model regex literals at all, so
 *     `const RE = /` + backtick + `/;` opened a template frame and took the
 *     file dark. Round 10 fixed it by modelling them.
 *   Round 11 found the same failure one position over. Where the lexer REFUSES
 *     a regex — after `)`, `]` or a division `/` — the body it declines to
 *     consume stays in the code channel, so `if (1) /` + backtick + `/.test(x)`
 *     opened the same frame. One inert, valid, `node --check`-clean line took
 *     the file dark and returned it CLEAN.
 *
 * A 32,631-run harness scored 1,310 total silences from nine such one-liners,
 * over every loud file at every anchor, all four real production bugs included.
 *
 * That class is closed structurally rather than by enumeration — see the
 * invariant at the top of _lexer.mjs, which forbids the scan from ending inside
 * a frame and forbids a disputed `/` from darkening anything at all, with no
 * line test and no cost test left to evade — and the same harness now scores
 * zero, as does a wider one that adds the three mechanisms which evaded the
 * conditional version of that second clause. What is left is not a third
 * outcome of this rule but the scan SCOPE around it, and every one is visible as a
 * drop in `filesScanned` rather than as a clean report: a file bigger than
 * MAX_FILE_BYTES, a file whose extension is not in `extensions`, a file under a
 * skipped directory. All three are documented in the README under "What gets
 * scanned"; none of them can make a scanned file report clean.
 *
 * ── why proxy-trust CONFIGURATION is not a suppression ──────────────────────
 *
 * An eighth round removed the last one. Until it, a third outcome existed:
 * SILENT, whenever the file appeared to configure proxy trust — `app.set(
 * 'trust proxy', …)`, `app.enable('trust proxy')`, a `trustProxy` option, a
 * TRUSTED_PROXIES-style allowlist. That was defended as a CONFIGURATION FACT
 * rather than an inference about control flow, and the defence was wrong on
 * both halves.
 *
 * It was not a fact. It was two grep hits. `TRUST_HINT` was a
 * case-insensitive substring over the whole code channel with no position, no
 * value and no reachability test; `TRUST_SETTING` was matched against source
 * with STRING LITERALS KEPT. A mutation harness of ~10,500 runs — 45 spellings
 * across 3 insertion anchors over 78 loud files — drove 78 of 78 files,
 * including all four of the real production bugs this rule was built from, to
 * TOTAL SILENCE. Fourteen distinct one-line edits did it, from anywhere in the
 * file:
 *
 *     if (false) { app.set('trust proxy', 1); }   // never executes
 *     notAnApp.set('trust proxy', 1)              // not an app
 *     const HINT = "TODO: app.set('trust proxy', 1)"   // a string
 *     const trustProxy = false                    // trust explicitly OFF
 *     const TRUSTED_PROXIES = []                  // an EMPTY allowlist
 *     let untrustedProxyHits = 0                  // "untrusted prox" matched
 *     const distrustProxyMetrics = null           // so did "distrust prox"
 *     { trustProxy: false }                       // an option set to false
 *     function trustProxyTODO() {}                // a name
 *     type TrustProxy = never                     // erased at build time
 *     export const TRUSTED_PROXY_HEADER = 'x-forwarded-for'  // names the bug
 *
 * The worst of them was ours. The remediation this rule PRINTED —
 * `const ip = getClientIp(req, { trustProxy: TRUSTED_PROXIES })` — carried both
 * tokens. Paste prodcheck's own fix line, stub `getClientIp` to return the raw
 * header, and the file reported zero findings with the bypass fully intact.
 *
 * And it was not a suppression worth having even when the configuration was
 * real. A rule that can be silenced by a token a reader can SEE teaches an
 * attacker and an ordinary developer the same escape hatch, and the ordinary
 * developer reaches it by accident — one log line, one TODO, one type alias.
 * There is no way to make a substring test mean "this configuration is
 * reachable, enabled, and applies to this read": that is the same dataflow
 * question, wearing the word "configuration".
 *
 * So both gates are gone, and with them the constants that existed only to
 * feed them. The consequence is deliberate and worth stating plainly:
 *
 *   MANUALLY READING X-FORWARDED-FOR IS REPORTED EVEN IF PROXY TRUST IS
 *   CONFIGURED — because when it IS configured, correct code does not read the
 *   header at all. It asks the framework for the address the framework already
 *   resolved from the hops it was told to trust (`req.ip` under Express's
 *   `trust proxy`, the platform's verified client-IP value on an edge runtime).
 *   Hand-parsing the forwarded header next to a `trust proxy` setting takes the
 *   raw client-controlled string and walks straight past the validation the
 *   setting exists to perform. That is not a false positive. It is the bug with
 *   a reassuring line above it.
 *
 * The MEDIUM tier absorbs the rest, which is the point of the redesign: a file
 * that genuinely resolves its address from the socket has socket-level code in
 * scope, lands at MEDIUM, and MEDIUM does not fail a build under the default
 * `--fail-on high`. Measured, deleting both gates left the real repositories
 * IDENTICAL (4 HIGH, 0 MEDIUM across 461 files) and corpus HIGH unchanged at
 * 44, for exactly two new findings — both MEDIUM, both on files that already
 * carried a socket source.
 *
 * Why this ends the arms race:
 *
 *   - No edit that argues about CONTROL FLOW can mute a finding any more. A
 *     finding can be DOWNGRADED, never hidden, and only by genuinely putting
 *     socket-level code in scope. All six surviving mutes — the OPTIONS
 *     short-circuit, the socket default hoisted above the read, the `catch`,
 *     the sibling `switch` case, the zero-iteration loop, the vacuous socket
 *     condition — now produce MEDIUM findings instead of silence, and so does
 *     every trust-vocabulary edit.
 *
 *     This bullet used to read "There is no mute left, in any spelling", and
 *     that is a claim about a search space rather than about this rule, which
 *     is why two later rounds falsified it. Round 10 found the regex-literal
 *     family — the lexer read a regex body as code and a backtick in it opened
 *     a template frame — and round 11 found the same family one position over,
 *     in the places the lexer REFUSES a regex. Both were total silence on all
 *     four real production bugs from a single inserted line. Neither was a
 *     spelling this rule had failed to enumerate; both were the character
 *     classification underneath it losing sync, which no amount of vocabulary
 *     in this file could have caught.
 *
 *     So the honest form of the claim is the measurement and the mechanism, not
 *     the absolute. The mechanism: _lexer.mjs now holds an INVARIANT — no scan
 *     may end inside a frame, and no character may be classified not-code
 *     because of a disputed `/` reading — the first enforced as a post-condition
 *     with a repair pass, the second unconditional and discharged inside the
 *     pass, so a lost frame fails OPEN (over-report) instead of BLIND (silence).
 *     The measurement: 45,120 runs, 188 mutations, 9 corpora, 80 loud files,
 *     zero total silences, plus a per-file tuned sweep of 23,520 runs that
 *     drives 0 of the 80 to silence. The conditional version of the second
 *     clause scored 32 silences on the same harness and took 2 of the 80 to
 *     total silence when the adversary tuned one line per file. The next round
 *     should assume there is a family neither has thought of, and go looking.
 *   - Correct defensive code is no longer a false HIGH. A guard-clause helper,
 *     a ternary that discards the forwarded value, a rescue two levels up, a
 *     closure that assigns the outer identity: all of them are an honest "I
 *     cannot tell" at MEDIUM rather than a confident accusation.
 *   - The default `--fail-on high` does the work the suppression kept failing
 *     to do. A correct helper never breaks anyone's build; a real bypass with
 *     no socket code in sight does.
 *
 * ── what "for that identity" means ──────────────────────────────────────────
 *
 * The presence question is asked about the identity the READ produces, not
 * about the function as a whole, because a function may resolve two identities
 * and only one of them be rescued:
 *
 *   - a read bound to a name (`const realIp = req.headers['x-real-ip']`) is
 *     that name: a socket source counts when it is written TO that name
 *     anywhere in the enclosing function, in any direction, nested closures
 *     included.
 *   - a read bound to no name at all leaves by RETURN, and the identity is the
 *     function's return value: a socket source counts when any of the
 *     function's own return expressions yields one.
 *
 * Direction is never consulted — that was the dataflow question. Only presence
 * is, and presence is a question a lexical pass can answer soundly.
 *
 * The single exclusion that survives is not about direction either: a socket
 * address sitting behind a `||` or `??` — `req.headers['x-forwarded-for'] ||
 * req.socket.remoteAddress` — is not a rescue under any control flow, because
 * an attacker is never the absent-header case. They always send the header, so
 * the forgeable value owns the bucket key on every request they make. That is a
 * fact about the operator, not a guess about the path.
 *
 * ── the seam between two files ──────────────────────────────────────────────
 *
 * All of the above sees ONE file at a time, and the layout production code
 * actually has splits this bug across two: `lib/rate-limit.ts` exports the
 * getIp helper, `routes/**` import it and key a limiter with the result. Every
 * half looks innocent on its own — the helper never mentions a limiter, the
 * route never reads a header — so the whole canonical lib/+routes/ shape was
 * silent, which is the layout of the very repository this rule was validated
 * against.
 *
 * So this check also implements the optional two-phase contract (see
 * src/checks/index.mjs): `collect(file)` records, per file, the exported
 * helpers that hand a forgeable header back to their caller and the
 * limiter-reaching calls to names the file does not define; `finalize` joins
 * the two after the walk and reports each helper ONCE, at its own header read,
 * which is where the trusted-proxy check belongs and where the fix goes.
 *
 * The join is by MODULE, never by bare name: a call site is credited only when
 * it imports that name from that helper's module, or sits in the same package
 * with no binding of its own and no second module exporting the name. Matching
 * names across a repository would resurrect, at repository scale, exactly the
 * collision noise the per-function scoping above exists to prevent.
 *
 * ── the channel everything above reads ──────────────────────────────────────
 *
 * Every search here is gated on a character classification — code, or data —
 * that used to live in this file and now lives in ./_lexer.mjs, shared with
 * webhook-swallows-2xx. It did not model REGEX LITERALS, and that was not a
 * recall gap but a correctness bug: `const RE = /`/;` opened a template frame
 * that never closed, so every character below it was classified not-code and
 * every search in this rule — header reads, limiter calls, keyGenerator
 * bodies, socket writes — skipped it. The file reported clean with the bypass
 * intact, and the same thing happened with `/[`]/` and with `/[/*]/`. It had
 * already happened by accident in production code: ordinary CSV quoting,
 * `` `"${str.replace(/"/g, '""')}"` ``, took a real file dark from its line 11
 * to EOF.
 *
 * Modelling regex literals fixed those three and moved the hole rather than
 * closing it: in a position where the lexer REFUSES a regex — after `)`, `]`,
 * a division `/` — the body was left in the code channel, so `if (1) /` +
 * backtick + `/.test(x)` opened the same never-closing template frame. What
 * closes the class is not a longer list of positions but the INVARIANT stated
 * at the top of _lexer.mjs: no scan may end holding an open frame, and no
 * character may be classified not-code because of a disputed `/` reading. The
 * first is repaired by re-running the scan; the second is unconditional — a
 * frame the division reading opens inside a disputed span cannot darken
 * anything, whether it closes on the same line, forty lines down or never.
 * Either way the lexer fails OPEN. Read that header before touching the `/`
 * heuristic here.
 */

import { codeMask, stripComments } from './_lexer.mjs';

export const rule = 'rate-limit-bypass';

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

/**
 * A file is a candidate when its comment-stripped content mentions rate
 * limiting at all. The hint is matched against comment-stripped source, never
 * raw text — a stray `// TODO: add a rate limit` must not drag an unrelated
 * file into the analysis. Strings are deliberately KEPT in the hint text:
 * module names ('express-rate-limit', '@upstash/ratelimit') and header names
 * live in string literals, and stripping them would blind us to exactly the
 * files we care about.
 */
const CONTENT_HINT = /rate[-_ ]?limit|ratelimit|limiter|keyGenerator|slowDown/i;

/*
 * There is deliberately NO trust-proxy constant here any more. Two once lived
 * at this spot — a TRUST_HINT substring over the code channel and a
 * TRUST_SETTING match over source with strings kept — and each was a one-line
 * mute for the entire file. See the "why proxy-trust CONFIGURATION is not a
 * suppression" section of the module header before reintroducing anything of
 * the kind: proxy trust being configured somewhere in a file is not evidence
 * that a hand-rolled read of X-Forwarded-For is safe. It is evidence that the
 * read should not be there at all.
 */

/**
 * A client address the caller cannot choose: the peer address of the TCP
 * connection itself (`socket.remoteAddress`, `connection.remoteAddress`) or
 * the framework's own resolved address (`req.ip`, `request.ip`). Optional
 * chaining is allowed and the receiver is free — `req.socket`, `req?.socket`
 * and `ctx.request.connection` all read the same non-forgeable value.
 * Matched against the right-hand side of an assignment or the expression a
 * `return` yields, never on its own: the point is not that the file mentions
 * the socket, it is that THIS identity is *given* that value somewhere. A
 * `lookupRegion(req.socket.remoteAddress)` two lines up is a socket read that
 * has nothing to do with the limiter's key, and downgrading a finding for it
 * would make the MEDIUM tier meaningless.
 */
const SOCKET_SOURCE =
  /\b(?:req|request)\s*\??\.\s*ip\b|\b(?:socket|connection)\s*\??\.\s*remoteAddress\b/;

/** The two identity headers a client can set freely on the way in. */
const FORGEABLE = '(?:x-forwarded-for|x-real-ip)';

/** An opening quote, captured so the closing quote must match it. */
const Q = "(['\"`])";

/**
 * A read of a client-forgeable identity header, in the four spellings the
 * ecosystems actually use.
 *
 * Two are keyed on a `headers` receiver: `headers.get('x-forwarded-for')`
 * (fetch-style Headers, Next.js) and `headers['x-forwarded-for']` (Node/Express
 * plain object). There the receiver is any identifier CONTAINING `headers`, so
 * `req.headers`, `request.headers`, a bare destructured `headers` and the App
 * Router idiom `const headersList = headers()` all match. Anchoring on the
 * exact token `headers` looked equivalent and was not: it missed
 * `headersList.get('x-forwarded-for')` — the spelling Next.js's own docs use —
 * and with it every route that resolves its client IP through a bound Headers
 * object rather than off `req` directly.
 *
 * The other two are Express's accessors, `req.header('x-forwarded-for')` and
 * its alias `req.get('x-forwarded-for')`. Both were SILENT for eight rounds,
 * because the receiver test above demanded the token `headers` and `req` does
 * not contain it — so the single most idiomatic Express spelling of this bug,
 * fed straight into a limiter, was a documented-nowhere recall miss. These two
 * carry NO receiver constraint, and do not need one: what makes the read
 * forgeable is the header NAME, not the object it is asked of. `req`, `ctx.req`
 * and a bound `request` are all the same read.
 *
 * The noise that buys is a `.get(…)` on a Map or a URLSearchParams keyed by the
 * literal string 'x-forwarded-for' — which is either vanishingly rare or is
 * itself a forwarded-header lookup. Two things keep it bounded. The name must
 * be one of the two forgeable headers, spelled as a literal. And the call must
 * take EXACTLY ONE argument — `\(\s*'name'\s*\)` — which is what separates a
 * read from a write: Express's `res.header('x-forwarded-for', ip)` and
 * `headers.set('x-forwarded-for', ip)` both carry a second argument and neither
 * matches. A read is what can key a limiter; a write cannot.
 *
 * A fifth spelling reads the header by DESTRUCTURING the headers object rather
 * than indexing it — `const { 'x-forwarded-for': ip } = req.headers` — which no
 * accessor pattern can see because there is no accessor. It is matched at the
 * header name itself, with a lookahead requiring that the pattern it sits in is
 * closed and assigned from something whose name ends in `headers`. Without that
 * lookahead the alternative would match any object literal that happens to map
 * the string 'x-forwarded-for' to a name — a fixture, a mock, a test table.
 *
 * Header names are case-insensitive, and optional chaining is allowed on the
 * accessor forms (`req?.get('x-forwarded-for')`).
 *
 * ── header names held in a constant ─────────────────────────────────────────
 *
 * Every alternative above wants the name as a LITERAL at the read. Hoisting it
 * into a constant is ordinary code — `const XFF = 'x-forwarded-for'` at the top
 * of a middleware file, then `req.headers[XFF]` — and it was a total mute: the
 * read matched nothing, so the file was silent however the value was used. So
 * the pattern is built per file, and when the file binds a forgeable header
 * name to a constant, the same three accessor shapes are also matched with that
 * CONSTANT'S NAME in the argument position. The binding is the whole gate: a
 * name is only ever admitted because this file was seen assigning it one of the
 * two forgeable header strings.
 */

/** `const XFF = 'x-forwarded-for'` — the binding that admits a name below. */
const HEADER_NAME_BINDING = new RegExp(
  `\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::[^=;\\n]+)?=\\s*${Q}${FORGEABLE}\\2\\s*(?=[;,\\n]|$)`,
  'gi'
);

/**
 * The names this file binds to a forgeable header string, as a Set. Empty for
 * almost every file, which is why the read pattern is only rebuilt when it is
 * not: a constant-free file gets exactly the regex it always got.
 */
function headerNameConstants(src, mask) {
  const names = new Set();
  const re = new RegExp(HEADER_NAME_BINDING.source, 'gi');
  let m;
  while ((m = re.exec(src))) {
    if (mask[m.index]) names.add(m[1]);
  }
  return names;
}

/**
 * The read pattern for one file: the literal-name spellings, plus the same
 * accessors keyed by any constant this file bound to a header name.
 *
 * Built rather than declared because the backreference numbers have to stay in
 * step with the alternatives — `\1`…`\4` below are the four opening quotes, and
 * the constant-name alternatives add no groups at all.
 */
function headerReadPattern(nameConsts = new Set()) {
  const alternatives = [
    // headers.get('x-forwarded-for') — fetch-style Headers
    `\\b[\\w$]*headers[\\w$]*\\s*\\??\\.\\s*get\\s*\\(\\s*${Q}${FORGEABLE}\\1\\s*\\)`,
    // headers['x-forwarded-for'] — plain object
    `\\b[\\w$]*headers[\\w$]*\\s*\\[\\s*${Q}${FORGEABLE}\\2\\s*\\]`,
    // req.header('x-forwarded-for') / req.get('x-forwarded-for') — Express
    `\\b[\\w$]+\\s*\\??\\.\\s*(?:header|get)\\s*\\(\\s*${Q}${FORGEABLE}\\3\\s*\\)`,
    // const { 'x-forwarded-for': ip } = req.headers — object destructuring.
    // Anchored on the `{` or `,` that introduces the property rather than on
    // the quote, because the quote opens a STRING and `headerReads` only
    // accepts matches that begin on the code channel.
    `[{,]\\s*(['"])${FORGEABLE}\\4\\s*:\\s*[A-Za-z_$][\\w$]*` +
      `(?=[^}]{0,200}\\}\\s*=\\s*(?:await\\s+)?[\\w$.?()]*headers\\b)`,
  ];

  if (nameConsts.size) {
    const names = [...nameConsts].map((n) => n.replace(/\$/g, '\\$&')).join('|');
    const held = `(?:${names})`;
    alternatives.push(
      `\\b[\\w$]*headers[\\w$]*\\s*\\??\\.\\s*get\\s*\\(\\s*${held}\\s*\\)`,
      `\\b[\\w$]*headers[\\w$]*\\s*\\[\\s*${held}\\s*\\]`,
      `\\b[\\w$]+\\s*\\??\\.\\s*(?:header|get)\\s*\\(\\s*${held}\\s*\\)`
    );
  }

  return new RegExp(alternatives.join('|'), 'gi');
}

/**
 * Receivers that plausibly are a limiter. Substring match on purpose:
 * `limiter`, `rateLimiter`, `loginRateLimit`, `bucket`, `slowDown` — plus the
 * conventional short name `rl`. `res.check()` or `user.increment()` must not
 * qualify, which is why the receiver is tested at all.
 */
const LIMITER_RECEIVER = /limit|rate|bucket|slow|throttl|^rl$/i;

/**
 * Constructors and factories that PRODUCE a limiter, matched against the callee
 * name of the expression a variable is initialised from.
 *
 * The name test above asks what a variable is CALLED; this asks what it IS.
 * Until it existed, `const guard = new RateLimiterMemory({ points: 5 })`
 * followed by `await guard.consume(ip)` was silent, and renaming `guard` to
 * `limiter` made the identical program a HIGH. That is a rule that only sees
 * code somebody has already thought about naming — the in-house limiter written
 * by a team that never considered proxy trust is exactly the one called `guard`,
 * `gate` or `bucketStore`, and it was invisible by construction.
 *
 * Covers `new RateLimiterMemory(...)` / `new RateLimiterRedis(...)`
 * (rate-limiter-flexible), `new Ratelimit(...)` (@upstash/ratelimit),
 * `rateLimit(...)` (express-rate-limit), `slowDown(...)` (express-slow-down) and
 * any `new …Throttle…`/`…RateLimit…`/`…Limiter…` of the same shape.
 */
const LIMITER_CONSTRUCTOR = /rate[-_]?limit|ratelimit|limiter|throttl|slow[-_]?down/i;

/**
 * Callee prefixes that make a limiter-ish FACTORY name a predicate instead.
 * `const allowed = checkRateLimit(ip)` yields a boolean, not a limiter, and
 * binding `allowed` as a limiter receiver would widen the receiver gate on
 * nothing. Only applied to the bare-call form: a `new` expression is a
 * construction whatever it is named.
 */
const NOT_A_LIMITER_FACTORY = /^(?:check|is|has|assert|enforce|apply|verify|validate|test|should|can|get)/i;

/**
 * Callee names that make a BARE `name(...)` call a limiter call — the shape
 * hand-rolled limiters actually ship as: `checkRateLimit(ip)`,
 * `rateLimit(key, limit, windowMs)`, `throttle(ip)`, `enforceLimiter(ip)`.
 * Matching only `receiver.method(...)` meant every in-house limiter — the ones
 * with no library behind them, written by the teams least likely to have
 * thought about proxy trust at all — was invisible to this rule.
 *
 * The bar is higher than LIMITER_RECEIVER's because there is no second gate
 * here: with a method call the receiver AND the verb must both fit, while a
 * bare call has only its own name to go on. So the limiter-ish word must be in
 * the callee name itself — `checkRateLimit` and `rateLimiter` qualify, plain
 * `check(...)`, `limit(...)` and `apply(...)` do not, and the `check`/`enforce`/
 * `apply` prefixes come along for free because this is a substring test.
 */
const LIMITER_FUNCTION = /rate[-_ ]?limit|ratelimit|limiter|throttl|slow[-_ ]?down|consume/i;

/**
 * Keywords that turn `name(` into something other than a call: the definition
 * of the limiter (`function rateLimit(key, limit, windowMs)`) and the
 * construction of one (`new RateLimiterMemory({ points: 5 })`). Neither
 * consumes an identity, and reading a parameter list as an argument list put
 * the limiter's own parameter names — `key`, `limit` — into the reachability
 * search, where any identity variable sharing one would have matched.
 */
const DECLARATION_KEYWORD = /^(?:function|class|new)$/;

const IMPACT =
  'The rate-limit identity comes from a header any client can set freely. An ' +
  'attacker rotates the value to get a fresh bucket on every request — the ' +
  'limit simply does not exist for them — or pins a victim\'s IP to exhaust ' +
  'that victim\'s bucket. Without trusted-proxy validation the header proves ' +
  'nothing about who is calling.';

/**
 * The framework nuance the one-line patch cannot carry, appended to every
 * finding. It belongs here rather than in `FIX_ADD` because the correct call is
 * different per runtime and a snippet that looks universal gets pasted where it
 * is wrong.
 *
 * The load-bearing sentence is the last one. This finding is reported even when
 * the file DOES configure proxy trust, and a reader who assumes otherwise will
 * read the report as a false positive and dismiss a live bug.
 */
const REMEDIATION =
  ' Resolve the address through the framework instead of parsing the header: ' +
  'under Express, set `trust proxy` to the number of proxies you actually ' +
  'control and read `req.ip`, which is then derived from validated hops only. ' +
  'On Next.js, Vercel, Cloudflare or another edge runtime there is no `req.ip` ' +
  'to read — use the platform\'s own verified client-IP value, since only the ' +
  'platform knows which hop it terminated. Note that configuring proxy trust ' +
  'does not by itself make this line safe: reading the forwarded header by ' +
  'hand walks straight past the validation that setting performs, which is why ' +
  'prodcheck reports this read even in a file where trust is configured.';

/**
 * The printed patch. Two lines, Express-shaped, and deliberately NOT a call to
 * a `getClientIp` helper.
 *
 * The previous value was `const ip = getClientIp(req, { trustProxy:
 * TRUSTED_PROXIES })`, and it was the single worst line in this rule. It named
 * a helper that does not exist, so the reader has to write it — and the obvious
 * stub, "return the header", is the bypass they started with. Worse, while the
 * trust suppression existed that string carried both of its trigger tokens: a
 * developer who pasted prodcheck's own remediation and stubbed the helper got a
 * clean report over an untouched bug. Remediation that silences the rule that
 * printed it is not remediation.
 *
 * `req.ip` needs no helper and cannot be stubbed wrong: under `trust proxy` the
 * framework has already done the hop validation. Non-Express runtimes are
 * covered in REMEDIATION rather than here, because there is no single line that
 * is correct in all of them.
 */
const FIX_ADD = [
  "app.set('trust proxy', <hops you control>)  // once, at app setup",
  'const ip = req.ip  // the address the framework resolved, not the raw header',
];

export function isCandidate(relPath, content) {
  return CONTENT_HINT.test(stripComments(content));
}

/** Advance past whitespace and not-code (comments) to the next code char. */
function skipToCode(src, mask, j) {
  while (j < src.length && (!mask[j] || /\s/.test(src[j]))) j += 1;
  return j;
}

/** Step back past whitespace and not-code (comments) to the previous code char. */
function skipBackToCode(src, mask, j) {
  while (j >= 0 && (!mask[j] || /\s/.test(src[j]))) j -= 1;
  return j;
}

/** Is `index` inside the half-open range `r`? */
const within = (index, r) => index >= r.start && index < r.end;

/**
 * The index of the `}` closing the block opened at `brace`, brace-matched on
 * the code channel. Unbalanced source runs to EOF rather than throwing away
 * the rest of the analysis.
 */
function matchingCloseBrace(src, mask, brace) {
  let depth = 0;
  for (let i = brace; i < src.length; i++) {
    if (!mask[i]) continue;
    if (src[i] === '{') depth += 1;
    else if (src[i] === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return src.length;
}

/** The index of the `(` matching the `)` at `closeIndex`, or -1. */
function matchingOpenParen(src, mask, closeIndex) {
  let depth = 0;
  for (let i = closeIndex; i >= 0; i--) {
    if (!mask[i]) continue;
    if (src[i] === ')') depth += 1;
    else if (src[i] === '(') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * The one shape that also reads as `ident ( … ) { … }` and is not a function.
 * `try`, `else`, `do` and bare blocks carry no parameter list and are rejected
 * by the `)` test before this list is ever consulted.
 */
const BLOCK_KEYWORD = /^(?:if|for|while|switch|catch|with)$/;

/** The identifier ending at `end`, as {name, start}, or null if none does. */
function identifierEndingAt(src, mask, end) {
  if (end < 0 || !mask[end] || !/[\w$]/.test(src[end])) return null;
  let k = end;
  while (k >= 0 && mask[k] && /[\w$]/.test(src[k])) k -= 1;
  return { name: src.slice(k + 1, end + 1), start: k + 1 };
}

/**
 * Step back from `from` over a TypeScript RETURN-TYPE annotation to the `)`
 * that closes the parameter list, or return `from` unchanged when there is no
 * annotation to skip.
 *
 * `function getIp(req: Request): string {` is the shape every annotated route
 * in a .ts file has, and the token before its body brace is `string`, not `)`.
 * Without this step such a function did not read as a function at all: its body
 * was not a function body, so "the enclosing function of this read" silently
 * widened to the whole file — in the very TypeScript API routes this rule
 * exists to check.
 *
 * The annotation is skipped by scanning back to its `:`, tracking `<>` and `[]`
 * so `): Promise<Map<string, T>> {` resolves to its own `)`. Anything that
 * cannot be an annotation — a brace, a `;`, an assignment, a stray paren —
 * stops the walk and leaves `from` as it was, which reads as "not a function"
 * exactly as before.
 */
function skipReturnType(src, mask, from) {
  let depth = 0;
  for (let i = from; i >= 0; i--) {
    if (!mask[i]) continue;
    const ch = src[i];
    if (ch === '>' || ch === ']') { depth += 1; continue; }
    if (ch === '<' || ch === '[') {
      if (depth === 0) return from;
      depth -= 1;
      continue;
    }
    if (depth > 0) continue;
    if (ch === ':') {
      const k = skipBackToCode(src, mask, i - 1);
      return k >= 0 && src[k] === ')' ? k : from;
    }
    if (/[;={}()!?,]/.test(ch)) return from; // not an annotation after all
  }
  return from;
}

/**
 * The token that ends a function SIGNATURE preceding the `{` at `brace`: the
 * `>` of an arrow's `=>`, or the `)` of a parameter list — looking past a
 * TypeScript return-type annotation when one sits in between.
 */
function signatureEnd(src, mask, brace) {
  const j = skipBackToCode(src, mask, brace - 1);
  if (j < 0) return j;
  if (src[j] === ')') return j;
  if (src[j] === '>' && j > 0 && src[j - 1] === '=') return j; // arrow body
  return skipReturnType(src, mask, j);
}

/**
 * Does the `{` at `brace` open a FUNCTION body?
 *
 * Same reasoning keyGeneratorRanges applies when it walks forward onto a body,
 * run backwards: skipping whitespace, comments and any return-type annotation
 * on the code channel, the `{` is preceded either by the `=>` of an arrow, or
 * by a `)` whose matching `(` is preceded by `function`, by a method-shorthand
 * or function name, or by a name that itself follows `function`. All three
 * collapse to one test — the token before the parameter list is an identifier —
 * once the control-flow keywords that share the shape are excluded.
 */
function isFunctionBody(src, mask, brace) {
  const j = signatureEnd(src, mask, brace);
  if (j < 0) return false;
  if (src[j] === '>' && j > 0 && src[j - 1] === '=') return true; // arrow body
  if (src[j] !== ')') return false;

  const open = matchingOpenParen(src, mask, j);
  if (open <= 0) return false;
  const end = skipBackToCode(src, mask, open - 1);
  if (end < 0) return false;

  let k = end;
  while (k >= 0 && mask[k] && /[\w$]/.test(src[k])) k -= 1;
  if (k === end) return false; // `)(`, `](`, an operator — not a callable name
  return !BLOCK_KEYWORD.test(src.slice(k + 1, end + 1));
}

/**
 * The enclosing FUNCTION body of `index`, as {start, end} delimiting the text
 * between its braces. Walks outward through the brace blocks containing the
 * index — brace-matched on the code channel, so a `{` inside a string or a
 * comment cannot open one — and returns the first that is a function body.
 * A read at module top level has none, and gets the whole file.
 *
 * This is the scope the socket-source search runs in. The function is the unit
 * that matters because it is the unit a local identity variable lives in: every
 * `if`, `else` and loop body inside it can be reached from the read, and so can
 * every line of the function above and below the block the read happens to sit
 * in. The innermost `{...}` is a smaller thing than the identity it was being
 * used to reason about, and a file is a larger one.
 *
 * The module-top-level fallback is a known false positive, disclosed in the
 * README: a top-level read gets the whole file as its "function", so a log-only
 * read there can still collide by name with a limiter keyed further down. Every
 * other read is safe from that, which is why the fallback is the exception
 * worth documenting rather than the rule worth rewriting.
 */
function enclosingFunctionBody(src, mask, index) {
  const open = [];
  const limit = Math.min(index, src.length);
  for (let i = 0; i < limit; i++) {
    if (!mask[i]) continue;
    if (src[i] === '{') open.push(i);
    else if (src[i] === '}') open.pop();
  }

  for (let d = open.length - 1; d >= 0; d--) {
    const brace = open[d];
    if (isFunctionBody(src, mask, brace)) {
      return { start: brace + 1, end: matchingCloseBrace(src, mask, brace) };
    }
  }
  return { start: 0, end: src.length }; // module top level
}

/**
 * The function bodies nested inside `range`, outermost only — anything deeper
 * is already contained in one of them, and containment is all the caller needs.
 */
function nestedFunctionBodies(src, mask, range) {
  const out = [];
  for (let i = range.start; i < range.end; i++) {
    if (!mask[i] || src[i] !== '{') continue;
    if (!isFunctionBody(src, mask, i)) continue;
    const close = Math.min(matchingCloseBrace(src, mask, i), range.end);
    out.push({ start: i + 1, end: close });
    i = close;
  }
  return out;
}

/**
 * The name bound by `… name = <j>` — used to recover the name of a function
 * written as an expression. Steps over an `async` keyword, and refuses `==`,
 * `<=`, `>=` and `!=`, none of which bind anything.
 */
function nameBeforeAssignment(src, mask, j) {
  if (j < 0) return null;
  const maybeAsync = identifierEndingAt(src, mask, j);
  if (maybeAsync && maybeAsync.name === 'async') {
    j = skipBackToCode(src, mask, maybeAsync.start - 1);
  }
  if (j < 0 || src[j] !== '=') return null;
  if ('=!<>'.includes(src[j - 1])) return null;
  const id = identifierEndingAt(src, mask, skipBackToCode(src, mask, j - 1));
  return id ? id.name : null;
}

/**
 * The NAME of the function whose body starts at `bodyStart`, or null when it
 * has none (an anonymous callback, a module top level). Covers the spellings a
 * getClientIp-style helper is actually written in:
 *
 *   function getClientIp(req) { … }          export function getIp(req) { … }
 *   const getClientIp = (req) => { … }       const getIp = async (req) => { … }
 *   const getClientIp = function (req) { … } { getClientIp(req) { … } }
 *
 * A name is what makes the cross-function reach path possible at all: a local
 * variable dies with its block, but a function's name is a binding the rest of
 * the file can call — which is exactly what the caller does with the forgeable
 * value the helper hands back.
 */
function functionNameOfBody(src, mask, bodyStart) {
  const brace = bodyStart - 1;
  if (brace < 0 || src[brace] !== '{') return null;
  const j = signatureEnd(src, mask, brace);
  if (j < 0) return null;

  if (src[j] === '>' && j > 0 && src[j - 1] === '=') {
    // `name = (a, b) => {`, `name = a => {`, `name = async (a): T => {`
    let k = skipBackToCode(src, mask, j - 2);
    if (k >= 0 && src[k] !== ')') k = skipReturnType(src, mask, k);
    if (k < 0) return null;
    if (src[k] === ')') {
      const open = matchingOpenParen(src, mask, k);
      if (open < 0) return null;
      k = skipBackToCode(src, mask, open - 1);
    } else {
      const param = identifierEndingAt(src, mask, k); // single bare parameter
      if (!param) return null;
      k = skipBackToCode(src, mask, param.start - 1);
    }
    return nameBeforeAssignment(src, mask, k);
  }

  if (src[j] !== ')') return null;
  const open = matchingOpenParen(src, mask, j);
  if (open <= 0) return null;
  const id = identifierEndingAt(src, mask, skipBackToCode(src, mask, open - 1));
  if (!id) return null;
  // `function name(` and method shorthand `name(` both end in the name itself;
  // only an anonymous `function (` sends us one token further back.
  if (id.name !== 'function') return id.name;
  return nameBeforeAssignment(src, mask, skipBackToCode(src, mask, id.start - 1));
}

/**
 * Yield the expression range {start, end} of every `return` belonging to the
 * function body `range` — nested function bodies cut out, because their
 * returns hand a value to a different caller entirely.
 *
 * The expression runs to the `;` that ends the statement, or to the `}` that
 * ends the function, whichever comes first, with parens/brackets/braces
 * tracked so a `;` inside `return f({ a: 1 })` cannot end it early.
 */
function* returnExpressions(src, mask, range) {
  const nested = nestedFunctionBodies(src, mask, range);
  const re = /\breturn\b/g;
  re.lastIndex = range.start;
  let m;
  while ((m = re.exec(src)) && m.index < range.end) {
    if (!mask[m.index]) continue; // the word inside a string or a comment
    if (nested.some((r) => within(m.index, r))) continue; // another function's return

    const start = m.index + 'return'.length;
    let depth = 0;
    let k = start;
    for (; k < range.end; k++) {
      if (!mask[k]) continue;
      const ch = src[k];
      if (ch === '(' || ch === '[' || ch === '{') depth += 1;
      else if (ch === ')' || ch === ']' || ch === '}') {
        if (depth === 0) break;
        depth -= 1;
      } else if (depth === 0 && ch === ';') break;
    }
    yield { start, end: k };
  }
}

/**
 * Yield every read of a forgeable header: {index}. The `headers` token itself
 * must be code — a header name quoted inside some unrelated string (a log
 * message, a test assertion) is not a read.
 *
 * `pattern` is the per-file read pattern from `headerReadPattern`, which is the
 * literal-name spellings plus any accessor keyed by a constant this file bound
 * to a header name. It defaults to the literal-only pattern so that a caller
 * with no file context still gets the behaviour it always had.
 */
function* headerReads(src, mask, pattern = headerReadPattern()) {
  const re = new RegExp(pattern.source, 'gi');
  let m;
  while ((m = re.exec(src))) {
    if (!mask[m.index]) continue;
    yield { index: m.index };
  }
}

/**
 * Yield the value range of every `keyGenerator` property: {start, end}.
 * Handles the spellings rate limiters actually use:
 *
 *   keyGenerator: (req) => expr
 *   keyGenerator: (req) => { ... }
 *   keyGenerator: function (req) { ... }
 *   keyGenerator(req) { ... }
 *
 * Braced bodies are brace-matched on the code channel. Expression-arrow
 * bodies end at the first code-level `,`, `;`, `}`, `)` or newline outside
 * nested parens/brackets — a multi-line expression body is truncated at the
 * first line, which is accepted: the header read we care about starts on it.
 */
function* keyGeneratorRanges(src, mask) {
  const re = /\bkeyGenerator\b/g;
  let m;
  while ((m = re.exec(src))) {
    if (!mask[m.index]) continue; // the word in a string or template, not code

    let j = skipToCode(src, mask, m.index + 'keyGenerator'.length);
    if (src[j] === ':') j = skipToCode(src, mask, j + 1);

    // Walk to the start of the body: past the parameter list and, for arrows,
    // past the `=>`. The paren depth keeps default parameter values from
    // ending the walk early.
    let depth = 0;
    let body = -1; // index of the `{` opening a block body
    let expr = -1; // index of the first code char of an expression body
    while (j < src.length) {
      if (mask[j]) {
        const ch = src[j];
        if (ch === '(') depth += 1;
        else if (ch === ')') depth -= 1;
        else if (depth === 0 && ch === '{') { body = j; break; }
        else if (depth === 0 && ch === '=' && src[j + 1] === '>') {
          j = skipToCode(src, mask, j + 2);
          if (src[j] === '{') body = j;
          else expr = j;
          break;
        } else if (depth === 0 && (ch === ',' || ch === ';' || ch === '}')) {
          break; // `delete opts.keyGenerator` and friends — not a function
        }
      }
      j += 1;
    }

    if (body !== -1) {
      yield { start: body + 1, end: matchingCloseBrace(src, mask, body) };
      continue;
    }

    if (expr !== -1) {
      let d = 0;
      let k = expr;
      for (; k < src.length; k++) {
        if (!mask[k]) continue;
        const ch = src[k];
        if (ch === '(' || ch === '[') d += 1;
        else if (ch === ')' || ch === ']') {
          if (d === 0) break; // closes the enclosing call — body over
          d -= 1;
        } else if (d === 0 && (ch === ',' || ch === ';' || ch === '}' || ch === '\n')) {
          break;
        }
      }
      yield { start: expr, end: k };
    }
  }
}

/** The argument range {start, end, args} of the call whose `(` sits at `open`. */
function callArguments(src, mask, open) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (!mask[i]) continue;
    if (src[i] === '(') depth += 1;
    else if (src[i] === ')') {
      depth -= 1;
      if (depth === 0) return { start: open + 1, end: i, args: src.slice(open + 1, i) };
    }
  }
  return null;
}

/**
 * The identifier inside the parentheses that close at `closeIndex`, or null.
 *
 * `(limiter).consume(ip)` and `(limiter as Ratelimit).consume(ip)` name the same
 * receiver `limiter.consume(ip)` does; `(await getLimiter()).consume(ip)` and
 * `foo().consume(ip)` name something this rule cannot resolve, and answer null.
 * A TypeScript `as` cast or a `!` non-null assertion is stepped over because
 * neither changes which variable is being called.
 */
function parenthesisedReceiver(src, mask, closeIndex) {
  const open = matchingOpenParen(src, mask, closeIndex);
  if (open === -1) return null;
  const inner = src.slice(open + 1, closeIndex).trim();
  const id = /^([A-Za-z_$][\w$]*)\s*(?:!|as\s[\s\S]+)?$/.exec(inner);
  return id ? id[1] : null;
}

/**
 * The variables this file assigns a CONSTRUCTED limiter to.
 *
 * `const guard = new RateLimiterMemory({ points: 5 })` binds a limiter to a name
 * that says nothing about limiting, and `await guard.consume(ip)` is then a
 * limiter call that the name-based receiver test cannot see. The set collected
 * here is what makes the two spellings equivalent — the previous behaviour was
 * that renaming `guard` to `limiter` turned a silent file into a HIGH, which
 * means code written that way from the start was never checked at all.
 *
 * Three binding shapes, which is what real setup code uses: a declaration
 * (`const|let|var name = …`, TypeScript annotation and `export` included), a
 * plain reassignment (`name = …`), and a field (`this.name = …`, whose call
 * sites read as `this.name.consume(…)` and whose receiver token is `name`).
 *
 * `new X(…)` qualifies on the constructor name alone. A bare factory call
 * `f(…)` qualifies on the same vocabulary minus the predicate prefixes, because
 * `const allowed = checkRateLimit(ip)` binds a boolean and not a limiter.
 */
function limiterVariables(src, mask) {
  const names = new Set();
  const re =
    /(?:\b(?:const|let|var)\s+|(?:^|[;{}()\n])\s*(?:this\s*\.\s*)?)([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=\s*(?:await\s+)?(new\s+)?([A-Za-z_$][\w$.]*)\s*\(/g;
  let m;
  while ((m = re.exec(src))) {
    if (!mask[m.index]) continue; // the declaration is text inside a literal
    const [, name, isNew, callee] = m;
    if (!LIMITER_CONSTRUCTOR.test(callee)) continue;
    const tail = callee.slice(callee.lastIndexOf('.') + 1);
    if (!isNew && NOT_A_LIMITER_FACTORY.test(tail)) continue;
    names.add(name);
  }
  return names;
}

/**
 * Yield every call that consumes a limiter identity: {start, end, args} where
 * start/end delimit the argument text. Two shapes qualify.
 *
 * A METHOD call `receiver.verb(...)`, where the verb is one of the ones limiter
 * APIs use (limit, consume, check, increment) AND the receiver IS a limiter —
 * both gates together are what keeps `res.check()` or `metrics.increment()` out
 * of the findings.
 *
 * "Is a limiter" is answered two ways, and the second one is what stops the
 * rule from only seeing limiters somebody named well. A receiver whose NAME
 * carries a limiter word qualifies (LIMITER_RECEIVER), and so does one this
 * file CONSTRUCTED as a limiter — `const guard = new RateLimiterMemory(…)`
 * makes `guard.consume(ip)` a limiter call however the variable is spelled.
 * `limiterVars` carries that set; it is empty when the caller does not compute
 * one, and the name test alone answers, exactly as before.
 *
 * The receiver may be reached through `?.` and it may be parenthesised —
 * `limiter?.consume(ip)` and `(limiter).consume(ip)` are the same call as
 * `limiter.consume(ip)`, and both were silent while the header-read pattern and
 * SOCKET_SOURCE had allowed optional chaining for rounds. A defensive `?.`
 * added by someone tidying up is not a fix, and it must not read as one.
 *
 * A BARE call `name(...)` whose own name carries a limiter-ish word. This is
 * how a hand-rolled limiter is invoked — `checkRateLimit(ip)`,
 * `rateLimit(key, limit, windowMs)` — and it has no receiver to corroborate the
 * verb, so LIMITER_FUNCTION carries the whole burden and is strict about it.
 * Definitions and constructions are skipped: `function rateLimit(key, …)` is
 * where the limiter is written, not where an identity is handed to it. Calls
 * already reached through a `.` are skipped too, as the method form owns them.
 *
 * A definition is recognised two ways, because only one of them has a keyword.
 * `function rateLimit(…)` and `new RateLimiterMemory(…)` announce themselves
 * with DECLARATION_KEYWORD; method shorthand — `{ rateLimitKey(ip) { … } }` in
 * an object literal, `rateLimit(key) { … }` in a class — announces nothing at
 * all, and its parameter list read as an argument list put the definition's own
 * parameter names into the reachability search, where any identity variable
 * spelling one of them the same way matched. What both forms do share is the
 * `{` that follows the parameter list, and a call never has one there.
 */
function* limiterCalls(src, mask, limiterVars = new Set()) {
  const method = /(?:\b([A-Za-z_$][\w$]*)|\))\s*\??\.\s*(limit|consume|check|increment)\s*\(/g;
  let m;
  while ((m = method.exec(src))) {
    if (!mask[m.index]) continue; // receiver named inside a string
    const receiver = m[1] ?? parenthesisedReceiver(src, mask, m.index);
    if (!receiver) continue;
    if (!LIMITER_RECEIVER.test(receiver) && !limiterVars.has(receiver)) continue;
    const call = callArguments(src, mask, m.index + m[0].length - 1);
    if (call) yield call;
  }

  const bare = /\b([A-Za-z_$][\w$]*)\s*\(/g;
  while ((m = bare.exec(src))) {
    if (!mask[m.index]) continue; // callee named inside a string
    if (!LIMITER_FUNCTION.test(m[1])) continue;

    const before = skipBackToCode(src, mask, m.index - 1);
    if (before >= 0 && src[before] === '.') continue; // a method call, handled above
    const keyword = identifierEndingAt(src, mask, before);
    if (keyword && DECLARATION_KEYWORD.test(keyword.name)) continue;

    const call = callArguments(src, mask, m.index + m[0].length - 1);
    if (!call) continue;
    // `name(…) {` is a body, not a call site: method shorthand, a class method,
    // a keyword-less definition of any kind. A real call is followed by `)`,
    // `;`, `,`, an operator — never by the block it would otherwise own.
    if (src[skipToCode(src, mask, call.end + 1)] === '{') continue;
    yield call;
  }
}

/**
 * Does a `||` or `??` operator GOVERNING the expression appear on the code
 * channel in `src[from, to)`?
 *
 * Both are two characters, so optional chaining (`req?.socket`) and the `?` of
 * a ternary never trip it — which is the whole point: a ternary means a
 * condition is choosing, a coalescing operator means the absence of a value is.
 *
 * Only operators at bracket depth 0 relative to `from` count. A coalesce nested
 * inside a call or an index — the `|| ''` of the ubiquitous
 * `String(req.headers['x-forwarded-for'] || '').split(',')[0]` — defaults that
 * argument, not the value the whole expression yields, and reading it as the
 * outer choice made `cond ? String(xff || '') : req.socket.remoteAddress` look
 * like a fallback when a condition is plainly doing the choosing.
 */
function coalesceBefore(src, mask, from, to) {
  let depth = 0;
  for (let i = from; i + 1 < to; i++) {
    if (!mask[i]) continue;
    const ch = src[i];
    if (ch === '(' || ch === '[' || ch === '{') { depth += 1; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth -= 1; continue; }
    if (depth > 0) continue;
    if (!mask[i + 1]) continue;
    if (ch === src[i + 1] && (ch === '|' || ch === '?')) return true;
  }
  return false;
}

/**
 * The variable a header read is assigned to, or null. Line-local on purpose:
 * `const ip = req.headers['x-forwarded-for'].split(',')[0]` is the pattern in
 * the wild, and chasing assignments across statements is parser territory.
 *
 * The declaration NEAREST the read wins, and a declaration list has more than
 * one: in `const a = 1, ip = req.headers['x-forwarded-for']` the read belongs to
 * `ip`, not to the declarator that happens to follow the keyword. Hence the
 * second alternative — a declarator introduced by a comma rather than by
 * `const`/`let`/`var` — without which the read was linked to `a`, `a` was never
 * seen near a limiter, and a genuinely bypassable file went unreported while the
 * same code split across two statements was flagged.
 *
 * `(?![=>])` keeps `==`, `===` and the `=>` of a comma-separated callback
 * parameter (`fn(a, req => …)`) from reading as a binding.
 *
 * ── binding through a destructuring pattern ─────────────────────────────────
 *
 * Two of the three most common spellings in the wild bind through a pattern
 * rather than through a bare name, and both used to answer null — which meant
 * the read reached no limiter, the file was silent, and the bypass was complete:
 *
 *   const [ip] = String(req.headers['x-forwarded-for'] || '').split(',')
 *   const { 'x-forwarded-for': ip } = req.headers
 *
 * The array form takes the FIRST element, which is the first forwarded hop and
 * the value every one of these lines is after. The object form is read at the
 * header name itself — that is where the read pattern matches it — so it is
 * recognised by looking FORWARD from the read rather than back along the line.
 */
function assignedName(src, index) {
  // `{ 'x-forwarded-for': ip }` — the read IS the key, so the name is ahead of
  // the `{`/`,` the read pattern anchors on rather than back along the line.
  const destructured = /^[{,]\s*(['"])(?:x-forwarded-for|x-real-ip)\1\s*:\s*([A-Za-z_$][\w$]*)/i.exec(
    src.slice(index, index + 64)
  );
  if (destructured) return destructured[2];

  const start = src.lastIndexOf('\n', index - 1) + 1;
  const line = src.slice(start, index);
  const declarator = /(?:\b(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=(?![=>])/g;
  const decl = [...line.matchAll(declarator)].pop();
  if (decl) return decl[1];
  // `const [ip] = …` — an array pattern binds its first element to the value's
  // first element, which for a forwarded chain is the hop an attacker chooses.
  const array = [...line.matchAll(/\b(?:const|let|var)\s*\[\s*([A-Za-z_$][\w$]*)/g)].pop();
  if (array) return array[1];
  const assign = [...line.matchAll(/(?:^|[;({,])\s*([A-Za-z_$][\w$]*)\s*=(?![=>])/g)].pop();
  return assign ? assign[1] : null;
}

/**
 * Where in `range` is `name` *given* a client address the caller cannot forge —
 * as the value the assignment produces, rather than as the branch taken when a
 * header is absent? Returns the index of the socket source, or -1.
 *
 * Scans the range for writes to that single identifier — `name = rhs`, never
 * `==`, `===` or the `=>` of an arrow, and never a compound form: only
 * whitespace may sit between the name and the `=`, so `||=`, `??=` and `+=`
 * cannot match at all. The right-hand side stops at the statement end (`;` or
 * newline) so a later statement on the next line cannot lend its value to this
 * one. Both halves must be on the code channel: a log message that happens to
 * quote `ip = req.socket.remoteAddress` proves nothing.
 *
 * A socket address on the right-hand side counts only when it is what the
 * expression yields:
 *
 *   ip = req.socket.remoteAddress                    the override wins outright
 *   if (!fromGateway(req)) ip = req.socket…          a condition chose it
 *   ip = fromGateway(req) ? xff : req.socket…        a condition chose it
 *
 * and never when the address is merely what is left if the header is missing —
 * a FALLBACK, which looks almost identical and means the opposite:
 *
 *   ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress
 *   ip = req.headers['x-forwarded-for'] ?? req.socket.remoteAddress
 *   ip ||= req.connection.remoteAddress
 *
 * An attacker is never the absent-header case: they always send the header, so
 * in every fallback form the forgeable value still owns the bucket key and the
 * bug is fully present whatever the control flow. That is the one exclusion
 * this function makes, and it is a fact about the operator rather than a guess
 * about which write reaches the read.
 *
 * PRESENCE, NOT DIRECTION. Every earlier version of this function also asked
 * whether the write could reach the read — a dominance approximation drawn with
 * brace matching. It was wrong in both directions and both were one line wide:
 * a rescue hoisted above the read, dropped into a `catch`, into a sibling
 * `switch` case or into a zero-iteration `for` body muted a live bypass, while
 * a genuine rescue reached through a loop was not credited and correct code
 * drew a HIGH. Answering only "is a socket source written to this name here at
 * all" is a question brace matching CAN answer, and its answer no longer
 * silences anything: it selects MEDIUM instead of HIGH.
 *
 * Nested function bodies are searched too, for the same reason. A closure that
 * ASSIGNS the outer identity (`const pin = () => { ip = req.socket
 * .remoteAddress; }`) genuinely rescues it; a closure that DECLARES its own
 * `ip` does not, and telling the two apart needs the scope table this detector
 * does not have. Both now read as "socket code is in scope, I cannot prove what
 * it governs" — which is exactly true of both.
 *
 * Scoped to `range`, the enclosing FUNCTION body of the header read, because a
 * variable name means nothing outside the scope that declares it. Searching the
 * whole file would let one careful handler answer for every careless one that
 * happened to reuse the name.
 */
function socketWriteTo(src, mask, name, range) {
  const ident = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // The lookbehind keeps `ip` from matching inside `clientIp` or `x.ip`; the
  // lookahead keeps `==`, `===` and `=>` out — comparisons are not writes.
  const re = new RegExp(`(?<![\\w$.])${ident}\\s*=(?![=>])([^;\\n]*)`, 'g');
  re.lastIndex = range.start;
  let m;
  while ((m = re.exec(src)) && m.index < range.end) {
    if (!mask[m.index]) continue; // the assignment is text inside a literal
    const rhs = SOCKET_SOURCE.exec(m[1]);
    if (!rhs) continue;
    // The captured group runs to the end of the match, so this is where it
    // starts in `src` — the address must be read there, not quoted there.
    const rhsStart = m.index + m[0].length - m[1].length;
    const at = rhsStart + rhs.index;
    if (!mask[at]) continue;
    if (coalesceBefore(src, mask, rhsStart, at)) continue; // fallback, not choice
    return at;
  }
  return -1;
}

/** `name` as a whole word. `$` is the only identifier char the engine treats. */
const wordRe = (name) => new RegExp(`\\b${name.replace(/\$/g, '\\$&')}\\b`);

/** Does the range `r` begin inside `scope`? */
const startsIn = (r, scope) => r.start >= scope.start && r.start < scope.end;

/**
 * Does `name` appear as a limiter key somewhere in `scope`?
 *
 * Scoped for the same reason the socket-source search is: a variable name means
 * nothing outside the function that declares it, so a limiter keyed on `ip` in
 * one handler says nothing about an `ip` in the next one along.
 */
function keysLimiterIn(src, name, scope, calls, kgRanges) {
  const word = wordRe(name);
  return (
    calls.some((c) => startsIn(c, scope) && word.test(c.args)) ||
    kgRanges.some((r) => startsIn(r, scope) && word.test(src.slice(r.start, r.end)))
  );
}

/** Is the range `inner` wholly contained in `outer`? */
const contains = (outer, inner) => inner.start >= outer.start && inner.end <= outer.end;

/**
 * Does `scope` DECLARE a binding named `name`?
 *
 * Only the binding side of a declaration counts, which is what separates
 * `const getClientIp = () => req.socket.remoteAddress` — a local that shadows
 * the module helper — from `const clientIp = getClientIp(req)`, where the same
 * name appears as a callee and shadows nothing. So each `const`/`let`/`var`/
 * `function`/`class` is read only up to the `=` (or the `(` of a parameter
 * list) that ends its target, with `{}`/`[]` tracked so destructuring patterns
 * — `const { getClientIp } = require('./safe-net')` — are read whole.
 *
 * Nested function bodies are cut out for the same reason every other scoped
 * search cuts them: a declaration in there is a different scope's binding.
 */
function declaresBinding(src, mask, name, scope) {
  const word = wordRe(name);
  const nested = nestedFunctionBodies(src, mask, scope);
  const re = /\b(?:const|let|var|function|class)\b/g;
  re.lastIndex = scope.start;
  let m;
  while ((m = re.exec(src)) && m.index < scope.end) {
    if (!mask[m.index]) continue; // the keyword inside a string or a comment
    if (nested.some((r) => within(m.index, r))) continue;

    let depth = 0;
    let k = m.index + m[0].length;
    for (; k < scope.end; k++) {
      if (!mask[k]) continue;
      const ch = src[k];
      if (ch === '{' || ch === '[') { depth += 1; continue; }
      if (ch === '}' || ch === ']') { if (depth === 0) break; depth -= 1; continue; }
      if (depth > 0) continue;
      if (ch === '(' || ch === ';' || ch === '\n') break;
      if (ch === '=' && src[k + 1] !== '=') break;
    }
    if (word.test(src.slice(m.index, k))) return true;
  }
  return false;
}

/**
 * How many helper hops the return-value path follows before giving up, and the
 * only thing that bounds it: a visited set already stops recursion and mutual
 * recursion, and real code does not stack identity helpers deeper than this.
 */
const MAX_HELPER_HOPS = 3;

/**
 * Is `fnName` called somewhere its RESULT becomes a limiter identity?
 *
 * Three ways now. The call sits directly inside a limiter call's arguments or a
 * keyGenerator body (`rateLimit(`login:${getIp(req)}`, 5, 60_000)`); its result
 * is bound to a variable that keys a limiter in the calling function
 * (`const clientIp = getClientIp(headersList)` … `checkRateLimit(clientIp)`);
 * or the calling function hands that value on as ITS return value, and the
 * question repeats one layer out.
 *
 * That third way is fix (d): following exactly one hop meant
 * `forwardedChain()` → `identityFor()` → `checkRateLimit(key)` — a complete,
 * live bypass — went unreported, while collapsing the two helpers into one
 * fired. Splitting a resolver in two is ordinary refactoring, not evasion, and
 * the bug is exactly as real at depth two. The iteration is bounded by
 * MAX_HELPER_HOPS and by `seen`, which doubles as a memo: a name already
 * resolved to "no limiter" answers the same for every path that reaches it.
 *
 * Unlike the variable searches, this one runs over the whole file on purpose.
 * A function name is a MODULE-level binding — the helper exists precisely to be
 * called from elsewhere, and the caller is by definition in another function.
 * Scoping this to the helper's own body would only ever find recursion, which
 * is why calls inside `ownBody` are skipped rather than sought.
 *
 * File-wide is not name-blind, though: a call site whose own function DECLARES
 * that name is calling something else entirely. A module-level `getClientIp`
 * that feeds analytics must not be credited for the limiter keyed by a local
 * `const getClientIp = () => req.socket.remoteAddress` shadowing it inside one
 * handler — that is the cross-function twin of the collision step (B) is
 * already scoped against. The check is skipped when the helper's own body lies
 * inside the calling scope, because then the declaration found IS the helper.
 */
function callResultReachesLimiter(src, mask, fnName, ownBody, calls, kgRanges, seen, hops) {
  const re = new RegExp(`(?<![\\w$.])${fnName.replace(/\$/g, '\\$&')}\\s*\\(`, 'g');
  let m;
  while ((m = re.exec(src))) {
    if (!mask[m.index]) continue; // the name inside a string or a comment
    if (within(m.index, ownBody)) continue; // a recursive call is not a consumer

    const keyword = identifierEndingAt(src, mask, skipBackToCode(src, mask, m.index - 1));
    if (keyword && DECLARATION_KEYWORD.test(keyword.name)) continue; // the declaration

    const scope = enclosingFunctionBody(src, mask, m.index);
    if (!contains(scope, ownBody) && declaresBinding(src, mask, fnName, scope)) {
      continue; // a local binding of that name — this call is not our helper
    }

    if (calls.some((c) => within(m.index, c)) || kgRanges.some((r) => within(m.index, r))) {
      return true;
    }

    const bound = assignedName(src, m.index);
    if (bound && keysLimiterIn(src, bound, scope, calls, kgRanges)) return true;

    // The caller is itself a helper: follow its return value one layer further.
    if (escapesByReturn(src, mask, m.index, bound, scope, calls, kgRanges, seen, hops + 1)) {
      return true;
    }
  }
  return false;
}

/**
 * Does a `return` in `scope` hand the value produced at `index` — a header
 * read, or a helper call whose result is bound to `name` — back to the caller?
 *
 * A return carries the value when `index` sits inside the returned expression
 * outright, or when that expression mentions the variable it was bound to:
 * `return forwarded.split(',')[0].trim()` counts, and so does any other
 * expression built from `forwarded`. A read at module top level escapes
 * nowhere, so it answers no.
 */
function returnCarries(src, mask, index, name, scope) {
  if (scope.start === 0 && scope.end === src.length) return false; // module top level
  return [...returnExpressions(src, mask, scope)].some(
    (r) => within(index, r) || (name && wordRe(name).test(src.slice(r.start, r.end)))
  );
}

/**
 * Does the value produced at `index` leave `scope` as a RETURN VALUE that keys
 * a limiter in some caller? The reach question `returnCarries` answers the
 * first half of — this half finds the caller and asks it the same question.
 */
function escapesByReturn(src, mask, index, name, scope, calls, kgRanges, seen, hops) {
  if (hops > MAX_HELPER_HOPS) return false;
  if (!returnCarries(src, mask, index, name, scope)) return false;

  const fnName = functionNameOfBody(src, mask, scope.start);
  if (!fnName) return false; // an anonymous body has no name a caller could use
  if (seen.has(fnName)) return false; // already resolved, or a cycle
  seen.add(fnName);
  return callResultReachesLimiter(src, mask, fnName, scope, calls, kgRanges, seen, hops);
}

/**
 * Does this read escape its function as a RETURN VALUE that keys a limiter?
 *
 * The getClientIp shape, and the one this rule was blind to for as long as it
 * only looked within a single function:
 *
 *   function getClientIp(headersList) {
 *     const forwarded = headersList.get('x-forwarded-for');   ← reported here
 *     if (forwarded) return forwarded.split(',')[0].trim();
 *     return headersList.get('x-real-ip') || 'unknown';       ← and here
 *   }
 *   const clientIp = getClientIp(headersList);
 *   if (!checkRateLimit(clientIp)) return tooManyRequests();
 *
 * Nothing inside the helper mentions a limiter, so (A) and (B) both answer no,
 * and the helper is the single most common way real code resolves a client IP.
 *
 * A return carries the forgeable value when the read sits inside the returned
 * expression outright, or when that expression mentions the variable the read
 * was assigned to — `return forwarded.split(',')[0].trim()` counts, and so does
 * any other expression built from `forwarded`.
 *
 * The finding is still reported at the HEADER READ, inside the helper. That is
 * where the forgeable value enters the program and where the trusted-proxy
 * check belongs; the call site is only where the consequence shows up.
 */
function returnsIntoLimiter(src, mask, read, name, scope, calls, kgRanges) {
  return escapesByReturn(src, mask, read.index, name, scope, calls, kgRanges, new Set(), 1);
}

/**
 * Every position in the returned expression `r` where the function hands back a
 * client address the caller cannot forge: the socket source read there
 * outright, or a local variable that was itself *given* one inside `scope`.
 *
 * The second half is what makes the guard-clause spelling work. `return peer`
 * yields the peer address as surely as `return req.socket.remoteAddress` does
 * when `peer` is two lines above it — and naming the value first is the more
 * common way to write the check, not a different check.
 */
function* socketYields(src, mask, r, scope) {
  const address = new RegExp(SOCKET_SOURCE.source, 'g');
  const text = src.slice(r.start, r.end);
  let m;
  while ((m = address.exec(text))) {
    if (mask[r.start + m.index]) yield r.start + m.index;
  }
  const ident = /(?<![\w$.])[A-Za-z_$][\w$]*/g;
  while ((m = ident.exec(text))) {
    const at = r.start + m.index;
    if (!mask[at]) continue;
    if (socketWriteTo(src, mask, m[0], scope) !== -1) yield at;
  }
}

/**
 * Where does `scope` hand a client address the caller cannot forge back to its
 * caller — as what a return expression YIELDS, not as the `||`/`??` default
 * behind it? Returns the index of the first such position, or -1.
 *
 * This is the identity question for a read that lands in no variable at all:
 * such a read leaves by return, so what a caller can receive from this function
 * is what stands for its identity, and a socket source in any of the function's
 * own returns is socket-level code in that identity's scope.
 *
 * WHICH return is deliberately not asked. Three rounds were spent trying: is
 * the socket return an early guard that dominates the read, is its condition
 * about the connection, was the read's own branch the one a connection test
 * selected. Every version of that question was a one-line mute in some
 * spelling — `if (req.method === 'OPTIONS') return req.socket.remoteAddress`
 * over the whole helper, `if (req.socket.remoteAddress)` as a vacuous
 * discriminator — and the version strict enough to reject them turned a guard
 * lifted into `const trusted = EDGE_NODES.has(peer)` into a false HIGH. Asking
 * only whether such a return EXISTS is sound, and costs nothing now that the
 * answer downgrades rather than silences.
 *
 * Nested function bodies are cut out by `returnExpressions`: their returns hand
 * a value to a different caller entirely and say nothing about this identity.
 */
function returnedSocketSource(src, mask, scope) {
  if (scope.start === 0 && scope.end === src.length) return -1; // module top level
  for (const r of returnExpressions(src, mask, scope)) {
    for (const at of socketYields(src, mask, r, scope)) {
      if (!coalesceBefore(src, mask, r.start, at)) return at;
    }
  }
  return -1;
}

function lineNumberAt(src, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (src[i] === '\n') line += 1;
  return line;
}

/**
 * The impact text for a finding that stands for `reads` header reads, and — at
 * MEDIUM — for the socket source that made it a MEDIUM.
 *
 * One helper resolving its identity from two headers in a row is ONE bug with
 * one fix — a report that lists it twice reads as noise and doubles the count
 * a reader has to work through. The reads that are not reported still deserve
 * a mention, though: someone opening the file at the line we name has to know
 * the line below it needs the same treatment.
 *
 * The MEDIUM sentence says exactly what prodcheck does and does not know, and
 * points at the line that decides it. A reader who opens that line can settle
 * in seconds what no lexical pass can settle at all: whether the fallback runs
 * on the path an attacker takes.
 */
function impactFor(reads, socketAt) {
  let text = IMPACT;
  if (reads > 1) {
    text += ` There are ${reads} forgeable header reads in this function, all resolving the same identity — one fix covers them.`;
  }
  if (socketAt) {
    text +=
      ` A socket-level fallback is present at ${socketAt}, but prodcheck cannot prove it` +
      ' governs this read — if that fallback runs only on a path an attacker avoids (a CORS' +
      ' preflight, a catch block, a feature flag), the limit is still bypassable. Confirm' +
      ' manually.';
  }
  return text + REMEDIATION;
}

function sourceLineAt(src, index) {
  const start = src.lastIndexOf('\n', index - 1) + 1;
  let end = src.indexOf('\n', index);
  if (end === -1) end = src.length;
  return src.slice(start, end);
}

/**
 * The socket-level source in scope for the identity this read produces, as an
 * index into `src`, or -1 when there is none.
 *
 * -1 is the HIGH finding: nothing in the read's enclosing function could rescue
 * this identity under any control flow, so the forgeable header is what the
 * limiter buckets on. Anything else is the MEDIUM finding: socket-level code is
 * there, and which of the two the limiter actually sees is a dataflow question
 * this rule does not answer.
 *
 * Which question gets asked depends on how the read leaves. A read bound to a
 * NAME is that name — the identity has a handle, and only a write to that
 * handle can change it, so a `const peer = req.socket.remoteAddress` two lines
 * away that is never written to this name is a different identity and leaves
 * this one confidently unrescued. A read bound to NO name leaves by return, and
 * has no handle to key on: there the identity is whatever the function returns,
 * so any socket-yielding return of that function counts.
 */
function socketSourceFor(src, mask, read, name, scope) {
  return name ? socketWriteTo(src, mask, name, scope) : returnedSocketSource(src, mask, scope);
}

/**
 * Fold one read into the finding its FUNCTION earns, or start that finding.
 *
 * A function resolving its identity from two headers in a row is one bug with
 * one fix, so the reads are counted and reported once. Severity is the strongest
 * any of them earns: a single read with no socket source in scope makes the
 * whole finding HIGH, and the finding moves to that read, because that is the
 * line the confident claim is about.
 */
function foldRead(group, index, socketAt) {
  if (!group) return { index, reads: 1, socketAt };
  group.reads += 1;
  if (socketAt === -1 && group.socketAt !== -1) {
    group.index = index;
    group.socketAt = -1;
  }
  return group;
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

  // NOTE: nothing suppresses here. A trust-proxy gate used to sit on this line
  // and return early, and it was the last one-line mute in the rule — see the
  // module header. A file that configures proxy trust and then reads the
  // forwarded header by hand is not a file that fixed this; it is a file that
  // has the validation and does not use it. If it also resolves the address
  // from the socket, that socket source is what lands it at MEDIUM below, on
  // the same evidence every other file is judged by.

  const kgRanges = [...keyGeneratorRanges(stripped, mask)];
  // Receivers this file CONSTRUCTED as limiters, so `const guard = new
  // RateLimiterMemory(…)` is a limiter whatever `guard` is called.
  const calls = [...limiterCalls(stripped, mask, limiterVariables(stripped, mask))];
  // The read pattern for THIS file: literal header names, plus any accessor
  // keyed by a constant this file bound to one.
  const readPattern = headerReadPattern(headerNameConstants(stripped, mask));

  // The reads that survive every gate, in source order. They are grouped and
  // reported below rather than as they are found: a helper that resolves its
  // identity from two headers in a row is one bug with one fix.
  const reported = [];

  for (const read of headerReads(stripped, mask, readPattern)) {
    // The variable this read lands in, if any. It answers two questions: can
    // the read reach a limiter (B), and which identity is the confidence
    // decision (C) about — this name, or the function's return value.
    const name = assignedName(stripped, read.index);

    // The enclosing function of the read, and the scope of everything below.
    // Reachability and the socket-source search ask their questions inside the
    // same boundary, which is the symmetry that was missing: the socket search
    // was already per-function while (B) searched the whole file, so a rescued
    // identity could not launder its neighbour but a limiter two functions away
    // could still drag an unrelated read into a finding.
    const scope = enclosingFunctionBody(stripped, mask, read.index);

    // (A) The read itself sits where a limiter identity is produced.
    let reaches =
      kgRanges.some((r) => within(read.index, r)) || calls.some((c) => within(read.index, c));

    // (B) The read is assigned to a variable that also appears as a limiter key
    // — as a bare argument or inside a template like `rl_${ip}`. The match is
    // position-insensitive: a key mentioned above the read counts as much as
    // one below it, because a loop, a closure or a hoisted call can reach it
    // either way and ordering the two would only invite guesses about control
    // flow this rule does not model. What DOES bound the search is the
    // function: a variable name means nothing outside the scope that declares
    // it, and matching it file-wide meant one handler's `ip` answered for
    // every other handler's `ip` — a debug log in one function was reported
    // because an unrelated function down the file keyed a limiter on the same
    // name. Renaming that one variable made the finding disappear, which is
    // the signature of a false positive.
    if (!reaches && name) {
      reaches = keysLimiterIn(stripped, name, scope, calls, kgRanges);
    }

    // (B2) The read leaves its function as a RETURN VALUE, and the caller keys
    // a limiter with it — the getClientIp / getIp helper every codebase grows.
    if (!reaches) {
      reaches = returnsIntoLimiter(stripped, mask, read, name, scope, calls, kgRanges);
    }

    // Logging-only reads land here — not our bug. True of any read whose
    // function neither keys a limiter with it nor hands it to one that does,
    // however many limiters the rest of the file happens to contain.
    if (!reaches) continue;

    // (C) The confidence decision, and the only thing the old suppression's
    // machinery is still asked for. Is a socket-level source present in scope
    // for THIS identity? Absent, the finding is HIGH and nothing in the
    // function could have rescued it. Present, it is MEDIUM and names the line,
    // because whether that source governs this read is a dataflow question and
    // seven rounds proved a lexical pass cannot answer it in either direction
    // without handing someone a one-line mute or a one-refactor false alarm.
    reported.push({
      index: read.index,
      scope,
      socketAt: socketSourceFor(stripped, mask, read, name, scope),
    });
  }

  // One finding per FUNCTION, at its first forgeable read — the granularity the
  // cross-file phase has always used, and now the granularity of both. Per-LINE
  // was the same bug seen twice: `getClientIp` reading x-forwarded-for and then
  // x-real-ip produced two rows, two identical diffs and one actual fix, while
  // the same helper reached through an import produced one. A security report
  // is read by someone counting what they have to do.
  //
  // Reads at module top level have no function to group by — `scope` is the
  // whole file there, and collapsing every top-level read in a file into one
  // finding would be a different claim entirely — so those stay per-line.
  const groups = new Map();
  for (const r of reported) {
    const key =
      r.scope.start === 0 && r.scope.end === stripped.length
        ? `line:${lineNumberAt(content, r.index)}`
        : `fn:${r.scope.start}:${r.scope.end}`;
    groups.set(key, foldRead(groups.get(key), r.index, r.socketAt));
  }

  const seenLines = new Set(); // two functions on one line are still one line
  for (const group of groups.values()) {
    const line = lineNumberAt(content, group.index);
    if (seenLines.has(line)) continue;
    seenLines.add(line);

    const socketAt =
      group.socketAt === -1 ? null : `${relPath}:${lineNumberAt(content, group.socketAt)}`;

    findings.push({
      severity: socketAt ? 'medium' : 'high',
      rule,
      file: relPath,
      line,
      impact: impactFor(group.reads, socketAt),
      fix: {
        remove: [sourceLineAt(content, group.index).trim()],
        add: [...FIX_ADD],
      },
    });
  }

  return findings;
}

// ═══ cross-file analysis ════════════════════════════════════════════════════
//
// Phase 1 (`collect`) reads one file and writes down two kinds of fact; phase 2
// (`finalize`) joins them once every file has been read. Nothing below can see
// a file it was not handed, and nothing above changed: `check` still answers
// for the single file in front of it, and every finding it produces it produces
// exactly as before.

/**
 * A raw-text pre-gate. Cheaper than the real candidacy tests and applied
 * before them: a file with neither a forgeable header name nor rate-limit
 * vocabulary anywhere in it — comments included — can be neither half of a
 * cross-file finding, and most of a repository is that file.
 */
const CROSSFILE_HINT = /x-forwarded-for|x-real-ip|rate[-_ ]?limit|ratelimit|limiter|keyGenerator|slowDown/i;

/** A forgeable header name anywhere in the raw text — the helper-side gate. */
const HEADER_HINT = /x-forwarded-for|x-real-ip/i;

/** Words that read as `name(` and are not a call to anything a module exports. */
const NOT_A_CALLEE =
  /^(?:if|for|while|switch|catch|with|do|else|case|return|typeof|instanceof|void|delete|await|yield|new|function|class|import|export|require|super|this|throw|in|of)$/;

/** Stands in for "this name has no definition here" in the reach search. */
const NO_BODY = { start: -1, end: -1 };

/** POSIX-normalise `a/./b/../c` to `a/c`, with no filesystem involved. */
function normalizePosix(p) {
  const out = [];
  for (const seg of p.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      if (out.length && out[out.length - 1] !== '..') out.pop();
      else out.push('..');
      continue;
    }
    out.push(seg);
  }
  return out.join('/');
}

/** The directory part of a POSIX path, or '' when there is none. */
function dirOf(p) {
  const i = p.lastIndexOf('/');
  return i === -1 ? '' : p.slice(0, i);
}

/**
 * The keys a module path is known by: the path with its extension dropped, the
 * directory when the file is an `index`, and both with and without a leading
 * `src/`.
 *
 * That last pair is what makes the match survive the choice of scan root. The
 * same repository is scanned as `prodcheck ./src` and as `prodcheck .`, and the
 * relative paths differ by exactly that prefix while the import specifiers do
 * not move at all.
 */
function moduleKeys(relPath) {
  const base = relPath.replace(/\\/g, '/').replace(/\.(?:d\.)?[mc]?[jt]sx?$/i, '');
  const keys = new Set([base, base.replace(/\/index$/, '')]);
  for (const k of [...keys]) {
    keys.add(k.replace(/^src\//, ''));
    keys.add(`src/${k}`);
  }
  return keys;
}

/**
 * Path-alias prefixes. What `specifierKeys` does with a match is drop the FIRST
 * PATH SEGMENT, whatever it is, and that is correct exactly when the segment is
 * nothing but a marker:
 *
 *     '@/lib/ip'   -> 'lib/ip'      right
 *     '~/lib/ip'   -> 'lib/ip'      right
 *     '@@/lib/ip'  -> 'lib/ip'      right
 *     '$lib/ip'    -> 'ip'          WRONG — SvelteKit loads src/lib/ip
 *     '$app/ip'    -> 'ip'          WRONG — the same, one alias over
 *     '$lib/a/ip'  -> 'a/ip'        WRONG
 *     '#lib/ip'    -> nothing       the `#` alternative below is DEAD
 *     '#/lib/ip'   -> nothing       so is this one
 *
 * This comment used to say "the alias target is a project directory, so the
 * segments after it are a path from the project root", which describes the
 * first three and mis-describes everything under them. `$lib` and `$app` ARE
 * the directory, so dropping them costs a level: measured, a route importing
 * `getIp` from `$lib/ip` joins a helper at the project ROOT `ip.js` and does
 * not join `lib/ip.js`, which is the file SvelteKit would load.
 *
 * `#lib/x` — Node's subpath imports, which the old comment named as supported —
 * never reaches this pattern at all. `specifierKeys` strips a query or fragment
 * suffix first (`.replace(/[?#].*$/, '')`), and on a specifier that BEGINS with
 * `#` that deletes the whole string, so the `#` alternative here can never
 * match and the specifier resolves to no key. That is the quieter of the two
 * failures — it joins nowhere rather than joining the wrong module.
 *
 * The comment is corrected rather than the behaviour because neither fix is one
 * line: `$lib` means `src/lib` in SvelteKit and `#x` means whatever a package's
 * `imports` field says, so resolving either needs the project config file, and
 * reading project config is machinery this tool does not have. Anchoring the
 * suffix stripper would revive `#/lib/x`, which nobody writes, and still not
 * `#lib/x`, which is the spelling that exists. `@/` and `~/` are between them
 * the overwhelming majority of aliased imports in this ecosystem, which is why
 * the gap survived to be written down wrongly.
 */
const ALIAS_PREFIX = /^(?:@|~|#|\$lib|\$app|@@)\//;

/** Specifiers that name a directory inside the project, not a package. */
const ROOT_RELATIVE = /^(?:src|app|lib|server|shared|packages|apps)\//;

/**
 * The keys the import specifier `spec`, written in `importer`, could resolve
 * to. Empty for a bare specifier: `express` and `@upstash/ratelimit` live in
 * node_modules, which this tool never walks, so nothing in the scan can be it.
 */
function specifierKeys(spec, importer) {
  const s = String(spec).replace(/\\/g, '/').replace(/[?#].*$/, '');
  let base;
  if (s.startsWith('./') || s.startsWith('../')) base = normalizePosix(`${dirOf(importer)}/${s}`);
  else if (ALIAS_PREFIX.test(s)) base = s.slice(s.indexOf('/') + 1);
  else if (s.startsWith('/')) base = s.slice(1);
  else if (ROOT_RELATIVE.test(s)) base = s;
  else return new Set();
  return moduleKeys(base);
}

/** Does `spec`, written in `importer`, name the module `target`? */
function resolvesTo(spec, importer, target) {
  const wanted = moduleKeys(target);
  for (const key of specifierKeys(spec, importer)) if (wanted.has(key)) return true;
  return false;
}

/**
 * Directory names that open a package in a monorepo. The package a file
 * belongs to is the directory just inside the LAST of these on its path, and
 * the scan root itself when there is none.
 *
 * This bounds the one join that is not backed by an import: a bare call in
 * `apps/web` must not be credited to a helper in `packages/auth`, because
 * nothing there is in scope without an import to bring it in.
 */
const PACKAGE_BOUNDARY = /^(?:packages|apps|services|libs|plugins|modules|workspaces)$/;

function packageOf(relPath) {
  const parts = relPath.split('/');
  for (let i = parts.length - 2; i >= 1; i--) {
    if (PACKAGE_BOUNDARY.test(parts[i - 1])) return parts.slice(0, i + 1).join('/');
  }
  return '';
}

/** Split `{ a, b as c, d: e }` into {imported, local} pairs. */
function* namedBindings(list) {
  for (const part of list.split(',')) {
    const m = part
      .trim()
      .match(/^(?:type\s+)?([A-Za-z_$][\w$]*)(?:\s*(?::|\bas\b)\s*([A-Za-z_$][\w$]*))?$/);
    if (m) yield { imported: m[1], local: m[2] ?? m[1] };
  }
}

/**
 * Yield {local, imported, spec} for every name this file binds from another
 * module: ESM `import`, and `require` in BOTH its spellings — the destructured
 * `const { getIp } = require('./ip')` and the whole-module
 * `const ip = require('./ip')`.
 *
 * `local` is the name a call site spells, `imported` the name the other module
 * exports. Aliasing (`import { getIp as clientIp }`) separates the two, and
 * that is what lets `finalize` check a call is reaching the helper it means to
 * credit rather than merely the right file.
 *
 * — EXCEPT for the whole-module form, and this is the part the comment here
 * used to get wrong. `const ip = require('./m')` and `import ip from './m'`
 * both yield `imported: 'default'`, and `credits` treats `'default'` as a
 * WILDCARD: any helper the target module exports satisfies it. Measured:
 *
 *     lib/ip.js       exports resolveClientIp (reads x-forwarded-for)
 *                     and tenantOf (reads req.auth.tenantId)
 *     routes/login.js const tenantOf = require('../lib/ip');
 *                     await apiLimiter.consume(tenantOf(req));
 *
 * — a limiter keyed on the tenant, which no header can move, reported HIGH
 * against `resolveClientIp` because the binding names the module and the module
 * exports something dangerous. Rename the import to a module that does not, and
 * the finding correctly disappears. So on the whole-module form the join is
 * honest about the MODULE and nothing finer; only the destructured and named
 * forms carry a name to check.
 *
 * The CJS branches were both dead until recently, and for a reason worth
 * keeping: `collectCallSites` dropped every name `declaresBinding` matched, and
 * both `const { getIp } = require('./ip')` and `const ip = require('./ip')`
 * match it — a declaration target read whole, which is right for the local that
 * SHADOWS an import and wrong for the import itself. `collectCallSites` now
 * takes the names yielded here and exempts them. Removing that exemption takes
 * every `require`-bound cross-file finding to zero while every `import`-bound
 * one survives, which is the measurement that says this is load-bearing.
 */
function* importBindings(src, mask) {
  const esm = /\bimport\s+([^;]*?)\s+from\s*(['"`])([^'"`]+)\2/g;
  let m;
  while ((m = esm.exec(src))) {
    if (!mask[m.index]) continue; // the word `import` inside a string
    const clause = m[1];
    const spec = m[3];
    const braced = clause.match(/\{([^}]*)\}/);
    if (braced) for (const b of namedBindings(braced[1])) yield { ...b, spec };
    // `import getIp from './ip'` and `import getIp, { rateLimit } from './ip'`
    const head = clause.replace(/\{[^}]*\}/, '').split(',')[0].trim();
    const dflt = head.match(/^(?:type\s+)?([A-Za-z_$][\w$]*)$/);
    if (dflt) yield { imported: 'default', local: dflt[1], spec };
  }

  const cjs =
    /\b(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*(['"`])([^'"`]+)\2\s*\)/g;
  while ((m = cjs.exec(src))) {
    if (!mask[m.index]) continue;
    const target = m[1];
    const spec = m[3];
    if (target.startsWith('{')) {
      for (const b of namedBindings(target.slice(1, -1))) yield { ...b, spec };
    } else {
      yield { imported: 'default', local: target, spec };
    }
  }
}

/**
 * The names this file exports, in every spelling the two module systems use.
 *
 * Only an exported helper can be called from another file, so this is the gate
 * on the helper side — and on the consuming side it answers the ambiguity
 * question the bare-name join has to ask: a name two modules both export names
 * nothing in particular.
 *
 * `mask` may be null, meaning "read the raw text and treat all of it as code".
 * That is how the export names of files with no rate-limit vocabulary at all
 * are read: those files can be neither half of a finding, so they never earn a
 * comment-accurate pass, but the module next door exporting a second `getIp`
 * is exactly the thing that must make a bare-name join back off — and it need
 * not mention rate limiting to exist. Over-counting a name quoted in a comment
 * only makes that guard stricter, which is the safe direction to be wrong in.
 */
function exportedNames(src, mask) {
  const names = new Set();
  const isCode = (i) => !mask || mask[i];
  let m;

  const decl =
    /\bexport\s+(?:default\s+)?(?:declare\s+)?(?:async\s+)?(?:function\s*\*?\s*|class\s+)([A-Za-z_$][\w$]*)/g;
  while ((m = decl.exec(src))) if (isCode(m.index)) names.add(m[1]);

  // `export const getIp = …`, including declaration lists. A declarator is a
  // name followed by `=` or a type annotation; anything else on the line is
  // part of an initialiser, not a second binding.
  const vars = /\bexport\s+(?:declare\s+)?(?:const|let|var)\s+([^;\n]*)/g;
  while ((m = vars.exec(src))) {
    if (!isCode(m.index)) continue;
    for (const part of m[1].split(',')) {
      const id = part.trim().match(/^([A-Za-z_$][\w$]*)\s*(?:[:=]|$)/);
      if (id) names.add(id[1]);
    }
  }

  // `export { getIp }` / `export { getIp as clientIp }`: both names count, the
  // local one for the definition side and the alias for the importing side.
  const list = /\bexport\s*\{([^}]*)\}/g;
  while ((m = list.exec(src))) {
    if (!isCode(m.index)) continue;
    for (const b of namedBindings(m[1])) {
      names.add(b.imported);
      names.add(b.local);
    }
  }

  const cjsProp = /\b(?:module\s*\.\s*)?exports\s*\.\s*([A-Za-z_$][\w$]*)\s*=/g;
  while ((m = cjsProp.exec(src))) if (isCode(m.index)) names.add(m[1]);

  const cjsObject = /\bmodule\s*\.\s*exports\s*=\s*\{([^}]*)\}/g;
  while ((m = cjsObject.exec(src))) {
    if (!isCode(m.index)) continue;
    for (const b of namedBindings(m[1])) names.add(b.local);
  }

  // `module.exports = getIp` and `export default getIp` — a bare identifier
  // assigned as the WHOLE export, which is how a single-function module is
  // spelled in both ecosystems and was the one export spelling nothing above
  // recognises. A module whose only export it is exported NOTHING as far as
  // this function was concerned, so `collectHelpers` recorded no helper for it
  // and every route importing it joined to nothing: the CommonJS half of the
  // cross-file question was silent on exactly the shape CommonJS uses most.
  //
  // The lookahead is what keeps this from swallowing the forms already handled
  // above and the ones that are not exports at all: `export default function f`
  // and `export default class C` are `decl`'s, `module.exports = { … }` is
  // `cjsObject`'s, and `module.exports = require('./x')` is a re-export this
  // tool does not follow — all three continue past the identifier with
  // something other than a statement end.
  const bareWhole =
    /(?:\bmodule\s*\.\s*exports\s*=|\bexport\s+default\b)\s*([A-Za-z_$][\w$]*)\s*(?=[;\n]|$)/g;
  while ((m = bareWhole.exec(src))) if (isCode(m.index)) names.add(m[1]);

  return names;
}

/**
 * The exported functions in this file that hand a forgeable header back to
 * their caller, as {name, line, source} — one per function, at its FIRST
 * unrescued read.
 *
 * Every gate here is one `check` already applies to the same read, asked in the
 * same order: the read must escape by return (the reach path a caller in
 * another file completes), and its identity is then asked the same confidence
 * question — is a socket-level source present in the helper's own body? A
 * helper with one is still recorded, at MEDIUM, carrying the line it saw: the
 * cross-file phase never re-reads the helper's body, so the answer has to
 * travel with the fact. Recording nothing was the cross-file spelling of the
 * same mute the single-file path just gave up: one
 * `if (req.method === 'OPTIONS') return req.socket.remoteAddress` inside an
 * exported helper silenced every route that keyed a limiter with it.
 */
function collectHelpers(content, stripped, mask, exported) {
  const helpers = new Map();
  const readPattern = headerReadPattern(headerNameConstants(stripped, mask));

  for (const read of headerReads(stripped, mask, readPattern)) {
    const scope = enclosingFunctionBody(stripped, mask, read.index);
    const fnName = functionNameOfBody(stripped, mask, scope.start);
    if (!fnName || !exported.has(fnName)) continue;

    const name = assignedName(stripped, read.index);
    if (!returnCarries(stripped, mask, read.index, name, scope)) continue;

    const socketAt = socketSourceFor(stripped, mask, read, name, scope);
    const group = foldRead(helpers.get(fnName), read.index, socketAt);
    group.line = lineNumberAt(content, group.index);
    group.source = sourceLineAt(content, group.index).trim();
    group.name = fnName;
    group.socketLine = group.socketAt === -1 ? 0 : lineNumberAt(content, group.socketAt);
    helpers.set(fnName, group);
  }
  // `index`/`socketAt` are offsets into one file's text and mean nothing to
  // `finalize`; only the line numbers cross the phase boundary.
  return [...helpers.values()].map(({ name, line, source, reads, socketLine }) => ({
    name,
    line,
    source,
    reads,
    socketLine,
  }));
}

/**
 * The names this file CALLS in a limiter-reaching position and does not define
 * itself — the other half of the seam.
 *
 * "Limiter-reaching" is the existing question, unchanged: the call sits in a
 * limiter call's arguments or a keyGenerator body, its result is bound to a
 * variable that keys a limiter in the same function, or the calling function
 * returns it on to something that does.
 *
 * What remains is "does this file define the name itself". `declaresBinding`
 * answers that by reading every `const`/`let`/`var`/`function`/`class` target
 * whole, destructuring patterns included — which is right for a local that
 * shadows an imported helper, and wrong for `const { getIp } = require('./ip')`,
 * where the pattern IS the import. That made the CJS half of `importBindings`
 * unreachable: every destructured `require` binding was read as a local
 * definition and dropped before it could ever be joined. So the names this file
 * binds from another module are handed in and exempted — a name that comes from
 * a module is not defined here, whichever module system spells it.
 */
function collectCallSites(stripped, mask, calls, kgRanges, imported) {
  const reaching = [];
  const tried = new Set();
  const fileScope = { start: 0, end: stripped.length };

  const bare = /\b([A-Za-z_$][\w$]*)\s*\(/g;
  let m;
  while ((m = bare.exec(stripped))) {
    if (!mask[m.index]) continue; // a name inside a string or a comment
    const name = m[1];
    if (tried.has(name) || NOT_A_CALLEE.test(name)) continue;

    const before = skipBackToCode(stripped, mask, m.index - 1);
    if (before >= 0 && stripped[before] === '.') continue; // `x.getIp(…)`, another object
    tried.add(name);

    if (!imported.has(name) && declaresBinding(stripped, mask, name, fileScope)) {
      continue; // defined here, not imported from anywhere
    }
    if (callResultReachesLimiter(stripped, mask, name, NO_BODY, calls, kgRanges, new Set(), 1)) {
      reaching.push(name);
    }
  }
  return reaching;
}

/**
 * Phase 1 of the two-phase contract: the facts this file contributes to a
 * cross-file question, or null when it contributes none.
 *
 * Serialisable by construction — names, line numbers and strings — because the
 * CLI holds one of these per file until the walk ends, and a future runner may
 * well produce them somewhere other than the process that consumes them.
 *
 * @param {object} file {path, content}
 * @returns {object|null} {helpers, exports, imports, calls}
 */
export function collect(file) {
  const content = file.content ?? '';

  // A file with neither a forgeable header name nor rate-limit vocabulary is
  // neither half of a finding — but it is still a module, and the names it
  // exports are what tell a bare-name join that it has more than one candidate
  // to choose from. That question is worth a handful of regexes on raw text;
  // the rest of the analysis is not worth running at all.
  if (!CROSSFILE_HINT.test(content)) {
    const names = exportedNames(content, null);
    return names.size ? { helpers: [], exports: [...names], imports: [], calls: [] } : null;
  }

  const stripped = stripComments(content);
  const mask = codeMask(content);
  const exported = exportedNames(stripped, mask);
  const bindings = [...importBindings(stripped, mask)];

  // The helper side. A trust-proxy gate used to wrap this half too, on the
  // theory that a file which configured proxy trust had handled the problem and
  // its exported helper should not be reported from another file. It was the
  // same grep hit as the one `check` used, with the same one-line mute in it —
  // and it hid MORE, because a helper is reported once for every route that
  // consumes it. An exported helper that hands its caller a raw forwarded
  // header is a bypass in each of those routes no matter what its own module
  // configures; only the code that reads the header can decide that, and it
  // decides it by reading `req.ip` instead.
  let helpers = [];
  if (HEADER_HINT.test(content)) {
    helpers = collectHelpers(content, stripped, mask, exported);
  }

  // The consuming side. A file with no rate-limit vocabulary has no limiter for
  // a call to reach, so the same candidacy gate `check` uses bounds this too.
  let calls = [];
  if (CONTENT_HINT.test(stripped)) {
    const kgRanges = [...keyGeneratorRanges(stripped, mask)];
    const limiters = [...limiterCalls(stripped, mask, limiterVariables(stripped, mask))];
    if (kgRanges.length || limiters.length) {
      const imported = new Set(bindings.map((b) => b.local));
      calls = collectCallSites(stripped, mask, limiters, kgRanges, imported);
    }
  }

  if (!helpers.length && !calls.length && !exported.size) return null;

  // Only the bindings a recorded call could be using are worth keeping.
  const imports = calls.length ? bindings.filter((b) => calls.includes(b.local)) : [];

  return { helpers, exports: [...exported], imports, calls };
}

/**
 * Is the call to `name` in `consumer` a call to `helper`?
 *
 * The strong answer is an import: the file binds that name from a specifier
 * that resolves to the helper's module, and the module it names is the module
 * the helper is in. Aliases are followed, so `import { getIp as clientIp }`
 * credits `clientIp(req)` to `getIp` and to nothing else.
 *
 * The weak answer is the same package with nothing to contradict it: the file
 * binds that name from no module at all (`collect` already established it
 * defines none either), the helper is in the same package, and no second module
 * in the scan exports the name. Two modules exporting `getIp` make a bare call
 * ambiguous, and an ambiguous join is the repository-scale version of the name
 * collisions this rule spent its precision rounds eliminating.
 */
function credits(consumer, name, helper, exporters) {
  const binding = consumer.imports.find((b) => b.local === name);
  if (binding) {
    if (binding.imported !== helper.name && binding.imported !== 'default') return false;
    return resolvesTo(binding.spec, consumer.file, helper.file);
  }
  if (name !== helper.name) return false;
  if (packageOf(consumer.file) !== packageOf(helper.file)) return false;
  return (exporters.get(name)?.size ?? 0) === 1;
}

/**
 * Phase 2 of the two-phase contract: the findings that only exist between
 * files.
 *
 * One finding per helper, at the helper's own header read. Eleven routes
 * keying a limiter with `getIp(req)` are eleven symptoms of one bug, and the
 * one line that has to change is the read inside the helper — reporting the
 * call sites instead would hand someone eleven identical diffs, none of which
 * fixes anything.
 *
 * @param {Map<string, object>} factsByFile every file's `collect` result
 * @returns {Array} findings, in the shape the renderers consume
 */
export function finalize(factsByFile) {
  const helpers = [];
  const consumers = [];
  const exporters = new Map(); // exported name -> the files exporting it

  for (const [file, facts] of factsByFile) {
    if (!facts) continue;
    for (const h of facts.helpers ?? []) helpers.push({ ...h, file });
    if (facts.calls?.length) consumers.push({ file, calls: facts.calls, imports: facts.imports ?? [] });
    for (const name of facts.exports ?? []) {
      if (!exporters.has(name)) exporters.set(name, new Set());
      exporters.get(name).add(file);
    }
  }
  if (!helpers.length || !consumers.length) return [];

  const findings = [];
  for (const helper of helpers) {
    const reached = consumers.some(
      (c) =>
        c.file !== helper.file && // the same file is `check`'s question, not ours
        c.calls.some((name) => credits(c, name, helper, exporters))
    );
    if (!reached) continue;

    // The confidence decision travelled here from phase 1 as a line number:
    // `collect` looked inside the helper's body, `finalize` no longer has it.
    const socketAt = helper.socketLine ? `${helper.file}:${helper.socketLine}` : null;

    findings.push({
      severity: socketAt ? 'medium' : 'high',
      rule,
      file: helper.file,
      line: helper.line,
      impact: impactFor(helper.reads ?? 1, socketAt),
      fix: { remove: [helper.source], add: [...FIX_ADD] },
    });
  }
  return findings;
}
