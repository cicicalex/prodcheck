# prodcheck design notes

[README](https://github.com/cicicalex/prodcheck/blob/main/README.md) · Rules:
[webhook-swallows-2xx](https://github.com/cicicalex/prodcheck/blob/main/docs/rules/webhook-swallows-2xx.md) ·
[rate-limit-bypass](https://github.com/cicicalex/prodcheck/blob/main/docs/rules/rate-limit-bypass.md) ·
[env-secret-fallback](https://github.com/cicicalex/prodcheck/blob/main/docs/rules/env-secret-fallback.md)

This document holds the reasoning behind prodcheck's rules and the lexer they
share: why the checks exist, how severity is decided, what the scanner can and
cannot see, and the adversarial testing that shaped it. The README is the
quick-start; this is the reference.

## Why these checks

Every rule here came from a bug found in real production code, then fixed. Not
from a blog post and not from a CVE feed. That is the whole selection criterion:
if it has not actually broken something, it is not a rule.

### Shipping today

Three rules run on every scan. All are free and open source
(MIT), and all are in [`src/checks/index.mjs`](https://github.com/cicicalex/prodcheck/blob/main/src/checks/index.mjs) — that
array is the only list that decides what actually runs.

| Check | What it catches |
| --- | --- |
| `webhook-swallows-2xx` | `catch` in a webhook handler returning 2xx without re-throwing |
| `rate-limit-bypass` | a rate limiter keyed on `X-Forwarded-For` read by hand instead of the address the framework resolved |
| `env-secret-fallback` | a credential read from the environment with a silent fallback to a literal, in a file that calls out to the internet |

### Designed, not yet implemented

These four are the rest of the seven-rule design. **None of them ships in any
form today** — there is no code for them in this repository, free or paid, and
`prodcheck` will not report them however you invoke it. They are listed because
the report's `→ 4 more checks` row refers to exactly this table, and because
each one came from the same place the three above did: a bug that shipped.

| Check | What it will catch |
| --- | --- |
| `2fa-skips-api` | 2FA guard on the UI layout or middleware, absent on `/api` routes |
| `account-delete-blocked` | foreign keys to `user` with `NO ACTION`/`RESTRICT` that make erasure fail |
| `migrations-not-replayable` | migration chain that does not run against an empty database |
| `backup-unencrypted` | plaintext dumps, `pg_dumpall` carrying role hashes |

The design is seven, so shipping `env-secret-fallback` cost this table an entry:
`quota-per-key` (usage metered on `api_key_id` rather than `user_id`) came out
when the new rule went in. That is a decision, not an oversight, and it is
recorded in [`src/checks/index.mjs`](https://github.com/cicicalex/prodcheck/blob/main/src/checks/index.mjs) beside the
subtraction that keeps the two counts honest — `LOCKED_PAID_CHECKS` is
`7 - checks.length`, never a number typed in twice.

## What gets scanned

A scanner's blind spots start with the files it never opens, so here is the
whole of the walk. None of it is configurable today, and `--help` does not
print any of it — this section is the reference.

**Extensions.** A file is read only if its extension is one of:

```
.js  .mjs  .cjs  .ts  .mts  .cts  .jsx  .tsx
```

Anything else is skipped, including `.es6`, `.vue`, `.svelte`, `.astro` and
`.json`. `.cts` used to be missing while `.mts` was present, which meant
renaming `route.mts` to `route.cts` dropped the file from the scan with the bug
untouched; it is in the list now, and the list is the union of every registered
check's `extensions` set.

**Size cap.** `MAX_FILE_BYTES` is 1 MiB. A file larger than that is skipped
whole — the cap exists because generated bundles are noise, and it applies to
handwritten source just the same. Padding a route past 1 MiB removes it from the
scan, and padding a shared *helper* past it removes the helper's half of every
cross-file finding, so each route importing it goes quiet too.

**Skipped directories.** These are never descended into, at any depth:

```
node_modules  .git  dist  build  .next  coverage
```

**Symlinks** are not followed — neither files nor directories — because
following them invites cycles and pulls in code outside the scan root.

**Every one of these is visible, not silent.** A file dropped by its extension,
its size or its directory is not reported on — it stops being *counted*, and
the count is printed on every run: `3 files · 0.1s` on the summary row, and
`scan.filesScanned` in `--json`. If that number is lower than you expect,
something was skipped. Nothing in this section can make a *scanned* file come
back clean.

A path with no scannable files at all reports clean and exits `0` — there is
nothing to find — but prints a warning to stderr so the empty scan is not
mistaken for a passing one:

```
prodcheck: warning: no .js/.ts files found under <path>
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | clean, or only findings below the threshold |
| `1` | findings at or above `--fail-on` (default `high`) |
| `2` | the scan itself failed — bad path, parse error, crash |

`1` and `2` are deliberately distinct. A CI job needs to tell "found problems"
apart from "the tool broke", and conflating them is how a scanner silently stops
scanning.

## The MEDIUM tier

**HIGH means prodcheck is confident. MEDIUM means it found something it cannot
resolve on its own, and is telling you rather than guessing.**

`rate-limit-bypass` is a lexical pass — no AST, no control-flow graph, because
zero runtime dependencies is a hard rule here. It can see that a forgeable
header keys a limiter, and it can see whether any socket-level source
(`req.socket.remoteAddress`, `req.ip`) exists in scope for that identity. What
it cannot see is which of the two the limiter actually receives at runtime. So:

- **HIGH** — the identity reaches a limiter and there is *no* socket-level
  source for it in the enclosing function (cross-file: in the helper). Nothing
  could have rescued it, whatever the control flow turns out to be.
- **MEDIUM** — a socket-level source *is* there, and it might be a real
  defence or it might be a `catch` block, a CORS preflight branch or a
  feature-flagged path an attacker never travels. The finding names the line so
  you can settle it in about ten seconds.

"For it" is per-identity, not per-function: a read bound to a name is asked
whether *that name* is ever given a socket address; a read that leaves by
`return` with no name is asked whether the function returns one. So a helper
that resolves `x-real-ip` into a variable nothing rescues stays HIGH even when a
separate `peer` two lines below it is handled correctly — those are two
identities, and only one of them is a bypass.

Every MEDIUM carries that sentence and the file:line of the socket source it
saw. **`--fail-on high` is the default, and it does not fail a build on a
MEDIUM.** Run `--fail-on medium` when you want to review every one of them.

`env-secret-fallback` uses the same contract, for the same reason. HIGH is a
credential defaulted to a literal in a file that also calls out to the network,
and the finding names the outbound line. MEDIUM is the identical default with no
outbound call visible in that file — still a default credential compiled into the
source, and inherited by everything importing it, but prodcheck cannot show where
it is spent and does not pretend to. Its third outcome is silence, and the
fallback's own value decides it: `''`, `'undefined'`, `'CHANGEME'` and
`'REPLACE_ME'` fail loudly the first time they are used, which is the behaviour
the rule asks for rather than the bug it looks for.

This replaced a suppression that tried to decide the question and stayed silent
when it thought a rescue was present. Seven rounds of adversarial testing showed
that decision could be flipped either way by one line — a `catch`, a preflight
short-circuit, a socket default moved above the read — which meant a live bypass
could be muted by an edit that fixed nothing. **No edit that argues about
control flow can hide a finding any more; it can only downgrade one.**

That is deliberately narrower than what this paragraph used to claim ("it can no
longer be hidden"), because the two rounds after it found silence that had
nothing to do with control flow. Both were in the shared lexer underneath every
rule — the pass that decides which characters are code and which are data — and
both took *all four* of the real production bugs to a clean report from a single
inserted line of valid, inert JavaScript:

```js
const RE = /`/;             // found in round 10: regex literals were not
                            // modelled at all, so the body read as code and its
                            // backtick opened a template frame that never
                            // closed. Everything below it went dark.
if (1) /`/.test(x);         // found in round 11: the same failure one position
                            // over. Modelling regex literals did not help here,
                            // because this is a position where the lexer
                            // REFUSES a regex and reads `/` as division — which
                            // leaves the backtick loose exactly as before.

// found in round 12: no second frame is opened at all. The quote inside the
// refused regex flips STRING PARITY for the rest of the line, so the
// req.headers['…'] beside it lands on the data channel and nothing can match it.
if (1) /'/.test('x'); const ip = req.headers['x-forwarded-for'];
```

Those are closed structurally rather than by listing spellings. The shared lexer
now carries an invariant in two clauses — **no scan may end holding an open
frame**, and **no character may be classified not-code because of a disputed `/`
reading** — so a lexer that loses its place fails *open* (reports too much)
instead of *blind* (reports nothing).

The second clause used to be conditional: a frame a disputed `/` let loose was
repaired only if it outlived that `/`'s line *and* cost more than re-reading the
span as a regex would. Both qualifications were holes. A frame that opened and
closed on the same line was invisible to the first (and on a minified bundle,
"that line" is the whole file); declining on cost left the darkness standing with
nothing to replace it; and quote parity opens no frame to test in the first
place. The clause is now unconditional — when the reading is in doubt, the
affected span is code, no line test, no cost test — which is a post-condition
with no condition left to evade.

A 40,560-run mutation harness across nine corpora and 169 one-line mutations
finds zero total silences, against 1,310 before the invariant existed and 32
before this clause became unconditional. The honest claim is that number and
that mechanism, not an absolute; see [The shared lexer](#the-shared-lexer) for
what the invariant costs.

## Configured proxy trust does not silence this rule

This section concerns `rate-limit-bypass`.

**A hand-rolled read of `X-Forwarded-For` is reported even when the file
configures proxy trust.** If you have `app.set('trust proxy', …)` above a
finding, that is not a false positive — it is the finding pointing at the
contradiction.

Setting `trust proxy` tells the framework how many hops it may believe. It then
walks the forwarded chain, discards the parts an attacker controls, and puts the
result in `req.ip`. Code that reads the raw header itself gets none of that: it
takes the whole client-supplied string, and the setting above it changes nothing
about the value the limiter buckets on. Configuring the validation and then not
using it is the bug with a reassuring line above it.

```js
app.set('trust proxy', 1);                                  // real, and ignored
const ip = req.headers['x-forwarded-for'].split(',')[0];    // ← reported, HIGH
const ip = req.ip;                                          // ← what to write
```

Earlier versions did go silent on any file mentioning proxy trust, and that was
the last one-line mute in the rule. The test was a case-insensitive substring —
no position, no value, no reachability. An adversarial sweep of ~10,500 runs
took **78 of 78** noisy files to total silence through it, including all four
real production bugs the rule was built from. Fourteen different one-line edits
did it, from anywhere in the file:

```js
if (false) { app.set('trust proxy', 1); }        // never runs
const trustProxy = false;                        // trust explicitly OFF
const TRUSTED_PROXIES = [];                      // an empty allowlist
let untrustedProxyHits = 0;                      // "untrusted prox" matched
type TrustProxy = never;                         // erased at build time
export const TRUSTED_PROXY_HEADER = 'x-forwarded-for';   // names the bug
```

The worst one was ours. The fix line this rule used to print —
`const ip = getClientIp(req, { trustProxy: TRUSTED_PROXIES })` — contained two
of the trigger tokens, so pasting prodcheck's own remediation and stubbing
`getClientIp` to return the header produced a clean report over an untouched
bypass. The printed fix is now `req.ip`, which needs no helper and cannot be
stubbed wrong.

There is no way to make a substring test mean "this configuration is reachable,
enabled, and applies to this read" — that is the same dataflow question wearing
the word "configuration". So the gate is gone. A file that genuinely resolves
its address from the socket still has socket-level code in scope, lands at
MEDIUM, and does not fail a build on the default threshold. Across the
repositories this rule is validated against, removing it changed no HIGH finding
and added two MEDIUMs, both on files that already carried a socket source.

## Which header reads it sees

This section and the next concern `rate-limit-bypass`.

Six spellings, in both ecosystems:

```js
req.headers['x-forwarded-for']                                  // Node / Express plain object
headersList.get('x-forwarded-for')                              // fetch-style Headers (Next.js, Hono, edge)
req.header('x-forwarded-for')                                   // Express accessor
req.get('x-forwarded-for')                                      // Express accessor, alias
const [ip] = String(req.headers['x-forwarded-for']).split(',')  // array destructuring
const { 'x-forwarded-for': ip } = req.headers                   // object destructuring
```

`x-real-ip` is treated identically, and header names are case-insensitive.

The header name may also be held in a constant. When a file binds one of the
two forgeable names to a `const`/`let`/`var`, that name is admitted in the
argument position of the four accessor spellings above:

```js
const XFF = 'x-forwarded-for';
const ip = req.headers[XFF];          // ← seen, because the binding above was seen
```

The binding is the whole of the gate: a name is admitted only because *this
file* was seen assigning it a forgeable header string. A constant holding
`'user-agent'`, or one imported from another module, admits nothing.

The last two were added after they turned up as undocumented recall misses: the
read pattern used to require a receiver containing the token `headers`, and
`req` does not contain it, so the two most idiomatic Express spellings of this
bug were silent no matter what they fed. They carry no receiver constraint now —
what makes the read forgeable is the header *name*, not the object it is asked
of. Only single-argument calls match, which is what keeps the setter forms
(`res.header(name, value)`, `headers.set(name, value)`) out: those write a
header, and a write cannot key a limiter.

## Which limiter calls it sees

A limiter identity is consumed by a method call on a limiter
(`limiter.consume(ip)`, `.limit`, `.check`, `.increment`) or by a bare call
whose own name carries limiter vocabulary (`checkRateLimit(ip)`,
`rateLimit(key, max, windowMs)`).

The receiver may be reached through optional chaining or through parentheses —
`limiter?.consume(ip)` and `(limiter).consume(ip)` are the same call, and both
were silent until this round. A defensive `?.` added while tidying up is not a
fix, and it must not read as one.

**A limiter no longer has to be *named* like a limiter.** A variable this file
assigns from a limiter construction or a known factory is a limiter whatever it
is called:

```js
const guard = new RateLimiterMemory({ points: 5 });   // rate-limiter-flexible
const gate  = new Ratelimit({ redis, limiter: … });   // @upstash/ratelimit
const slow  = slowDown({ windowMs: 60_000 });         // express-slow-down
await guard.consume(ip);                              // ← a limiter call
```

Before this, `const limiter = new RateLimiterMemory(…)` was a HIGH and the
identical program with `const guard = …` was silent — so code written the
second way from the start was never checked at all. The name-based test remains
as a fallback for limiters that arrive from somewhere this file cannot see
(an import, a parameter, a factory of its own).

A predicate is not a limiter: `const allowed = checkRateLimit(ip)` binds a
boolean, so `allowed` is not admitted as a receiver.

## Colour

Colour is on for interactive terminals and off everywhere else. `NO_COLOR=1`
disables it, `FORCE_COLOR=1` forces it on — and `FORCE_COLOR` wins, matching
Node core and chalk.

Severity is never carried by colour alone: each level has its own ASCII glyph
(`!!`, `!`, `~`, `-`), so the report stays readable in CI logs, when piped to a
file, and for colourblind readers.

## The shared lexer

The detectors are lexical passes, not full parsers — a deliberate trade-off to
stay at zero dependencies. What that costs per rule is listed in each rule's
page under `docs/rules/`; here is what it costs in the character classification
all three read.

All three rules ask every question of one pass that labels each character CODE or
DATA (strings, template literals, regex literals, comments). It holds an
invariant in two clauses — no scan may end inside a frame, and no character may
be classified not-code because of a disputed `/` reading — so a file can no
longer go dark. What survives is the *direction* it is now allowed to be wrong
in:

**When the lexer cannot decide, it refuses to darken.** `/` divides or opens a
regex depending on what came before it, and after `)`, `]` or another `/` this
lexer reads division. Where a well-formed regex literal *also* reads there, the
`/` is DISPUTED — and if reading it as division opens any frame at all (a
string, a template, a comment), the whole affected span goes on the code
channel: the disputed span itself, everything the frame it let loose covers,
and — when that frame was a string, because a string closing mid-line inverts
quote parity for every quote after it — the rest of the line as well.

That repair has no direction it can be wrong in. It only ever moves characters
onto the code channel, so it adds matches and cannot remove them. Over-reporting
is a finding a human reads and dismisses; under-reporting is a bypass nobody
hears about.

**A repair for the other clause is applied at one character.** When a frame is
still open at EOF the lexer reinterprets exactly one position — the unclosed
opener is demoted to ordinary code, or the `/` that let it loose is re-read as
the regex literal it was — and every other literal in the file keeps the
classification it had. That one is a re-reading, so it *is* held arithmetically:
a repair that would put more text on the data channel than leaving the scan
alone is refused. Minified bundles are why: a bundle is one enormous line, and
plain division inside `tsx` had a closing `/` 39,000 characters later, so
promoting it would have taken 39,468 characters off the code channel.

Measured, across 517 files in four repositories: no scan needs a repair at all,
and the disputed-`/` clause moves 2,375 characters from the data channel to the
code channel in 31 of them, changing no finding — nothing added and nothing
removed, here or on the 105-file adversarial fixture corpus. The largest single
case is a dashboard layout at 826 characters — five
inline SVG icons, where two `<rect … />` on one line make the `/` of the first
`/>` a refused regex whose span reaches the second, with the attribute strings
of the second tag inside it. In 57,747 files under those repositories'
`node_modules`, where the minified bundles live, the same clause moves 6,301,805
characters in 598 files, the widest single run being 69,430 characters of a
Prisma runtime bundle. Nothing moves the other way in either scope, and this
tool never walks `node_modules`.

**Vocabulary inside a refused regex can match.** `if (x) /re/.test(y)` is legal
JavaScript, and there the pattern is read as division plus operands, so its
contents sit on the code channel. If the misread lets nothing loose, the cost is
that a header name or a trust word inside the pattern may produce one spurious
match on that line. A blinded file is no longer among the outcomes.

**A file that defeats the repair loop falls back to line-by-line lexing.** After
16 repair passes the lexer lexes each line from the neutral state, which cannot
leave a frame open past a newline but also cannot see a template literal or a
block comment that spans lines — their second line onward reads as code. No real
file measured has ever reached this path; it exists so the guarantee has a floor
rather than an exception.

**Only templates and block comments may span lines.** A string literal and a
regex literal stop at the newline, including when a backslash would legally
continue them (`const s = 'a\` at the end of a line). Real JavaScript carries
that string onto the next line; this lexer does not, because honouring it let a
single appended line swallow everything down to the next quote in the file. The
cost is that a multi-line continuation string reads as code from its second line
on — over-reporting again, and ESLint's `no-multi-str` has been telling people
not to write them for a decade. Over the whole scanned corpus — the 517 files
above plus their `node_modules` — exactly one file was affected: a selector
string in `eslint-plugin-react`, sitting directly under its own
`// eslint-disable-next-line no-multi-str`.

## Working from a checkout

The sample used in the README ships in this repository at
[`sample/`](https://github.com/cicicalex/prodcheck/blob/main/sample) — a Stripe route whose `catch` answers 200, a contact
route that keys an Upstash limiter on `x-forwarded-for`, and a clean
`lib/db.ts` — so `node src/cli.mjs sample` runs from a fresh clone with nothing
else installed. It is not in the published package: `package.json` lists
`files: ["src", "README.md"]`, so `npm pack` carries the tool and the README and
nothing else.

The two files under `sample/` are deliberately broken and are meant to be
found — so `node src/cli.mjs .` at the repository root reports them, along with
the fixtures under `tests/`. That is the tool working, not a self-scan failure.

Every flag works the same with `node src/cli.mjs` from a checkout as with the
installed `prodcheck` command. Run the test suite with `npm test`.
