# prodcheck

Finds the production bugs that ship green.

Your tests pass, your linter is clean, your types check — and the Stripe webhook
still swallows a failed payment because the `catch` block returns 200.
`prodcheck` looks for that specific class of bug: the ones that survive every
other tool in your pipeline.

```bash
# Not published yet — `npm view prodcheck` is a 404 today. This is what the
# install will be, and it does not work until the package ships:
npx prodcheck .

# What runs today, from a checkout of this repository:
node src/cli.mjs .              # scan the current directory
node src/cli.mjs ~/my-app       # or any other path
```

No config, no account, no telemetry. Reads your code, prints what is wrong and
the line that fixes it.

Below is the exact output of `node src/cli.mjs sample --no-color` over a
three-file sample — a Stripe route whose `catch` answers 200, a contact route
that keys an Upstash limiter on `x-forwarded-for`, and a clean `lib/db.ts`.
That sample ships in this repository at [`sample/`](sample), so the command
above runs from a fresh clone with nothing else installed. (It is not in the
published package: `package.json` lists `files: ["src", "README.md"]`, so
`npm pack` carries the tool and this document and nothing else.)

Copied verbatim, including the upsell row the report always appends:

```
  !! CRITICAL  webhook-swallows-2xx
     app/api/stripe/route.ts:13

     - return new Response('ok', { status: 200 });
     + } catch (e) { logger.error(e); throw e }

     The catch block returns a 2xx without re-throwing, so the webhook
     provider marks the event delivered and never retries. The failed event
     is silently lost — no retry, no alert, no trace in the provider
     dashboard.

  !  HIGH      rate-limit-bypass
     app/api/contact/route.ts:7

     - const ip = req.headers.get('x-forwarded-for') ?? 'anonymous';
     + app.set('trust proxy', <hops you control>)  // once, at app setup
     + const ip = req.ip  // the address the framework resolved, not the raw header

     The rate-limit identity comes from a header any client can set freely.
     An attacker rotates the value to get a fresh bucket on every request —
     the limit simply does not exist for them — or pins a victim's IP to
     exhaust that victim's bucket. Without trusted-proxy validation the
     header proves nothing about who is calling. Resolve the address through
     the framework instead of parsing the header: under Express, set `trust
     proxy` to the number of proxies you actually control and read `req.ip`,
     which is then derived from validated hops only. On Next.js, Vercel,
     Cloudflare or another edge runtime there is no `req.ip` to read — use
     the platform's own verified client-IP value, since only the platform
     knows which hop it terminated. Note that configuring proxy trust does
     not by itself make this line safe: reading the forwarded header by hand
     walks straight past the validation that setting performs, which is why
     prodcheck reports this read even in a file where trust is configured.

  --------------------------------------------------------------------------
  2 issues · 1 critical · 3 files · 0.1s

  → 5 more checks in prodcheck pro
```

The prose is long because it is the finding's own `impact` field, not a
tagline. An earlier version of this README showed a shorter, friendlier block
in this spot; prodcheck never emitted it, and it also omitted the upsell row.
Earlier still, the command itself was wrong: no `sample/` directory shipped, so
the one line this page tells you to run first exited 2 with `cannot read path:
sample`. Only the elapsed time on the summary row varies by machine.

The two files under `sample/` are deliberately broken and are meant to be
found — so `node src/cli.mjs .` at the repository root reports them, along with
the fixtures under `tests/`. That is the tool working, not a self-scan failure.

## Why these checks

Every rule here came from a bug found in real production code, then fixed. Not
from a blog post and not from a CVE feed. That is the whole selection criterion:
if it has not actually broken something, it is not a rule.

### Shipping today

Two rules run on every scan. Both are free and open source
(MIT), and both are in [`src/checks/index.mjs`](src/checks/index.mjs) — that
array is the only list that decides what actually runs.

| Check | What it catches |
| --- | --- |
| `webhook-swallows-2xx` | `catch` in a webhook handler returning 2xx without re-throwing |
| `rate-limit-bypass` | a rate limiter keyed on `X-Forwarded-For` read by hand instead of the address the framework resolved |

### Designed, not yet implemented

These five are the rest of the seven-rule design. **None of them ships in any
form today** — there is no code for them in this repository, free or paid, and
`prodcheck` will not report them however you invoke it. They are listed because
the report's `→ 5 more checks` row refers to exactly this table, and because
each one came from the same place the two above did: a bug that shipped.

| Check | What it will catch |
| --- | --- |
| `2fa-skips-api` | 2FA guard on the UI layout or middleware, absent on `/api` routes |
| `account-delete-blocked` | foreign keys to `user` with `NO ACTION`/`RESTRICT` that make erasure fail |
| `migrations-not-replayable` | migration chain that does not run against an empty database |
| `backup-unencrypted` | plaintext dumps, `pg_dumpall` carrying role hashes |
| `quota-per-key` | usage counted on `api_key_id` instead of `user_id` |

## Usage

Until the package is published, the entrypoint is `node src/cli.mjs` from a
checkout; every flag below is the same either way.

```bash
node src/cli.mjs sample                 # the three-file sample in this repository
node src/cli.mjs .                      # scan the current directory
node src/cli.mjs src/ --fail-on high    # fail the build at HIGH or above (the default)
node src/cli.mjs src/ --fail-on medium  # …and on the "confirm this by hand" findings too
node src/cli.mjs . --json               # machine-readable, for CI
node src/cli.mjs --help                 # every flag, with its default
```

### What gets scanned

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
its size or its directory does not report clean — it stops being *counted*, and
the count is printed on every run: `3 files · 0.1s` on the summary row, and
`scan.filesScanned` in `--json`. If that number is lower than you expect,
something was skipped. Nothing in this section can make a *scanned* file come
back clean.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | clean, or only findings below the threshold |
| `1` | findings at or above `--fail-on` (default `high`) |
| `2` | the scan itself failed — bad path, parse error, crash |

`1` and `2` are deliberately distinct. A CI job needs to tell "found problems"
apart from "the tool broke", and conflating them is how a scanner silently stops
scanning.

### The MEDIUM tier

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

This replaced a suppression that tried to decide the question and stayed silent
when it thought a rescue was present. Seven rounds of adversarial testing showed
that decision could be flipped either way by one line — a `catch`, a preflight
short-circuit, a socket default moved above the read — which meant a live bypass
could be muted by an edit that fixed nothing. **No edit that argues about
control flow can hide a finding any more; it can only downgrade one.**

That is deliberately narrower than what this paragraph used to claim ("it can no
longer be hidden"), because the two rounds after it found silence that had
nothing to do with control flow. Both were in the shared lexer underneath both
rules — the pass that decides which characters are code and which are data — and
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
that mechanism, not an absolute; see [Known limitations](#the-shared-lexer) for
what the invariant costs.

### Configured proxy trust does not silence this rule

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

### Which header reads it sees

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

### Which limiter calls it sees

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

### Colour

Colour is on for interactive terminals and off everywhere else. `NO_COLOR=1`
disables it, `FORCE_COLOR=1` forces it on — and `FORCE_COLOR` wins, matching
Node core and chalk.

Severity is never carried by colour alone: each level has its own ASCII glyph
(`!!`, `!`, `~`, `-`), so the report stays readable in CI logs, when piped to a
file, and for colourblind readers.

## Known limitations

The detectors are lexical passes, not full parsers — a deliberate trade-off to
stay at zero dependencies. Here is what that costs, per rule, and what it costs
in the character classification both of them read.

### The shared lexer

Both rules ask every question of one pass that labels each character CODE or
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
case is `zpl-finance/src/app/dashboard/layout.tsx` at 826 characters — five
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

### `webhook-swallows-2xx`

- A catch block that swallows via a helper (`return ok()` where `ok()` builds
  the 200 response elsewhere) is not detected.
- Any `throw` inside the catch body suppresses the finding, so conditional
  rethrows are treated as intentional. This is tuned for low noise: a finding
  you can't trust is worse than a miss you know about.
- **The Express branch never reads the status a chain sets.** `res.json(...)` in
  a catch is reported whatever came before it, and the only reason
  `res.status(500).json(...)` escapes is that `res` is not textually adjacent to
  `.json`. So the same 500 written as two statements is a false positive, and a
  real 2xx swallow written as `res.set(…).status(200).json(…)` is a miss:

  ```js
  res.status(500).json({ e });               // silent   — by accident
  res.status(500); res.json({ e });          // CRITICAL — false positive
  res.set('h', 'v').status(200).json({ o }); // silent   — real bug, missed
  ```

- **The status option is matched as text, and only as three digits.**
  `{ status: 99 }`, `{ status: 5000 }` and `{ status: code }` are all treated as
  "dynamic, assume intent" and not flagged. A quoted key — `{ "status": 500 }` —
  is a string, so the code channel does not contain it at all and the response
  reads as a defaulted 200: a false CRITICAL on a handler that answers 500. And
  the *first* `status:` in the argument text decides, so
  `Response.json({ status: 500 }, { status: 200 })` is read as a 500 while it
  sends a 200.

### `rate-limit-bypass`

**A hand-rolled limiter whose code contains no rate-limiting vocabulary is not
detected.** A file is analysed at all only when something outside its comments
mentions rate limiting. This route is a real bypass and prodcheck says nothing
about it:

```ts
// Simple in-memory rate limit: max 3 tickets per IP per hour
const ipWindow = new Map<string, { count: number; reset: number }>();

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0] ?? "unknown";
  const window = ipWindow.get(ip);
  ...
}
```

The window, the counter and the 429 are all there; the only place the words
"rate limit" appear is the comment, and comments are stripped before candidacy
is decided. Sibling routes in the same app, with the same in-memory logic, *are*
reported — purely because they happen to call a function named `checkRateLimit`.
That is candidacy working by luck rather than by analysis, and it is the
limitation we intend to fix.

**Destructuring is bound one shape at a time, and the shapes have edges.** All
three idioms in "Which header reads it sees" are recognised; what is *not*:

```js
const [, ip] = xff.split(',');              // a hole pattern — only the FIRST
                                            // element of an array pattern binds
const { 'x-forwarded-for': ip } = h;        // the object form needs the value it
                                            // destructures to be named `…headers`;
                                            // an aliased or renamed object is missed
import { XFF } from './headers';            // a header-name constant is resolved only
const ip = req.headers[XFF];                // when THIS file binds it to a literal —
                                            // an imported or computed name is not
```

Each of these is a deliberate stop rather than an oversight. Binding every
element of an array pattern would attach the identity to whichever name happened
to be last; accepting any right-hand side for the object form would report every
fixture and mock that maps the string `'x-forwarded-for'` to a name; and
resolving an imported constant is the cross-module value question, which is a
different piece of machinery from the one that joins helpers.

**Re-export chains break the cross-file join at one hop.** When a barrel
re-exports a helper — `export { getIp } from './lib/ip'` — the route imports
from the barrel while the header read lives in the module behind it, and a call
site is credited only to the module its import specifier actually names. The
same helper imported directly is found.

**The cross-file join reads `require`, but not the namespace idiom.** Every
named binding joins in both module systems — `const { getIp } = require('./ip')`
and `const getIp = require('./ip')` alike, against a helper exported as
`module.exports = { getIp }`, `exports.getIp = …` or `module.exports = getIp`.
What does not join is the namespace call, and it is the shape a lot of
CommonJS is written in:

```js
const ip = require('../lib/ip');
await limiter.consume(ip.getIp(req));       // ← not joined: a member call
```

Member calls are skipped for both module systems — `x.getIp(…)` says nothing
about which module `x` is — so a codebase that reaches its helpers through a
namespace object gets no cross-file findings from this rule. The single-file
half of the rule is unaffected.

**A whole-module binding credits any helper in that module.** `const ip =
require('./m')` and `import ip from './m'` both bind under the name `default`,
and the join treats that as a wildcard: the call is checked against the module,
not against a name in it. So a limiter keyed on something perfectly safe is
reported HIGH if the module it came from *also* exports something that reads a
forwarded header:

```js
// lib/ip.js exports resolveClientIp (reads x-forwarded-for) and tenantOf
const tenantOf = require('../lib/ip');
await limiter.consume(tenantOf(req));       // ← false HIGH against resolveClientIp
```

Named and destructured bindings carry the name and are checked against it; only
the whole-module form is loose.

**Some path aliases resolve to the wrong directory, and one resolves to
nothing.** `@/lib/x`, `~/lib/x` and `@@/lib/x` all resolve to `lib/x`, and
between them cover the overwhelming majority of aliased imports. But the
resolver drops the first path segment whatever it is, so where the marker *is* a
directory it costs a level: `$lib/x` (SvelteKit's `src/lib`) and `$app/x` both
resolve to `x`, and a route importing from `$lib/ip` joins a helper at the
project root instead of the one at `lib/ip`. Node's `#lib/x` subpath imports
resolve to nothing at all — the `?query`/`#fragment` suffix stripper runs first
and deletes a specifier that begins with `#`. Resolving either properly means
reading `svelte.config.js` or a package `imports` field, which is machinery this
tool does not have.

**Helper chains deeper than 3 hops are not followed.** `resolve()` → `identity()`
→ `key()` → the limiter is followed; one layer more is not.

**A log-only read at MODULE TOP LEVEL can still collide by name with a limiter
elsewhere in the file.** Every reachability question is asked inside the
enclosing *function* of the read, which is what stops one handler's `ip` from
answering for another's. A read at top level has no enclosing function, so the
scope it falls back to is the whole file — and there the collision is live
again:

```js
const ip = req.headers['x-forwarded-for'];   // ← reported, and only logs
console.log('caller', ip);

export async function POST(req) {
  const ip = getClientIp(req);
  await limiter.consume(ip);                 // a different `ip` entirely
}
```

Renaming the top-level variable makes the finding disappear, which is the
signature of a false positive. Module-level request handling is rare enough that
this has not been worth a scope table; it is a false HIGH when it happens.

**A closure that assigns an outer identity variable is a MEDIUM, not a HIGH.**

```js
let ip = req.headers['x-forwarded-for'];
const pin = () => { ip = req.socket.remoteAddress; };
if (!fromGateway(req)) pin();
```

This closure genuinely does rescue the identity; a closure that *declares* its
own `ip` rescues nothing. They differ by one keyword and by the scope table this
detector does not have, so both come out as MEDIUM naming the socket line. It
used to be a false HIGH on the first shape and a confident HIGH on the second —
the right answer for the wrong reason in one case and the wrong answer in the
other.

**A correct socket-level defence is a MEDIUM, not silence.** A guard clause, a
ternary that discards the forwarded value, a validating helper — prodcheck sees
the socket source and reports the read anyway, at MEDIUM, because proving the
defence governs the read is dataflow. This is deliberate noise: the alternative
was staying quiet, and staying quiet is what one unrelated line could buy.
`--fail-on high` is the default, so none of these break a build.

## About

`prodcheck` is a [Zero Point Logic](https://zeropointlogic.io) tool, built by
Ciciu Alexandru-Costinel. It grew out of the same discipline that shaped the
ZPL research work: every claim gets tested against reality, and a rule only
exists here because the bug behind it actually shipped, actually broke
something, and actually got fixed.

## Licence

MIT — see [LICENSE](LICENSE). That covers everything in this repository, which
is both shipping checks and the CLI around them. The five unimplemented rules
have no code and therefore no licence; if and when they ship, the terms will be
stated here rather than implied by a table.
