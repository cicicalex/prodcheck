# `rate-limit-bypass`

[README](https://github.com/cicicalex/prodcheck/blob/main/README.md) · [Design notes](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md)

**Severity:** HIGH, or MEDIUM when a socket-level address source is also in scope

## What it catches

A rate limiter keyed on `X-Forwarded-For` (or `X-Real-IP`) read by hand. Any
client can set that header, so an attacker rotates the value to get a fresh
bucket on every request — the limit does not exist for them — or pins a
victim's IP to exhaust that victim's bucket.

```ts
const ip = req.headers.get('x-forwarded-for') ?? 'anonymous';   // ← reported
await ratelimit.limit(ip);
```

The rule follows the identity across files: a helper that reads the header in
`lib/ip.ts` and a route that passes its result to a limiter are joined into one
finding.

## How to fix it

Use the address the framework or platform resolved, not the raw header. Under
Express, set `trust proxy` to the number of proxies you actually control and
read `req.ip`. On Next.js, Vercel, Cloudflare or another edge runtime there is
no `req.ip` — use the platform's own verified client-IP value.

Configuring proxy trust and then reading the header by hand is still reported:
see [Configured proxy trust does not silence this rule](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md#configured-proxy-trust-does-not-silence-this-rule).

## Severity: HIGH vs MEDIUM

HIGH means no socket-level source (`req.socket.remoteAddress`, `req.ip`) exists
for the identity in the enclosing function, so nothing could have rescued it.
MEDIUM means one does, and prodcheck cannot tell lexically whether it governs
the read. The default `--fail-on high` does not fail a build on a MEDIUM. The
full contract is in [The MEDIUM tier](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md#the-medium-tier).

## Which reads and limiters it recognises

The six header-read spellings, header-name constants, and the limiter calls and
constructions it understands are listed in the design notes:
[Which header reads it sees](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md#which-header-reads-it-sees) and
[Which limiter calls it sees](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md#which-limiter-calls-it-sees).

## Known limitations

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
three idioms in [Which header reads it sees](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md#which-header-reads-it-sees) are recognised; what is *not*:

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
