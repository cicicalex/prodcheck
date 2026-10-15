# `env-secret-fallback`

[README](https://github.com/cicicalex/prodcheck/blob/main/README.md) · [Design notes](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md)

**Severity:** HIGH when the file also calls out to the network, otherwise MEDIUM

## What it catches

A credential read from the environment with a silent fallback to a literal:

```ts
const key = process.env.STRIPE_SECRET_KEY || 'sk_test_dev';   // ← reported
```

If the variable is missing in production, the service does not fail — it runs
on a default credential that is compiled into the source and visible to anyone
who can read it.

## How to fix it

Fail loudly when the variable is missing instead of substituting a value:

```ts
const key = process.env.STRIPE_SECRET_KEY;
if (!key) throw new Error('STRIPE_SECRET_KEY is not set');
```

## Severity: HIGH vs MEDIUM vs silence

`env-secret-fallback` uses the same contract, for the same reason. HIGH is a
credential defaulted to a literal in a file that also calls out to the network,
and the finding names the outbound line. MEDIUM is the identical default with no
outbound call visible in that file — still a default credential compiled into the
source, and inherited by everything importing it, but prodcheck cannot show where
it is spent and does not pretend to. Its third outcome is silence, and the
fallback's own value decides it: `''`, `'undefined'`, `'CHANGEME'` and
`'REPLACE_ME'` fail loudly the first time they are used, which is the behaviour
the rule asks for rather than the bug it looks for.

See [The MEDIUM tier](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md#the-medium-tier) for why the tiers
exist.

## Known limitations

**The variable NAME is the whole gate, and it is a substring test.** A secret is
whatever is spelled `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`,
`CREDENTIAL`, `AUTH`, `DSN`, `CONNECTION_STRING` or `PRIVATE`, case-insensitively
and anywhere in the name. That is wrong in both directions and both are stated
rather than hidden:

```js
process.env.AUTHOR_NAME || 'anon'     // ← reported. "AUTH" is in "AUTHOR".
process.env.FOO || 'sk_live_abc123'   // ← silent. Nothing lexical knows FOO is
                                      //   a Stripe key.
```

The over-reporting direction costs one finding a reader dismisses in a second.
The alternative — flagging every environment variable with a string default —
reports `process.env.PORT || 3000` and `process.env.NODE_ENV || 'development'`,
which are correct code in every Node service ever written, and a rule that does
that is switched off the same day.

**One over-report was too common to leave standing, and the last segment of the
name now vetoes the match.** `AUTH_URL` is NextAuth's own variable name, it
holds an origin rather than a credential, and defaulting it to the production
URL is deliberate. On the first run against a real Next.js codebase it was **six
of nine findings, across five files**, purely because `AUTH` is a substring of
`AUTH_URL`. So a name ending in `URL`, `URI`, `ENDPOINT`, `HOST`, `HOSTNAME`,
`DOMAIN`, `ORIGIN`, `PATH`, `DIR`, `PORT` or `REGION` is configuration however
its earlier segments read — while `URL_SECRET` and `ENDPOINT_API_KEY` are still
reported, because the veto is last-segment-only. The price is stated rather than
hidden: a URL carrying its own credentials, `REDIS_AUTH_URL` defaulting to
`redis://user:pass@…`, is now a miss.

**Defaults expressed through a schema library are not seen.** This rule matches
`??`, `||` and destructuring defaults on `process.env`. It does not read zod,
envalid, convict or joi:

```ts
const envSchema = z.object({
  SECRET_KEY: z.string().min(32),                 // ← correct, and invisible
  SECRET_KEY: z.string().default('dev-secret'),   // ← the same bug, and a MISS
});
envSchema.safeParse(process.env);
```

A config module written the first way is correct, and prodcheck rightly says
nothing about it — but it would say nothing about the second either, and the
second is exactly this rule's bug wearing a schema.

**The outbound test is file-scoped and coarse.** It asks "does this file reach
the network at all" — `fetch(`, `axios`, `got(`, `http.request` /
`https.request`, and `.post(` / `.get(` whose argument carries an absolute URL or
a `url`/`uri`/`endpoint`/`host` identifier. It does *not* ask whether this
particular credential reaches that particular call, because that is dataflow over
a control-flow graph and this tool has no parser. The answer only ever chooses
between HIGH and MEDIUM; nothing is silenced by it. A leading `/` is deliberately
not enough — `app.post('/api/charge', handler)` registers an *inbound* route, and
reading a routing table as an outbound call would promote every Express app to
HIGH.

**A fallback whose value this file cannot see is not judged.** `process.env.KEY
|| DEFAULT_KEY` is resolved only when `DEFAULT_KEY` is assigned a string literal
in the same file. Imported from `./defaults`, or returned by `getSecret()`, and
the read is left alone — an accusation about a value nobody reading the report
can check is worse than a miss.

**There is no cross-file phase.** Unlike `rate-limit-bypass`, this bug is not
split across modules: the offending line is complete on its own and the fix goes
exactly where the fallback is written. A config module that defaults a key and a
route that spends it are already covered — the config module is reported at
MEDIUM, on the line that has to change either way.

**The finding quotes the fallback back at you, truncated to 32 characters**, and
`fix.remove` is the offending source line in full. If a real credential was
committed as the default, it appears in the report and therefore in your CI log.
That is the same line you are being asked to delete, so this is a reason to
rotate it rather than a reason to hide it — but know it before piping the JSON
somewhere public.
