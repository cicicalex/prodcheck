# prodcheck

Finds the production bugs that ship green — the ones that pass your tests,
linter and type checker and still lose a webhook or let a rate limit be bypassed.

Zero dependencies. No config, no account, no telemetry, no network calls.

## Install

```bash
npx @zeropointlogic/prodcheck .          # scan the current directory, no install

npm install -g @zeropointlogic/prodcheck # or install once…
prodcheck ~/my-app                       # …and run it as `prodcheck` (Node 18+)
```

## Example

Scanning a small app with a Stripe webhook route and a rate-limited contact route:

```
  !! CRITICAL  webhook-swallows-2xx
     app/api/stripe/route.ts:13

     - return new Response('ok', { status: 200 });
     + return new Response('webhook handler failed', { status: 500 });  // non-2xx so the provider retries

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

  → 4 more checks planned
```

Each finding names the file and line, the line to remove, the line to add, and
what goes wrong in production if you leave it.

## Checks

| Check | Severity | What it catches |
| --- | --- | --- |
| [`webhook-swallows-2xx`](https://github.com/cicicalex/prodcheck/blob/main/docs/rules/webhook-swallows-2xx.md) | CRITICAL | `catch` in a webhook handler returning 2xx without re-throwing |
| [`rate-limit-bypass`](https://github.com/cicicalex/prodcheck/blob/main/docs/rules/rate-limit-bypass.md) | HIGH / MEDIUM | a rate limiter keyed on `X-Forwarded-For` read by hand |
| [`env-secret-fallback`](https://github.com/cicicalex/prodcheck/blob/main/docs/rules/env-secret-fallback.md) | HIGH / MEDIUM | a credential from `process.env` with a silent fallback to a literal |

**`webhook-swallows-2xx`** — when a webhook handler's `catch` answers 200,
the provider marks the event delivered and never retries it, so a failed payment
or signup is silently lost. Return a non-2xx status (or re-throw) so the provider
retries. [Details](https://github.com/cicicalex/prodcheck/blob/main/docs/rules/webhook-swallows-2xx.md)

**`rate-limit-bypass`** — `X-Forwarded-For` and `X-Real-IP` are set by the
client, so a limiter keyed on them can be dodged by rotating the header, or
turned against a victim by pinning theirs. Use the address the framework or
platform resolved (`req.ip` with `trust proxy` set under Express; the
platform's verified client IP on edge runtimes). MEDIUM means a socket-level
address is also in scope and prodcheck cannot tell which one the limiter gets.
[Details](https://github.com/cicicalex/prodcheck/blob/main/docs/rules/rate-limit-bypass.md)

**`env-secret-fallback`** — `process.env.API_KEY || 'dev-key'` means a missing
variable in production runs on a credential compiled into your source. Throw
when the variable is missing instead. HIGH when the same file calls out to the
network, MEDIUM otherwise. [Details](https://github.com/cicicalex/prodcheck/blob/main/docs/rules/env-secret-fallback.md)

Four more checks are designed but not yet implemented; the `→ 4 more checks
planned` row in the report refers to them. See
[Why these checks](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md#why-these-checks).

## Usage

```bash
prodcheck [path] [options]     # path defaults to .
```

| Option | Meaning |
| --- | --- |
| `--fail-on <level>` | exit 1 at this severity or above: `critical`, `high` (default), `medium`, `low`, `never` |
| `--json` | emit JSON instead of the report (each finding links to its rule's docs) |
| `--no-color` | disable colour (same as `NO_COLOR=1`) |
| `-v`, `--version` | print version and exit |
| `-h`, `--help` | show help |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | clean, or only findings below the `--fail-on` threshold |
| `1` | findings at or above `--fail-on` (default `high`) |
| `2` | the scan itself failed — bad path, parse error, crash |

`1` and `2` are distinct so CI can tell "found problems" from "the tool broke".

### What gets scanned

- Files ending in `.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, `.jsx`, `.tsx`.
- Never descends into `node_modules`, `.git`, `dist`, `build`, `.next`, `coverage`.
- Files over 1 MiB are skipped; symlinks are not followed.

The number of files scanned is printed on every run. A path with no scannable
files reports clean but warns on stderr:
`prodcheck: warning: no .js/.ts files found under <path>`.
[More](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md#what-gets-scanned)

### Colour

Colour is on in interactive terminals and off elsewhere. `NO_COLOR=1` turns it
off and `FORCE_COLOR=1` turns it on (`FORCE_COLOR` wins over `NO_COLOR`, as in
Node). `--no-color` always wins. Severity is also shown by an ASCII glyph
(`!!`, `!`, `~`, `-`), so the report reads fine without colour.

## CI (GitHub Actions)

```yaml
- uses: actions/setup-node@v4
  with: { node-version: 20 }
- run: npx @zeropointlogic/prodcheck . --fail-on high
```

The step fails on any CRITICAL or HIGH finding. Use `--fail-on medium` to also
fail on findings that need a human to confirm.

## Limitations

prodcheck is a lexical analyzer, not a full parser — a deliberate trade-off to
stay at zero dependencies. In short:

- It can miss bugs written in shapes it does not recognise (e.g. a webhook
  `catch` that returns 200 through a helper, or secrets defaulted through a
  zod/envalid schema).
- When it cannot resolve something, it reports at MEDIUM rather than staying
  silent, so expect some MEDIUM findings on correct code.
- Cross-file analysis (`rate-limit-bypass` only) follows helpers up to 3 hops
  and does not follow re-export barrels or namespace imports.

Every known gap is listed per rule in [`docs/rules/`](https://github.com/cicicalex/prodcheck/blob/main/docs/rules), and the
lexer's design and testing in [`docs/DESIGN.md`](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md).

## Contributing

From a checkout, run the CLI with `node src/cli.mjs` (e.g.
`node src/cli.mjs sample` for the example above) and the tests with `npm test`.

## Licence

MIT — see [LICENSE](https://github.com/cicicalex/prodcheck/blob/main/LICENSE). A [Zero Point Logic](https://zeropointlogic.io)
tool by Ciciu Alexandru-Costinel.
