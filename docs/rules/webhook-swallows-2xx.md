# `webhook-swallows-2xx`

[README](https://github.com/cicicalex/prodcheck/blob/main/README.md) · [Design notes](https://github.com/cicicalex/prodcheck/blob/main/docs/DESIGN.md)

**Severity:** CRITICAL

## What it catches

A `catch` block in a webhook handler that answers with a 2xx status without
re-throwing. The webhook provider (Stripe, GitHub, Clerk, …) marks the event
delivered and never retries it, so the failure is silently lost — no retry, no
alert, no trace in the provider dashboard.

```ts
} catch (err) {
  logger.error(err);
  return new Response('ok', { status: 200 });   // ← reported
}
```

## How to fix it

Answer with a non-2xx status (or re-throw) so the provider retries:

```ts
return new Response('webhook handler failed', { status: 500 });
```

If the event really is safe to acknowledge (a duplicate delivery, say), inspect
the caught error before answering 2xx — see the idempotency exemption below.

## Known limitations

- A catch block that swallows via a helper (`return ok()` where `ok()` builds
  the 200 response elsewhere) is not detected.
- Any `throw` inside the catch body suppresses the finding, so conditional
  rethrows are treated as intentional. This is tuned for low noise: a finding
  you can't trust is worse than a miss you know about.
- **A 2xx on a branch that inspects the caught error is not reported**, provided
  the catch also has a way out that does not answer 2xx. That is the idempotency
  pattern —

  ```js
  catch (err) {
    if (err.code === "P2002") return NextResponse.json({ duplicate: true });
    log(err);          // anything else falls through and is processed for real
  }
  ```

  — and reporting it is noise on correct code. The condition does not have to
  name the binding: because `err` is `unknown` in TypeScript, the idiomatic
  spelling narrows through a local first, and that is followed —
  `const code = (err as { code?: string }).code`, the destructured
  `const { code } = err`, its renamed form `{ code: c }`, and transitive chains
  like `const e = err; const code = e.code`. Order does not matter; the widening
  runs to a fixpoint. **This was the shape most often written and least often
  handled: for the first three releases only the direct spelling was recognised,
  so the version of the pattern that appears most in real TypeScript was the
  version reported.** Found by running the rule against a 484-file repository,
  not by a fixture — the suite was green at 449 tests the whole time it was open.

  What that exemption still cannot read is listed with the code: `&&`/`||`
  short-circuits are not treated as guards (still reported); an `else` arm of an
  error-inspecting `if` counts as guarded even though it is the *general* path,
  so `if (err.code === "X") { log(err); } else { return res.json({ ok: true }); }`
  is a miss; a `return` nested in a loop inside the catch reads as "control falls
  out"; and a bare derived name — `if (code)` where `code` came from the error —
  is treated like `if (err)` and does **not** count as discrimination, because it
  asks whether the error has a field rather than which error it is. All apply
  only to a 2xx that is already guarded — an unconditional one anywhere in the
  block is reported regardless.
- **A chain's status is only read when the chain STARTS at the response
  object.** `res.status(500).json(...)` and `reply.code(204).send()` are read
  correctly, because `status`/`code` follow the receiver directly. A terminal
  method that does not — `res.json(...)` after a separate `res.status(500)`, or
  a chain opening with a different verb — is not:

  ```js
  res.status(500).json({ e });               // silent   — correct
  reply.code(204).send();                    // CRITICAL — correct
  res.status(500); res.json({ e });          // CRITICAL — false positive
  res.set('h', 'v').status(200).json({ o }); // silent   — real bug, missed
  ```

- **The response receivers are a fixed list** — `res`, `reply`, `response`,
  `resp`, `ctx`, plus `c` in a file that imports hono. A handler that names its
  response object anything else is missed, and that is deliberate: "any
  identifier" reports `logger.send(err)` and `queue.end()`. For the same reason
  `.text()`/`.html()`/`.body()` count on `c` alone (they are also how a `fetch`
  body is read), and a call whose result is assigned — `const b = await
  response.json()` — is read as a body read, not an answer.

- **The status option is matched as text, and only as three digits.**
  `{ status: 99 }`, `{ status: 5000 }` and `{ status: code }` are all treated as
  "dynamic, assume intent" and not flagged. A quoted key — `{ "status": 500 }` —
  is a string, so the code channel does not contain it at all and the response
  reads as a defaulted 200: a false CRITICAL on a handler that answers 500. And
  the *first* `status:` in the argument text decides, so
  `Response.json({ status: 500 }, { status: 200 })` is read as a 500 while it
  sends a 200.
