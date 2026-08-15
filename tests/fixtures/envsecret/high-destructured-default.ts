// HIGH, through the spelling no accessor pattern can see: the read IS the
// destructuring pattern, so there is no `process.env.X` to match on. This is
// also the spelling that collects defaults in bulk — a config module ends up
// holding several at once, and each one is a separate variable with a separate
// fix.
//
// The second default on the same line is empty, which is the SILENT case: `''`
// is falsy, the SDK below rejects it, and the deploy fails loudly. Only the
// first default is a credential this file would actually spend.
const { STRIPE_SECRET_KEY = 'sk_test_x', SIGNING_SECRET = '' } = process.env;

export async function charge(amountCents: number) {
  return fetch('https://api.stripe.com/v1/charges', {
    method: 'POST',
    headers: { authorization: `Bearer ${STRIPE_SECRET_KEY}` },
    body: new URLSearchParams({ amount: String(amountCents), signed: SIGNING_SECRET }),
  });
}
