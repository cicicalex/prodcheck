// SILENT. The offending line exists twice in this file and neither copy is
// code, which is the entire claim: every match must BEGIN on the code channel
// of _lexer.mjs.
//
// Once as a commented-out line, kept by the author as a note to themselves:
//
//   const key = process.env.STRIPE_SECRET_KEY || 'sk_live_fallback';
//
/* …and once inside a block comment, which is the same channel one spelling
   over: const key = process.env.PAYMENT_API_KEY ?? 'pk_demo_123'; */

// The third copy is a STRING, which is a different channel again — strings are
// deliberately KEPT by stripComments, because header names and module names
// live in them, so it is the mask and not the text that rejects this one.
const MIGRATION_NOTE = "was: process.env.STRIPE_SECRET_KEY || 'sk_live_fallback'";

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
if (!STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY is not set');

export async function charge(cents) {
  console.log(MIGRATION_NOTE);
  return fetch('https://api.stripe.com/v1/charges', {
    method: 'POST',
    headers: { authorization: `Bearer ${STRIPE_SECRET_KEY}` },
    body: new URLSearchParams({ amount: String(cents) }),
  });
}
