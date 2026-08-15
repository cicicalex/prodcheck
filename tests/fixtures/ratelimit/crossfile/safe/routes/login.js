/**
 * The consumer of the validating helper: identical in shape to
 * routes/register.js — an imported identity, a limiter keyed on it — and
 * correct, because the identity it receives cannot be forged.
 *
 * This is the discriminating half of the pair. If the cross-file join fired on
 * "an imported helper reads a header and its result keys a limiter" it would
 * report this file's helper too, and the rule would be back to reporting the
 * shape of code rather than the bug in it.
 */
import { resolveClientIp } from '../lib/client-ip.js';

const buckets = new Map();

function checkRateLimit(key) {
  const seen = buckets.get(key) ?? 0;
  buckets.set(key, seen + 1);
  return seen < 5;
}

export async function POST(req) {
  if (!checkRateLimit(`login:${resolveClientIp(req)}`)) {
    return new Response('too many logins', { status: 429 });
  }
  return new Response('ok');
}
