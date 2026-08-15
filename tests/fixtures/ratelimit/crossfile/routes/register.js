/**
 * The consuming half: the route imports both the limiter and the identity
 * helper, and keys one with the other.
 *
 * Read on its own this file is clean — it never touches a header, and the value
 * it buckets on is a function call whose body is somewhere else entirely. Read
 * together with lib/rate-limit.js it is a complete bypass: rotate
 * x-forwarded-for and every request lands in a fresh bucket.
 *
 * The finding belongs at the header read inside the helper, not here. Eleven
 * routes like this one are eleven symptoms of a bug with exactly one line to
 * change.
 */
import { rateLimit, getIp } from '../lib/rate-limit.js';

export async function POST(req) {
  const rl = rateLimit(`register:${getIp(req)}`, 5, 60_000);
  if (!rl.success) {
    return new Response('too many registrations', { status: 429 });
  }
  return new Response('ok');
}
