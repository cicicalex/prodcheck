/**
 * The decoy, and the reason the cross-file join asks WHERE the imported value
 * lands rather than merely whether it was imported.
 *
 * This route imports the very same getIp from the very same module, and it does
 * run a rate limiter — but the bucket is keyed on the account the caller
 * authenticated as, which no header can move. getIp's result reaches a log line
 * and nothing else.
 *
 * Crediting the import alone would report the helper for this file, and every
 * codebase has a file like it: the identity helper is used for analytics,
 * audit trails and debug output far more often than for bucketing. A rule that
 * cannot tell those apart is a rule nobody keeps switched on.
 */
import { rateLimit, getIp } from '../lib/rate-limit.js';

export async function POST(req) {
  const account = req.headers.get('x-account-id') ?? 'anonymous';
  const rl = rateLimit(`audit:${account}`, 20, 60_000);
  if (!rl.success) {
    return new Response('too many audit writes', { status: 429 });
  }

  console.log('[audit] %s from %s', account, getIp(req));
  return new Response('ok');
}
