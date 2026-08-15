/**
 * The second consumer of lib/limiter.js's getRequestIp, and the one that makes
 * `finalize` reach a read `check` has already reported.
 *
 * Nothing here is new — an imported identity, a limiter keyed on it — but the
 * finding it leads to lands on a line another phase already produced. Both are
 * correct, and there is still only one bug.
 */
import { checkRateLimit, getRequestIp } from '../lib/limiter.js';

export async function GET(req) {
  if (!checkRateLimit(`search:${getRequestIp(req)}`, 30)) {
    return new Response('slow down', { status: 429 });
  }
  return new Response('[]');
}
