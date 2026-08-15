/**
 * The module that is both halves at once, and the one that proves the two
 * phases do not double-report.
 *
 * getRequestIp resolves a forgeable address; guardHealthEndpoint, in this same
 * file, keys a limiter with it — so `check` finds the bug here on its own, by
 * the return path it has always followed. routes/search.js imports the same
 * helper and keys another limiter with it, so `finalize` finds the very same
 * read, from the other direction.
 *
 * Two phases, one header read, one line to change. The CLI dedupes findings by
 * (rule, file, line) precisely so that arriving at a bug twice reports it once:
 * a developer opening this file must see one thing to fix, not the same thing
 * listed once per route that happens to import it.
 */
const buckets = new Map();

export function checkRateLimit(key, max) {
  const seen = buckets.get(key) ?? 0;
  buckets.set(key, seen + 1);
  return seen < max;
}

export function getRequestIp(req) {
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  return 'unknown';
}

export function guardHealthEndpoint(req) {
  return checkRateLimit(`health:${getRequestIp(req)}`, 60);
}
