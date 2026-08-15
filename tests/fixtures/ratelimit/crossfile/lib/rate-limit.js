/**
 * The helper module of the canonical lib/ + routes/ layout, and the half of the
 * bug that is invisible to a single-file check.
 *
 * getIp walks a chain of client-settable headers and hands the first one it
 * finds back to its caller. Nothing in this file mentions a limiter, keys a
 * bucket or looks wrong in review — the identity it resolves is only dangerous
 * once somebody else buckets on it, and that somebody lives in routes/.
 *
 * This is the shape a real Next.js app ships: one lib module resolving the
 * client address, a dozen route modules importing it. `check(file)` sees this
 * file alone, finds no limiter to reach, and is right to stay quiet; the seam
 * is what `collect` records and `finalize` closes.
 */
const store = new Map();

export function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  const entry = store.get(key);

  if (!entry || entry.resetAt < now) {
    store.set(key, { count: 1, resetAt: now + windowMs });
    return { success: true, remaining: limit - 1 };
  }

  entry.count += 1;
  return { success: entry.count <= limit, remaining: Math.max(0, limit - entry.count) };
}

/** Resolve the caller's address from the request headers. */
export function getIp(req) {
  const cf = req.headers.get('cf-connecting-ip');
  if (cf) return cf;
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp;
  return 'unknown';
}
