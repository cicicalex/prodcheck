/**
 * A live, complete bypass two hops from the read: the raw X-Forwarded-For value
 * is returned by one helper, passed through a second, and handed to the limiter
 * as the bucket key. An attacker rotating the header gets a fresh bucket per
 * request.
 *
 * The return-value path used to follow exactly one hop, so collapsing
 * forwardedChain and identityFor into a single function fired while this — the
 * same code after an ordinary refactor — did not. Splitting a resolver in two
 * is not evasion, and the bug is exactly as real at depth two as at depth one.
 */
const { checkRateLimit } = require('./limiter');

function forwardedChain(req) {
  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
}

function identityFor(req) {
  const ip = forwardedChain(req);
  return ip || 'anonymous';
}

module.exports = async function handler(req, res) {
  const key = identityFor(req);
  if (!checkRateLimit(key, 20, 60_000)) {
    return res.status(429).end();
  }
  return res.json({ ok: true });
};
