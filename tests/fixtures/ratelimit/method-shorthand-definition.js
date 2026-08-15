/**
 * `rateLimitKey(ip) { ... }` as object METHOD SHORTHAND is a definition, not a
 * call — and unlike `function rateLimit(key, limit)` it has no keyword to be
 * excluded on. Read as a call, its parameter list became an argument list, so
 * the definition's own parameter name `ip` counted as a limiter key and the
 * logging-only header read two lines above it — same function, same name —
 * reported itself.
 *
 * Nothing here consumes a forgeable identity: the object is a formatting
 * helper, the only use of the header value is a debug log, and the one real
 * limiter in the file buckets on the authenticated user id.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const userLimiter = new RateLimiterMemory({ points: 30, duration: 60 });

function logForwarded(req) {
  const ip = String(req.headers['x-forwarded-for'] || '').trim();
  const keys = {
    rateLimitKey(ip) {
      return `rl:${ip}`;
    },
  };
  req.log.debug({ ip, sample: keys.rateLimitKey('example') }, 'forwarded chain head');
}

async function handler(req, res) {
  await userLimiter.consume(req.user.id);
  return res.json({ ok: true });
}

module.exports = { logForwarded, handler };
