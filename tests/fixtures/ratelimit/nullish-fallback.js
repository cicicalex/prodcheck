/**
 * or-fallback.js with `??` instead of `||`. The nullish operator is the more
 * careful spelling of the same mistake: it changes what counts as "missing",
 * never who decides. Whoever opens the socket still chooses the bucket.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

module.exports = async function guard(req, res, next) {
  const ip = req.headers['x-forwarded-for'] ?? req.socket.remoteAddress;
  await apiLimiter.consume(ip);
  next();
};
