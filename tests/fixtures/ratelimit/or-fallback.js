/**
 * The one-liner everybody writes, and the reason the socket suppression needed
 * a second look. `req.socket.remoteAddress` is on the right-hand side, but it
 * is only reached when the header is ABSENT — and an attacker always sends the
 * header. The forgeable value still owns the bucket key, so the limiter is as
 * bypassable as it would be with no fallback at all.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

module.exports = async function guard(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  await apiLimiter.consume(ip);
  next();
};
