/**
 * The same fallback split across two statements with `||=`. It reads like a
 * repair of the header read above it, which is exactly why it fooled the
 * suppression: the assignment happens only when the header produced nothing,
 * so a caller who sends one is never repaired.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const loginLimiter = new RateLimiterMemory({ points: 5, duration: 60 });

module.exports = async function guard(req, res, next) {
  let ip = req.headers['x-real-ip'];
  ip ||= req.connection.remoteAddress;
  await loginLimiter.consume(ip);
  next();
};
