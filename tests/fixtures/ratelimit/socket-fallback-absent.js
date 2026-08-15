/**
 * socket-fallback.js minus the one line that matters: the gateway check only
 * writes a log, so `ip` keeps whatever the caller put in the forwarded header
 * and the limiter buckets on a value the caller chooses.
 *
 * The file still reads req.socket.remoteAddress inside the helper — proof
 * that the suppression follows the assignment, not the file's vocabulary.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const KNOWN_GATEWAYS = new Set(['10.0.0.7', '10.0.0.8']);
const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

function isBehindKnownGateway(req) {
  return KNOWN_GATEWAYS.has(req.socket.remoteAddress);
}

module.exports = async function guard(req, res, next) {
  let ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (!isBehindKnownGateway(req)) console.warn('direct hit from %s', ip);
  await apiLimiter.consume(ip);
  next();
};
