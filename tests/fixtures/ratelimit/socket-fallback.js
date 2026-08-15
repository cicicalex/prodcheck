/**
 * Correct code that the name-based trust suppression alone would miss.
 *
 * The forwarded header is believed only when the request actually arrived
 * through the edge gateway; otherwise the identity falls back to the peer
 * address of the socket, which no client can forge. Nothing in this file is
 * named after proxy trust — the only evidence that the untrusted header was
 * handled is the reassignment, and that is exactly what must be enough.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const KNOWN_GATEWAYS = new Set(['10.0.0.7', '10.0.0.8']);
const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

function isBehindKnownGateway(req) {
  return KNOWN_GATEWAYS.has(req.socket.remoteAddress);
}

module.exports = async function guard(req, res, next) {
  let ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (!isBehindKnownGateway(req)) ip = req.socket.remoteAddress;
  await apiLimiter.consume(ip);
  next();
};
