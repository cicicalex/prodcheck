/**
 * A ternary, not a fallback. The header is kept only when the request actually
 * arrived through the edge gateway; otherwise the identity is the peer address
 * of the socket. The condition — never the presence of the header — decides,
 * so a caller who forges the header still lands in the socket's bucket.
 *
 * Shape-wise this is one character away from or-fallback.js, and it must stay
 * silent while that one fires.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const KNOWN_GATEWAYS = new Set(['10.0.0.7', '10.0.0.8']);
const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

function cameThroughGateway(req) {
  return KNOWN_GATEWAYS.has(req.socket.remoteAddress);
}

module.exports = async function guard(req, res, next) {
  let ip = req.headers['x-forwarded-for'];
  ip = cameThroughGateway(req) ? ip : req.socket.remoteAddress;
  await apiLimiter.consume(ip);
  next();
};
