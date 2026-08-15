/**
 * Two handlers, one variable name, opposite habits. safeRoute validates its
 * own `ip`; unsafeRoute buckets on the raw header and never touches a socket.
 *
 * Nothing in safeRoute is reachable from unsafeRoute, so a file-wide search for
 * "is `ip` ever assigned a socket address" answers yes and silences the real
 * bug. The suppression has to stop at the block that contains the read.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const KNOWN_GATEWAYS = new Set(['10.0.0.7', '10.0.0.8']);
const safeLimiter = new RateLimiterMemory({ points: 5, duration: 60 });
const unsafeLimiter = new RateLimiterMemory({ points: 100, duration: 60 });

function cameThroughGateway(req) {
  return KNOWN_GATEWAYS.has(req.socket.remoteAddress);
}

async function safeRoute(req) {
  let ip = req.headers['x-forwarded-for'];
  if (!cameThroughGateway(req)) ip = req.socket.remoteAddress;
  await safeLimiter.consume(ip);
}

async function unsafeRoute(req) {
  const ip = req.headers['x-forwarded-for'];
  await unsafeLimiter.consume(ip);
}

module.exports = { safeRoute, unsafeRoute };
