/**
 * Both validating shapes written with optional chaining, which the address
 * pattern allows on purpose: `req.socket?.remoteAddress` reads the same
 * unforgeable value as `req.socket.remoteAddress`.
 *
 * edgeGuard overrides behind a condition, directGuard overrides outright. The
 * `?.` must not be mistaken for the `??` that marks a fallback — one character
 * apart, opposite meanings.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const KNOWN_GATEWAYS = new Set(['10.0.0.7', '10.0.0.8']);
const edgeLimiter = new RateLimiterMemory({ points: 10, duration: 60 });
const directLimiter = new RateLimiterMemory({ points: 20, duration: 60 });

function cameThroughGateway(req) {
  return KNOWN_GATEWAYS.has(req.socket.remoteAddress);
}

async function edgeGuard(req) {
  let ip = req.headers['x-forwarded-for'];
  if (!cameThroughGateway(req)) ip = req.socket?.remoteAddress;
  await edgeLimiter.consume(ip);
}

async function directGuard(req) {
  let who = req.headers['x-real-ip'];
  console.warn('x-real-ip claims %s', who);
  who = req?.socket?.remoteAddress;
  await directLimiter.consume(who);
}

module.exports = { edgeGuard, directGuard };
