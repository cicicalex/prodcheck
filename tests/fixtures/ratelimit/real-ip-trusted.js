/**
 * Identity resolved through getClientIp, which only believes X-Real-IP when
 * the request arrived from a known proxy.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const TRUSTED_PROXIES = new Set(['10.0.0.1', '10.0.0.2']);
const limiter = new RateLimiterMemory({ points: 20, duration: 60 });

function getClientIp(req, { trustProxy }) {
  if (trustProxy.has(req.socket.remoteAddress)) {
    return req.headers['x-real-ip'] ?? req.socket.remoteAddress;
  }
  return req.socket.remoteAddress;
}

module.exports = async function guard(req, res, next) {
  const ip = getClientIp(req, { trustProxy: TRUSTED_PROXIES });
  await limiter.consume(ip);
  next();
};
