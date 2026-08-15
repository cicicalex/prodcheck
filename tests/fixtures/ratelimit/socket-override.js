/**
 * The forwarded chain is read for the log line and nothing else: the identity
 * is overwritten, unconditionally, with the peer address of the socket. No
 * condition is needed when the header never gets to win.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

module.exports = async function guard(req, res, next) {
  let ip = req.headers['x-forwarded-for'];
  console.log('forwarded chain claims %s', ip);
  ip = req.socket.remoteAddress;
  await apiLimiter.consume(ip);
  next();
};
