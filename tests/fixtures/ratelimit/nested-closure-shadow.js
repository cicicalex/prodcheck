/**
 * A live bypass hidden behind a closure that shadows the identity name.
 *
 * The handler's `ip` keeps the raw forwarded header all the way into
 * `consume()`, and nothing ever overrides it. The only socket assignment in the
 * function is auditPeer's own `const ip` — a different variable that merely
 * spells its name the same way, and one that could not rescue the handler's
 * identity even if it wanted to.
 *
 * Searching the enclosing function body without cutting out the bodies nested
 * inside it reads that declaration as a rescue and silences a real bypass.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

module.exports = async function handler(req, res, next) {
  const ip = req.headers['x-forwarded-for'];

  const auditPeer = () => {
    const ip = req.socket.remoteAddress;
    console.log('peer %s', ip);
  };

  auditPeer();
  await apiLimiter.consume(ip);
  next();
};
