/**
 * Correct code that a file-wide reachability search reported anyway.
 *
 * `guarded` keys its limiter on req.ip, which Express resolves itself — no bug.
 * `debugOnly` reads the forwarded chain for a log line and nothing else — no
 * bug either. The only thing they share is the variable NAME `ip`, and a name
 * means nothing outside the function that declares it.
 *
 * Matched file-wide, guarded's `apiLimiter.consume(ip)` answered for
 * debugOnly's `ip` and this file drew a high finding on a console.log. Renaming
 * that one variable to `fwd` made the finding vanish, which is the signature of
 * a false positive rather than a bug — the code never changed.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

async function guarded(req) {
  const ip = req.ip;
  await apiLimiter.consume(ip);
}

async function debugOnly(req) {
  const ip = req.headers['x-forwarded-for'];
  console.log('chain claims %s', ip);
}

module.exports = { guarded, debugOnly };
