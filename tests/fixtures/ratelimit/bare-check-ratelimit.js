/**
 * A limiter with no library behind it, invoked as a BARE function.
 *
 * `checkRateLimit(ip)` has no receiver to corroborate it, so a rule that only
 * understood `receiver.method(...)` never saw the identity being consumed and
 * read this file as a header read that goes nowhere. Hand-rolled limiters are
 * precisely the ones with no `trust proxy` setting anywhere near them, which
 * makes them the last shape that should be exempt.
 *
 * The declaration on line 15 is not a call: reading its parameter list as
 * arguments would put `ip` into the reachability search for free, and every
 * file that so much as defines a limiter would report itself.
 */
const buckets = new Map();

function checkRateLimit(ip) {
  const seen = buckets.get(ip) ?? 0;
  buckets.set(ip, seen + 1);
  return seen < 30;
}

module.exports = async function handler(req, res) {
  const ip = req.headers['x-forwarded-for'];
  if (!checkRateLimit(ip)) {
    res.statusCode = 429;
    return res.end('too many requests');
  }
  res.end('ok');
};
