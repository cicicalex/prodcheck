/**
 * The helper path's own near-twin, and the reason it follows the RETURN rather
 * than the mere fact that a helper was called.
 *
 * describeHop reads the forwarded chain, logs it, and returns something else
 * entirely. Its result really does key the limiter — so "this helper's value
 * reaches a limiter" is true — yet the forgeable header is not what it hands
 * back, and the bucket is keyed on the request method instead. Nothing here is
 * bypassable via the header, and the finding would be noise.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

function describeHop(req) {
  const forwarded = req.headers['x-forwarded-for'];
  console.log('chain claims %s', forwarded);
  return req.method;
}

module.exports = async function handler(req, res, next) {
  const label = describeHop(req);
  await apiLimiter.consume(label);
  next();
};
