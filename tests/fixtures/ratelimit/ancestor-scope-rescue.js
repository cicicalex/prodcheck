/**
 * Correct code whose rescue lives in an ANCESTOR scope of the header reads.
 *
 * Each read happens inside its own `if`/`else` body; the line that overrides
 * the identity with the socket's peer address sits one level out, in the
 * handler body containing all of them. It governs every read below it — that is
 * what an outer scope means — so the file is safe: a caller who forges the
 * header still lands in the socket's bucket unless the request really did
 * arrive through the edge.
 *
 * Anchored on the innermost `{...}` around a read, the suppression could not
 * see that line and reported two high findings here. The scope has to be the
 * enclosing FUNCTION body.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const KNOWN_EDGES = new Set(['10.0.0.7', '10.0.0.8']);
const apiLimiter = new RateLimiterMemory({ points: 10, duration: 60 });

function arrivedViaEdge(req) {
  return KNOWN_EDGES.has(req.socket.remoteAddress);
}

module.exports = async function handler(req, res, next) {
  let ip;
  if (req.method === 'POST') {
    ip = req.headers['x-forwarded-for'];
  } else {
    ip = req.headers['x-real-ip'];
  }
  if (!arrivedViaEdge(req)) ip = req.socket.remoteAddress;
  await apiLimiter.consume(ip);
  next();
};
