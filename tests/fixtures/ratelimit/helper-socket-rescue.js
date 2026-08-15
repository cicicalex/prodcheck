/**
 * helper-getclientip.ts with the one line that matters, and so the near-twin
 * that must stay silent.
 *
 * The helper still hands its result to a hand-rolled limiter, but the forgeable
 * header only survives inside it when the request really did arrive through the
 * edge; otherwise the identity is the peer address of the socket, which no
 * caller can choose. Nothing here is named after proxy trust — the reassignment
 * is the only evidence, and following the return value out must not cost the
 * suppression its reach: the rescue lives in the helper body, which is exactly
 * the scope the read inside it resolves to.
 */
const KNOWN_EDGES = new Set(['10.0.0.7', '10.0.0.8']);
const buckets = new Map();

function cameThroughEdge(req) {
  return KNOWN_EDGES.has(req.socket.remoteAddress);
}

function getClientIp(req) {
  let ip = req.headers['x-forwarded-for'];
  if (!cameThroughEdge(req)) ip = req.socket.remoteAddress;
  return ip;
}

function checkRateLimit(ip) {
  const seen = buckets.get(ip) ?? 0;
  buckets.set(ip, seen + 1);
  return seen < 30;
}

module.exports = async function handler(req, res) {
  const clientIp = getClientIp(req);
  if (!checkRateLimit(clientIp)) {
    res.statusCode = 429;
    return res.end('too many requests');
  }
  res.end('ok');
};
