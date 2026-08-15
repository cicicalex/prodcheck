/**
 * The defensive helper written as a GUARD CLAUSE, and the shape that proves the
 * suppression reads code rather than vocabulary.
 *
 * The peer address is taken from the socket first; if the peer is not one of
 * our edge nodes the header is never even read; only a request that physically
 * arrived from an edge node may name someone else, and even then an empty value
 * falls back to the peer. An attacker connecting directly is bucketed on their
 * own socket address and cannot move the bucket at all.
 *
 * This is `if (!cond) ip = socket` — which the assignment form of the
 * suppression already understands — spelled `if (!cond) return peer`, which is
 * how the identical check is written when it lives in a helper rather than in
 * the handler. The identity is never bound to a local at all, so there was no
 * name to look a rescue up by and the rescue was never looked for: correct
 * code, reported HIGH. Rename EDGE_NODES to TRUSTED_PROXIES and the file went
 * silent, which is the signature of a suppression keyed on a symbol's name.
 */
const { checkRateLimit } = require('./limiter');

const EDGE_NODES = new Set(['10.0.0.1', '10.0.0.2']);

function resolveClientIp(req) {
  const peer = req.socket.remoteAddress;
  if (!EDGE_NODES.has(peer)) return peer;
  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || peer;
}

module.exports = async function handler(req, res) {
  if (!checkRateLimit(resolveClientIp(req), 20, 60_000)) {
    return res.status(429).end();
  }
  return res.json({ ok: true });
};
