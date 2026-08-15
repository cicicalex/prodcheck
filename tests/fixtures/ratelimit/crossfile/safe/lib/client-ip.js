/**
 * The validating twin of lib/rate-limit.js's getIp, split across two files in
 * exactly the same way — and the shape that must never be a HIGH.
 *
 * The peer address of the socket is taken first, and the forwarded chain is
 * read at all only when the request physically arrived from one of our edge
 * nodes; anyone connecting directly is bucketed on an address they cannot
 * choose. Whether that guard governs the read below it is a dataflow question,
 * so this is a MEDIUM: the helper is recorded, carrying the line of the socket
 * source, and the join reports it as something to confirm by hand rather than
 * as a confident bypass.
 *
 * It must never be silent either. One `if (req.method === 'OPTIONS') return
 * req.socket.remoteAddress` is indistinguishable from this guard to a lexical
 * pass, and silence there muted every route importing the helper.
 *
 * Nothing here is named after proxy trust. Rename EDGE_NODES to anything at all
 * and the answer is unchanged, because the evidence is the data flow.
 */
const EDGE_NODES = new Set(['10.0.0.1', '10.0.0.2']);

export function resolveClientIp(req) {
  const peer = req.socket.remoteAddress;
  if (!EDGE_NODES.has(peer)) return peer;
  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || peer;
}
