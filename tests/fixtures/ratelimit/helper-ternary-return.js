/**
 * ternary-validated.js with no variable in the middle: a CONDITION picks the
 * identity and the helper returns the choice directly.
 *
 * When the request did not arrive through the edge, the peer address wins
 * outright and the forwarded value is discarded — the same thing
 * `ip = arrivedViaEdge(req) ? xff : req.socket.remoteAddress` says, minus the
 * name. That difference is invisible to an attacker and to a reviewer, and this
 * is the more compact of the two spellings; if binding the expression to a
 * local is what makes the tool quiet, the rule is keyed on whether a variable
 * happens to exist rather than on whether the identity can be forged.
 *
 * The `|| ''` inside the String(...) call defaults that argument, not the value
 * the return yields — a coalesce nested in a call is not the outer choice.
 */
const { checkRateLimit } = require('./limiter');
const { arrivedViaEdge } = require('./net-utils');

function resolveClientIp(req) {
  return arrivedViaEdge(req)
    ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    : req.socket.remoteAddress;
}

module.exports = async function handler(req, res) {
  const ip = resolveClientIp(req);
  if (!checkRateLimit(ip, 20, 60_000)) {
    return res.status(429).end();
  }
  return res.json({ ok: true });
};
