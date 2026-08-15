/**
 * or-fallback.js verbatim — the header wins whenever the client sends it, the
 * socket address is only the empty-handed default — plus one log message whose
 * TEXT contains the words "trust proxy". No configuration, no allowlist, no
 * validation: a string.
 *
 * Matched against source with string literals kept, the trust suppression made
 * that one line silence every finding in the file. It is a mute available to
 * anyone who wants the scanner quiet, and reachable by accident in any file
 * that merely DISCUSSES proxy trust in an error message. A real trust marker —
 * `trustProxy: true`, a TRUSTED_PROXIES allowlist, `app.set('trust proxy', 1)`
 * — is a symbol or a setter's option key, and those still suppress.
 */
const { RateLimiterMemory } = require('rate-limiter-flexible');

const rl = new RateLimiterMemory({ points: 20, duration: 60 });

module.exports = async function handler(req, res) {
  if (!process.env.EDGE_READY) {
    console.warn('deploy checklist: remember to configure trust proxy at the edge');
  }

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  try {
    await rl.consume(ip);
  } catch {
    return res.status(429).end();
  }
  return res.json({ ok: true });
};
