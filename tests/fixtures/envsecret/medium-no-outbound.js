// MEDIUM. The same silent default, in a module that never calls anything: no
// `fetch`, no client, no URL. prodcheck cannot show where the credential is
// spent, so it does not claim to — but a default signing secret compiled into
// a shared module is inherited by every file that imports it, which is why this
// is reported rather than dropped.
//
// The fallback is held in a constant rather than written at the read, which was
// the whole point of resolving those: `|| DEFAULT_SIGNING_KEY` reads as
// deliberate configuration until you look up the value one line above.
const DEFAULT_SIGNING_KEY = 'dev-signing-key-do-not-use';

export function signingKey() {
  return process.env.SESSION_SIGNING_KEY || DEFAULT_SIGNING_KEY;
}

export function sessionTtlSeconds() {
  // Configuration, not a credential, and correctly defaulted. Nothing here is
  // reported and nothing here should be.
  return Number(process.env.SESSION_TTL || 3600);
}
