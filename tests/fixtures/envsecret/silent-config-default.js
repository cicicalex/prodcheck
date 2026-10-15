// SILENT, and this file is the reason the rule is usable at all.
//
// A port and an environment are SUPPOSED to have defaults: neither
// authenticates anything, and every Node service in existence writes these two
// lines. A rule that reported them would be switched off within a day, and a
// rule nobody runs finds nothing — so the variable NAME is the gate, and none
// of the names here carries a credential word.
export const port = Number(process.env.PORT || 3000);
export const nodeEnv = process.env.NODE_ENV || 'development';
export const logLevel = process.env.LOG_LEVEL ?? 'info';
export const region = process.env.AWS_REGION || 'eu-central-1';
export const timeoutMs = Number(process.env.HTTP_TIMEOUT_MS ?? 5000);
export const baseUrl = process.env.API_BASE_URL || 'https://api.example.com';

// The one that made the last-segment veto necessary. `AUTH_URL` is NextAuth's
// own variable name and it holds this site's origin — a place, not a
// credential — and defaulting it to the production URL is deliberate. On
// a-real-app this single spelling was six of the rule's nine findings, in five
// different files, purely because `AUTH` is a substring of `AUTH_URL`.
export const authUrl = process.env.AUTH_URL ?? 'https://finance.example.com';
export const tokenEndpoint = process.env.OAUTH_TOKEN_ENDPOINT || 'https://id.example.com/token';
export const keyPath = process.env.SIGNING_KEY_PATH || '/etc/ssl/private/app.pem';

export async function health() {
  // An outbound call, again on purpose: these stay silent on the strength of
  // their names, not on the absence of a network path.
  return fetch(`${baseUrl}/health`);
}
