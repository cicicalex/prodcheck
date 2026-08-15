// SILENT. Every fallback here fails loudly the first time it is used, which is
// the behaviour this rule asks for — reporting it would be reporting somebody
// for having already applied the fix.
//
// `''` is falsy: the SDK throws exactly as if the variable were absent. The
// placeholders are worse than useless as credentials and better than useless as
// signals — a request signed with CHANGEME comes back 401 on the first call in
// staging, which is a Tuesday-afternoon fix rather than an invoice.
export const apiKey = process.env.API_KEY || '';
export const authToken = process.env.AUTH_TOKEN ?? '';
export const dbPassword = process.env.DB_PASSWORD || 'CHANGEME';
export const signingSecret = process.env.SIGNING_SECRET || 'REPLACE_ME';
export const dsn = process.env.SENTRY_DSN ?? 'undefined';

export async function ping(host) {
  // An outbound call IS present, so nothing about the file is what keeps these
  // quiet — only the values are.
  return fetch(`https://${host}/v1/ping`, { headers: { authorization: apiKey } });
}
