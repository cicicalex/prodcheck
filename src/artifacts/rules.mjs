/**
 * What the artifact scanner looks for, and how each match is redacted.
 *
 * Every rule runs over two kinds of text cut from the same bytes (see
 * scan.mjs): an 8-bit channel, where one byte is one character and the offset
 * of a match IS its byte offset, and a UTF-16LE channel, where a match at
 * character i sits at byte 2·i. A rule therefore never sees an encoding — only
 * a string — and the scanner turns its index back into bytes.
 *
 * A rule is {id, title, re, keep?, redact}:
 *
 *   re      a global regex. Every quantifier is bounded, so no match can be
 *           longer than the overlap the chunked reader keeps between chunks.
 *   keep    optional veto over a match: placeholders such as `C:\Users\<name>\`
 *           or `icon@2x.png` look like the real thing and are not.
 *   redact  what the report may show in place of the match. The report never
 *           prints a matched value whole — a scanner that copies the leaked
 *           user name or token into a public CI log has re-leaked it.
 */

/** A path separator as it appears in bytes: `\`, an escaped `\\`, or `/`. */
const SEP = String.raw`(?:\\{1,2}|/)`;

/** Directory names that are part of the OS layout, not anybody's account. */
const GENERIC_HOMES = new Set([
  'public',
  'default',
  'default user',
  'all users',
  'shared',
  'username',
  'user_name',
  'yourname',
  'your_name',
  'yourusername',
  'your_username',
  'me',
  'someone',
  'foo',
  'example',
]);

/**
 * A home-directory name that is a placeholder rather than an account:
 * `<name>`, `%USERNAME%`, `$USER`, `${user}`, `{user}`, `[user]`, `*`, `...`.
 */
function isPlaceholderName(name) {
  if (/^[<%$\[{*.~]/.test(name)) return true;
  return GENERIC_HOMES.has(name.toLowerCase());
}

/** First character if it is plain ASCII, then a fixed mask: length is not shown. */
export function mask(value) {
  const first = value[0] && /[A-Za-z0-9]/.test(value[0]) ? value[0] : '';
  return `${first}***`;
}

/** Keep a fixed prefix of a token (its type marker), mask the rest. */
const prefixMask = (n) => (m) => `${m[0].slice(0, n)}***`;

/** Image density suffixes and file extensions that make `x@y.z` not an e-mail. */
const NOT_A_DOMAIN = /^\d+x\.|\.(?:png|jpe?g|gif|svg|webp|ico|js|mjs|cjs|ts|css|map|json|html?)$/i;
const DOC_DOMAINS = /(?:^|\.)(?:example\.(?:com|org|net)|localhost)$/i;

export const RULES = [
  {
    id: 'windows-home-path',
    title: 'Windows user profile path (C:\\Users\\<name>\\)',
    // The name may contain spaces ("John Smith") but may not start with one,
    // and must be closed by a separator: `C:\Users\` followed by prose is not
    // a path into somebody's profile. Nothing is required BEFORE the drive
    // letter: compilers pack string constants back to back with no separator
    // (Rust's panic locations among them), so `…valueC:\Users\…` is the
    // shape the incident this scanner exists for actually had.
    re: new RegExp(
      String.raw`([A-Za-z]:${SEP}+Users${SEP}+)([^\\/\x00-\x20"*:<>?|][^\\/\x00-\x1f"*:<>?|]{0,63})(${SEP})`,
      'gi'
    ),
    keep: (m) => !isPlaceholderName(m[2].trimEnd()),
    redact: (m) => `${m[1]}${mask(m[2])}${m[3]}`,
  },
  {
    id: 'unix-home-path',
    title: 'Unix home path (/home/<name>/, /Users/<name>/)',
    // Case-sensitive on purpose: macOS writes `/Users/`, and `/users/` is far
    // more often a URL route than a home directory. The one context excluded
    // is a URL (`https://example.com/home/x/`); a word character in front is
    // not, for the same packed-strings reason as windows-home-path.
    // A drive letter in front makes it windows-home-path's (`C:/Users/<name>/`).
    re: /(?<!(?:https?|ftp|wss?):\/\/[^\s"'<>]{0,256})(?<![A-Za-z]:)(\/(?:home|Users)\/)([^/\x00-\x20"'<>|:*?\\]{1,64})(\/)/g,
    keep: (m) => !isPlaceholderName(m[2]),
    redact: (m) => `${m[1]}${mask(m[2])}${m[3]}`,
  },
  {
    id: 'email-address',
    title: 'E-mail address',
    // Shaped to stay quiet on binary noise, where `x@G.Gaf` turns up every few
    // dozen megabytes: two or more characters before the @, a label of two or
    // more before the top-level domain, and a TLD in one case — real TLDs are
    // written `com` or `COM`, random bytes write `Gaf`.
    re: /(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9._%+-]{1,63})@((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){0,7}[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.(?:[a-z]{2,24}|[A-Z]{2,24}))(?![A-Za-z0-9-])/g,
    keep: (m) =>
      !NOT_A_DOMAIN.test(m[2]) && !DOC_DOMAINS.test(m[2]) && m[1].toLowerCase() !== 'git',
    redact: (m) => `${mask(m[1])}@${m[2]}`,
  },
  {
    id: 'aws-access-key-id',
    title: 'AWS access key ID',
    re: /(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|AKPA|ANPA|ANVA|AROA|APKA|ASCA)[A-Z0-9]{16}(?![A-Z0-9])/g,
    redact: prefixMask(4),
  },
  {
    id: 'aws-secret-access-key',
    title: 'AWS secret access key assignment',
    re: /(aws_?secret_?access_?key["']?\s{0,4}[:=]\s{0,4}["']?)([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi,
    redact: (m) => `${m[1]}***`,
  },
  {
    id: 'github-token',
    title: 'GitHub token (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)',
    re: /(?<![A-Za-z0-9_])(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,240})(?![A-Za-z0-9_])/g,
    redact: (m) => `${m[0].slice(0, m[0].indexOf('_', 3) + 1)}***`,
  },
  {
    id: 'private-key',
    title: 'PEM private key block',
    // The header alone, whatever precedes PRIVATE KEY (RSA, EC, OPENSSH,
    // ENCRYPTED, PGP … BLOCK). The header is not secret and is shown; what
    // follows it is, and the snippet masks it like any other long run.
    re: /-----BEGIN (?:[A-Z0-9]{1,12} ){0,4}PRIVATE KEY(?: BLOCK)?-----/g,
    redact: (m) => m[0],
  },
  {
    id: 'jwt',
    title: 'JSON Web Token',
    re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,1024}\.eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{0,1024}/g,
    redact: () => 'eyJ***',
  },
  {
    id: 'npm-token',
    title: 'npm access token',
    re: /(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g,
    redact: prefixMask(4),
  },
  {
    id: 'slack-token',
    title: 'Slack token',
    re: /(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,200}/g,
    redact: prefixMask(5),
  },
  {
    id: 'stripe-live-key',
    title: 'Stripe live secret or restricted key',
    re: /(?<![A-Za-z0-9])(?:sk|rk)_live_[A-Za-z0-9]{16,247}(?![A-Za-z0-9])/g,
    redact: prefixMask(8),
  },
  {
    id: 'google-api-key',
    title: 'Google API key',
    re: /(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g,
    redact: prefixMask(4),
  },
];

export const DENY_RULE = 'deny-term';

/** Every id an allow-list line may name; `*` means any of them. */
export const RULE_IDS = new Set([...RULES.map((r) => r.id), DENY_RULE]);

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/**
 * Turn the deny-terms list into one rule per channel.
 *
 * The terms are the most sensitive input the scanner ever takes — they are
 * what the user is afraid of leaking — so they live only in memory: never
 * echoed, never in a snippet, and a finding names a term by its line number
 * in the file, not by its text.
 *
 * On the 8-bit channel a term is matched as its UTF-8 bytes (each byte one
 * latin1 character), which is how it sits in a UTF-8 file or binary. On the
 * UTF-16 channel it is matched as itself. Both case-insensitively.
 */
export function denyRules(terms) {
  if (!terms.length) return null;
  const byKey = { bytes: new Map(), utf16: new Map() };
  const alt = { bytes: [], utf16: [] };
  terms.forEach(({ term, line }) => {
    const bytes = Buffer.from(term, 'utf8').toString('latin1');
    if (!byKey.bytes.has(bytes.toLowerCase())) {
      byKey.bytes.set(bytes.toLowerCase(), line);
      alt.bytes.push(escapeRe(bytes));
    }
    if (!byKey.utf16.has(term.toLowerCase())) {
      byKey.utf16.set(term.toLowerCase(), line);
      alt.utf16.push(escapeRe(term));
    }
  });
  // Longest first, so `alexandra` is not reported as `alex` followed by noise.
  const sorted = (xs) => [...xs].sort((a, b) => b.length - a.length).join('|');
  const make = (channel, flags) => ({
    id: DENY_RULE,
    title: 'Term from the deny-terms file',
    re: new RegExp(sorted(alt[channel]), flags),
    term: (m) => byKey[channel].get(m[0].toLowerCase()) ?? null,
    redact: (m) => `[deny-term line ${byKey[channel].get(m[0].toLowerCase()) ?? '?'}]`,
  });
  return { bytes: make('bytes', 'gi'), utf16: make('utf16', 'giu') };
}
