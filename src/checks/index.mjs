/**
 * The check registry.
 *
 * Array order is the rule-table order — docs, README and the report all list
 * rules in this sequence, so a new check is appended, never inserted. Each
 * entry exposes the same surface: {rule, extensions, isCandidate, check}.
 * The CLI iterates this array and knows nothing about individual rules.
 *
 * ── the optional two-phase contract ─────────────────────────────────────────
 *
 * Some bugs are invisible to `check(file)` because they live in the seam
 * between two files: a helper module resolves a value, a route module misuses
 * it, and neither half is wrong on its own. A check MAY opt into a second
 * phase to see them. Both members are optional and independent, and a check
 * that exports neither — webhook-swallows-2xx — behaves exactly as it always
 * has, single-file and phase-1 only.
 *
 *   collect(file) -> facts | null
 *     Called during the walk, once per file the check claims, alongside
 *     `check(file)`. Returns serialisable facts about THAT file: no findings,
 *     no cross-file conclusions, nothing that depends on a file the walk has
 *     not reached yet. Returning null means "this file contributes nothing".
 *
 *   finalize(factsByFile) -> findings[]
 *     Called once, after the walk, with a Map of relative POSIX path -> the
 *     facts `collect` returned for it, in walk order. Returns extra findings in
 *     the same shape `check` produces. The CLI dedupes findings by
 *     (rule, file, line) and re-sorts, so a finding a cross-file join arrives
 *     at independently of `check` — the same read, the same line — collapses
 *     into one rather than being reported twice.
 */

import * as webhookSwallows from './webhook-swallows-2xx.mjs';
import * as rateLimitBypass from './rate-limit-bypass.mjs';

export const checks = [webhookSwallows, rateLimitBypass];

/**
 * How many of the seven-rule design are NOT in `checks` above. The report
 * renders it as the single quiet upsell row after the findings — "→ N more
 * checks" — so the arithmetic has to hold: `checks.length + LOCKED_PAID_CHECKS`
 * is the size of the design, and every rule is in exactly one of the two.
 *
 * Two ship (both MIT, both in this array). Five do not exist yet:
 * 2fa-skips-api, account-delete-blocked, migrations-not-replayable,
 * backup-unencrypted, quota-per-key. This was 4 while the README also claimed
 * three shipped free — 3 + 4 = 7 was the only true statement in the pair, and
 * the code disagreed with it. Appending a check here means decrementing this.
 */
export const LOCKED_PAID_CHECKS = 7 - checks.length;
