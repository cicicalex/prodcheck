/**
 * Report renderer.
 *
 * Layout contract, in priority order — this is the whole design:
 *
 *   1. Severity is a fixed-width column, not a sentence. The eye lands on what
 *      is burning without reading.
 *   2. The location gets its own line in `path:line` format, so terminals and
 *      editors linkify it. Buried mid-sentence, it is unclickable.
 *   3. The fix comes before the explanation. People want the patch, not the
 *      lecture. The prose stays underneath for whoever wants it.
 *   4. One summary line anchors the whole run. That line is what shows up in a
 *      screenshot, so it carries counts, scope and duration.
 *   5. The upsell is last and quiet — a single dim row after the value landed.
 */

import { SEVERITY, SEVERITY_COL, style, width, wrap, colorEnabled } from './theme.mjs';

const GUTTER = '  ';
const INDENT = ' '.repeat(GUTTER.length + 3); // aligns body under the severity label

/** Sort by severity, then by file, so repeat runs are diffable. */
function ordered(findings) {
  return [...findings].sort((a, b) => {
    const d = SEVERITY[a.severity].weight - SEVERITY[b.severity].weight;
    return d !== 0 ? d : a.file.localeCompare(b.file);
  });
}

function renderFinding(finding, out) {
  const sev = SEVERITY[finding.severity];
  const body = width() - INDENT.length;

  out.push(
    `${GUTTER}${sev.color(style.bold(`${sev.glyph} ${sev.label.padEnd(SEVERITY_COL)}`))}  ${style.bold(finding.rule)}`
  );
  out.push(`${INDENT}${style.cyan(`${finding.file}:${finding.line}`)}`);
  out.push('');

  // The patch first — truncated diffs are worse than none, so we print whole
  // lines and let the terminal soft-wrap rather than cutting mid-token.
  if (finding.fix) {
    for (const line of finding.fix.remove ?? []) out.push(`${INDENT}${style.red(`- ${line}`)}`);
    for (const line of finding.fix.add ?? []) out.push(`${INDENT}${style.green(`+ ${line}`)}`);
    out.push('');
  }

  for (const line of wrap(finding.impact, body)) out.push(`${INDENT}${style.dim(line)}`);
  out.push('');
}

/**
 * @param {object} result
 * @param {Array} result.findings   {severity, rule, file, line, impact, fix?}
 * @param {number} result.filesScanned
 * @param {number} result.durationMs
 * @param {number} [result.lockedChecks] checks available on the paid tier
 * @returns {string}
 */
export function renderReport(result) {
  const { findings, filesScanned, durationMs, lockedChecks = 0 } = result;
  const out = [''];

  if (!findings.length) {
    const tick = colorEnabled ? '✓' : 'OK';
    out.push(`${GUTTER}${style.green(style.bold(`${tick} clean`))}  no issues found`);
    out.push('');
    out.push(
      `${GUTTER}${style.dim(`${filesScanned} files · ${(durationMs / 1000).toFixed(1)}s`)}`
    );
    out.push('');
    return out.join('\n');
  }

  for (const finding of ordered(findings)) renderFinding(finding, out);

  // Rule uses box-drawing only when color is on; ASCII otherwise, because a
  // report piped into a plain-ASCII log should not sprout replacement glyphs.
  out.push(`${GUTTER}${style.dim((colorEnabled ? '─' : '-').repeat(width() - GUTTER.length))}`);

  const critical = findings.filter((f) => f.severity === 'critical').length;
  const parts = [
    style.bold(`${findings.length} ${findings.length === 1 ? 'issue' : 'issues'}`),
  ];
  if (critical) parts.push(style.red(style.bold(`${critical} critical`)));
  parts.push(`${filesScanned} files`);
  parts.push(style.green(`${(durationMs / 1000).toFixed(1)}s`));

  out.push(`${GUTTER}${parts.join(style.dim(' · '))}`);

  if (lockedChecks > 0) {
    out.push('');
    out.push(`${GUTTER}${style.dim(`→ ${lockedChecks} more checks designed, not built yet`)}`);
  }

  out.push('');
  return out.join('\n');
}

/**
 * Exit codes. Contract matters more than prettiness here: CI needs to fail the
 * build on findings, and needs to tell "found problems" apart from "the tool
 * itself broke". Conflating those two is the most common CLI design bug.
 *
 *   0 — clean
 *   1 — findings at or above the failure threshold
 *   2 — the scan itself failed (bad path, parse error, crash)
 */
export function exitCode(findings, threshold = 'high') {
  // 'never' means "report, but do not gate" — used by teams adopting the tool
  // on a legacy codebase where day-one findings should not block deploys.
  if (threshold === 'never') return 0;
  const limit = SEVERITY[threshold].weight;
  return findings.some((f) => SEVERITY[f.severity].weight <= limit) ? 1 : 0;
}
