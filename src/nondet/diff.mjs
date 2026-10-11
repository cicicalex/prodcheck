/**
 * A minimal line diff for the nondeterminism report.
 *
 * The reader needs the first place two runs disagree, not a patch file. So:
 * trim the common prefix and suffix, run a plain LCS over what is left when it
 * is small enough, and print one hunk with a little context. When the middle is
 * too big for an O(n*m) table it is shown truncated instead — a diff that takes
 * longer than the runs it compares has stopped helping.
 */

const MAX_LCS_CELLS = 4_000_000;
const CONTEXT = 2;
const MAX_LINES = 40;

function splitLines(s) {
  if (s === '') return [];
  const lines = s.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** LCS edit script over two short arrays: [{op: ' '|'-'|'+', line}]. */
function lcsOps(a, b) {
  const n = a.length;
  const m = b.length;
  const table = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      table[i][j] = a[i] === b[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }
  const ops = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ op: ' ', line: a[i] });
      i++;
      j++;
    } else if (table[i + 1][j] >= table[i][j + 1]) {
      ops.push({ op: '-', line: a[i++] });
    } else {
      ops.push({ op: '+', line: b[j++] });
    }
  }
  while (i < n) ops.push({ op: '-', line: a[i++] });
  while (j < m) ops.push({ op: '+', line: b[j++] });
  return ops;
}

/**
 * @param {string} before  baseline text
 * @param {string} after   the other run's text
 * @returns {string} one hunk, `-` baseline / `+` other, or '' when equal
 */
export function minimalDiff(before, after) {
  if (before === after) return '';
  const a = splitLines(before);
  const b = splitLines(after);

  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }

  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);
  let ops;
  if ((midA.length + 1) * (midB.length + 1) <= MAX_LCS_CELLS) {
    ops = lcsOps(midA, midB);
  } else {
    ops = [...midA.map((line) => ({ op: '-', line })), ...midB.map((line) => ({ op: '+', line }))];
  }

  // Equal line lists but unequal strings: only the trailing newline moved.
  if (ops.length === 0) return `@@ line ${start + 1} @@\n(differs only in trailing newline)`;

  const ctxBefore = a.slice(Math.max(0, start - CONTEXT), start).map((line) => ({ op: ' ', line }));
  const ctxAfter = a.slice(endA, endA + CONTEXT).map((line) => ({ op: ' ', line }));
  const all = [...ctxBefore, ...ops, ...ctxAfter];

  const header = `@@ line ${start + 1} @@`;
  const body = all.slice(0, MAX_LINES).map((o) => `${o.op} ${o.line}`);
  if (all.length > MAX_LINES) body.push(`… ${all.length - MAX_LINES} more diff lines`);
  return [header, ...body].join('\n');
}
