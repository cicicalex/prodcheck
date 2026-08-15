/**
 * Terminal design tokens.
 *
 * Design rule that drives this whole file: we use the 16 base ANSI colors and
 * the dim/bold attributes — never truecolor hex. Hex looks great in the
 * terminal you developed in and becomes illegible in everyone else's. The 16
 * base colors are remapped by each terminal theme precisely so they stay
 * readable against that theme's own background, light or dark. We are handing
 * the contrast problem to the only component that can actually solve it.
 *
 * Severity is never encoded by color alone: every level also carries a distinct
 * ASCII glyph, so the report survives NO_COLOR, CI logs, piping to a file, and
 * colorblind readers. Glyphs are ASCII rather than emoji because emoji have
 * inconsistent display width and break column alignment.
 */

const ESC = '\x1b[';

/** Detect whether we may emit color at all. */
function detectColor() {
  const env = process.env;

  // FORCE_COLOR is checked first, and deliberately so: it is the user's
  // explicit override, and Node core plus chalk both give it precedence over
  // NO_COLOR. Matching the ecosystem matters more here than the letter of
  // no-color.org — a CLI that disagrees with `node` about its own env vars is
  // a CLI people file bugs against.
  if (env.FORCE_COLOR) return env.FORCE_COLOR !== '0';
  // https://no-color.org — any non-empty value disables color.
  if (env.NO_COLOR) return false;
  if (env.TERM === 'dumb') return false;

  // Piped or redirected: emit plain text so grep/diff/logs stay clean.
  return Boolean(process.stdout.isTTY);
}

const COLOR = detectColor();

/** Wrap `s` in an SGR sequence, or return it untouched when color is off. */
const sgr = (open, close) => (s) => (COLOR ? `${ESC}${open}m${s}${ESC}${close}m` : s);

export const style = {
  bold: sgr(1, 22),
  dim: sgr(2, 22),
  red: sgr(31, 39),
  green: sgr(32, 39),
  yellow: sgr(33, 39),
  blue: sgr(34, 39),
  magenta: sgr(35, 39),
  cyan: sgr(36, 39),
};

/**
 * Severity tokens.
 *
 * `weight` orders findings — the reader should hit the thing that is on fire
 * first, and never have to scan for it.
 */
export const SEVERITY = {
  critical: { label: 'CRITICAL', glyph: '!!', color: style.red, weight: 0 },
  high: { label: 'HIGH', glyph: '! ', color: style.yellow, weight: 1 },
  medium: { label: 'MEDIUM', glyph: '~ ', color: style.blue, weight: 2 },
  low: { label: 'LOW', glyph: '- ', color: style.dim, weight: 3 },
};

/** Widest label, so the title column starts at the same offset on every row. */
export const SEVERITY_COL = Math.max(...Object.values(SEVERITY).map((s) => s.label.length));

export const colorEnabled = COLOR;

/**
 * Usable width. Capped at 76 even on wide terminals: long measure is hard to
 * read, and a report that stays under 80 columns pastes cleanly into a GitHub
 * issue, a Slack message, or a Hacker News comment without wrapping.
 */
export function width() {
  const cols = process.stdout.columns || 80;
  return Math.max(40, Math.min(cols, 76));
}

/** Greedy word wrap. Returns an array of lines, never pre-indented. */
export function wrap(text, max) {
  const words = String(text).split(/\s+/).filter(Boolean);
  const lines = [];
  let line = '';

  for (const word of words) {
    if (!line.length) {
      line = word;
    } else if (line.length + 1 + word.length <= max) {
      line += ` ${word}`;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line.length) lines.push(line);
  return lines;
}
