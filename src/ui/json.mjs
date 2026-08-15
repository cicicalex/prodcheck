/**
 * Machine-readable output.
 *
 * This is not a debug dump — it is the tool's public API surface. Two very
 * different consumers depend on it and neither can be broken casually:
 * CI jobs that gate a deploy, and the MCP server that lets a coding agent run
 * the audit while the developer writes. Field names here are a contract.
 *
 * Design decisions worth keeping:
 *
 *   - `schemaVersion` comes first so a consumer can reject an unknown shape
 *     before parsing the rest, rather than silently reading absent fields.
 *   - `summary` is precomputed. A CI job should be able to gate on a number
 *     without reducing the findings array, and an agent should be able to
 *     decide "is this worth reading" from the first few hundred bytes.
 *   - Paths are POSIX and relative to `scan.root`. The tool is developed on
 *     Windows and mostly runs on Linux CI; emitting backslashes would make the
 *     same repository produce two different JSON outputs, which quietly breaks
 *     every diff, snapshot test and cache key downstream.
 *   - Every finding carries a `docs` URL. The agent path needs somewhere to
 *     send the model for the full explanation instead of inlining it.
 */

const SCHEMA_VERSION = 1;

/** Normalise a path for output: POSIX separators, no leading `./`. */
function posix(p) {
  return String(p).replace(/\\/g, '/').replace(/^\.\//, '');
}

function summarise(findings) {
  const summary = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) summary[f.severity] += 1;
  return summary;
}

/**
 * @param {object} result   same shape the terminal renderer consumes
 * @param {object} meta     {version, root, startedAt}
 * @returns {string} JSON, newline-terminated
 */
export function renderJson(result, meta = {}) {
  const { findings, filesScanned, durationMs } = result;
  const { version = '0.0.0', root = '.', startedAt = null } = meta;

  const payload = {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: 'prodcheck', version, vendor: 'Zero Point Logic' },
    scan: {
      root: posix(root),
      filesScanned,
      durationMs,
      startedAt,
    },
    summary: summarise(findings),
    findings: findings.map((f) => ({
      rule: f.rule,
      severity: f.severity,
      file: posix(f.file),
      line: f.line,
      column: f.column ?? null,
      impact: f.impact,
      fix: f.fix ? { remove: f.fix.remove ?? [], add: f.fix.add ?? [] } : null,
      docs: `https://zeropointlogic.io/prodcheck/rules/${f.rule}`,
    })),
  };

  // Two-space indent, not compact: humans read this output while debugging a
  // CI failure at least as often as machines parse it.
  return `${JSON.stringify(payload, null, 2)}\n`;
}

export { SCHEMA_VERSION };
