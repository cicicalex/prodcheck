/**
 * Output for `prodcheck artifacts`: the report, the JSON, the help screen.
 *
 * Same layout contract as report.mjs — the location on its own line, one
 * summary row — with one rule added on top: a snippet is shown only as the
 * scanner redacted it. Nothing here ever reads a finding's unredacted value
 * (it is not enumerable and is never passed in), so no output path can print
 * a leaked token, user name or deny term in full.
 */

import { style, width, colorEnabled } from './theme.mjs';
import { DEFAULTS } from '../artifacts/scan.mjs';

const GUTTER = '  ';
const INDENT = '     ';
const ARTIFACT_SCHEMA_VERSION = 1;

export function locationText(f) {
  return [f.artifact, ...f.path].join('!');
}

const hex = (n) => `0x${n.toString(16)}`;

function where(f) {
  const at = f.where === 'content' ? 'offset' : f.where === 'header' ? 'entry header, container offset' : 'container offset';
  return `${at} ${f.offset} (${hex(f.offset)}) · ${f.encoding}`;
}

export function renderArtifactsReport(result) {
  const { findings, gaps, stats, allowed = 0, unusedAllow = [] } = result;
  const out = [''];
  const rule = () => out.push(`${GUTTER}${style.dim((colorEnabled ? '─' : '-').repeat(width() - GUTTER.length))}`);

  for (const f of findings) {
    out.push(`${GUTTER}${style.yellow(style.bold('!  LEAK'))}  ${style.bold(f.rule)}`);
    out.push(`${INDENT}${style.cyan(locationText(f))}`);
    out.push(`${INDENT}${style.dim(where(f))}`);
    out.push(`${INDENT}${f.snippet}`);
    out.push('');
  }

  if (gaps.length) {
    out.push(`${GUTTER}${style.magenta(style.bold(`?  NOT SCANNED (${gaps.length})`))}`);
    for (const g of gaps) {
      out.push(`${INDENT}${style.cyan([g.artifact, ...g.path].join('!'))}`);
      out.push(`${INDENT}${style.dim(g.reason)}`);
    }
    out.push('');
  }

  if (!findings.length && !gaps.length) {
    const tick = colorEnabled ? '✓' : 'OK';
    out.push(`${GUTTER}${style.green(style.bold(`${tick} clean`))}  nothing found in the shipped bytes`);
    out.push('');
  } else {
    rule();
  }

  const parts = [];
  if (findings.length) parts.push(style.red(style.bold(`${findings.length} ${findings.length === 1 ? 'finding' : 'findings'}`)));
  if (gaps.length) parts.push(style.magenta(`${gaps.length} not scanned`));
  parts.push(`${stats.artifacts} ${stats.artifacts === 1 ? 'artifact' : 'artifacts'}`);
  parts.push(`${stats.objects} objects`);
  parts.push(`${(stats.bytes / 1024 / 1024).toFixed(1)} MiB`);
  parts.push(style.green(`${(stats.durationMs / 1000).toFixed(1)}s`));
  out.push(`${GUTTER}${parts.join(style.dim(' · '))}`);
  if (allowed) out.push(`${GUTTER}${style.dim(`${allowed} more allowed by the allow-list`)}`);
  if (unusedAllow.length) {
    out.push(`${GUTTER}${style.dim(`allow-list lines that matched nothing: ${unusedAllow.join(', ')}`)}`);
  }
  if (gaps.length && !findings.length) {
    out.push(`${GUTTER}${style.dim('not clean: something above was not read (exit 3; --allow-gaps accepts it)')}`);
  }
  out.push('');
  return out.join('\n');
}

export function renderArtifactsJson(result, meta = {}) {
  const { findings, gaps, stats, allowed = 0, unusedAllow = [], denyTerms = 0 } = result;
  const { version = '0.0.0', inputs = [], startedAt = null, maxDepth = null } = meta;
  const byRule = {};
  for (const f of findings) byRule[f.rule] = (byRule[f.rule] ?? 0) + 1;
  const payload = {
    schemaVersion: ARTIFACT_SCHEMA_VERSION,
    tool: { name: 'prodcheck', version, vendor: 'Zero Point Logic' },
    scan: {
      kind: 'artifacts',
      inputs: inputs.map((p) => String(p).replace(/\\/g, '/')),
      artifacts: stats.artifacts,
      objects: stats.objects,
      bytes: stats.bytes,
      durationMs: stats.durationMs,
      startedAt,
      maxDepth,
      denyTerms, // a count: the terms themselves never leave memory
    },
    summary: { total: findings.length, byRule, allowed, gaps: gaps.length, unusedAllowLines: unusedAllow },
    findings: findings.map((f) => ({
      rule: f.rule,
      artifact: f.artifact,
      path: f.path,
      where: f.where,
      offset: f.offset,
      encoding: f.encoding,
      snippet: f.snippet,
      ...(f.term != null ? { denyTermLine: f.term } : {}),
    })),
    gaps: gaps.map((g) => ({ artifact: g.artifact, path: g.path, reason: g.reason })),
  };
  return `${JSON.stringify(payload, null, 2)}\n`;
}

export function renderArtifactsHelp(version = '0.0.0') {
  const h = (s) => style.dim(s.toUpperCase());
  const flag = (s) => style.bold(s);
  return `
${style.bold('prodcheck artifacts')} ${style.dim(`v${version}`)} — scan the bytes you ship, not the source

${h('usage')}
  prodcheck artifacts <artifact|dir>... [options]

${h('examples')}
  ${style.cyan('prodcheck artifacts dist/')}                         every file under dist/
  ${style.cyan('prodcheck artifacts app.iso pkg.tgz --json')}        machine-readable
  ${style.cyan('prodcheck artifacts dist/ --deny-terms ~/deny.txt')}  plus your own terms

${h('options')}
  ${flag('--deny-terms <file>')}  extra terms, one per line ${style.dim('(keep it out of the repo)')}
  ${flag('--allow <file>')}       known false positives: <glob> <rule> [pattern]
  ${flag('--max-depth <n>')}      nested-container limit ${style.dim(`[default: ${DEFAULTS.maxDepth}]`)}
  ${flag('--max-inflate-mb <n>')} per-entry decompression cap ${style.dim(`[default: ${DEFAULTS.maxInflate / 1024 / 1024}]`)}
  ${flag('--allow-gaps')}         exit 0, not 3, when something could not be read
  ${flag('--json')}               emit JSON instead of the report
  ${flag('--no-color')}           disable colour

${h('exit codes')}
  ${style.green('0')} clean  ${style.yellow('1')} findings  ${style.red('2')} scan failed  ${style.magenta('3')} not everything was read
`;
}
