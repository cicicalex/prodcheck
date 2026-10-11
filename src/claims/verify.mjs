/**
 * PAGE CLAIMS = SHIPPED BYTES.
 *
 * A store page makes promises about an archive: how many icons, which sizes,
 * how big, what is and is not inside, and in what words. This module checks a
 * claims file — those promises written down — against the manifest built from
 * the actual bytes (source.mjs), and against the page text itself.
 *
 * Three rules shape every check here:
 *
 *   1. Every claim reports PASS or FAIL with what was expected and what was
 *      found. Never a bare boolean: the person fixing the page needs the
 *      number to put on it.
 *   2. A claim with nothing to check is a FAIL, not a vacuous PASS. A group
 *      glob that matches no files, a page-count pattern that is not on the
 *      page, a dimensions claim with no images: each would otherwise be a
 *      green line that proves nothing, which is the failure this tool exists
 *      to catch.
 *   3. The claims file is parsed strictly. An unknown key is an error, so a
 *      typo (`"forbiden"`) stops the run instead of silently checking less.
 */

import { compileGlob } from './glob.mjs';
import { IMAGE_EXTENSIONS } from './imagesize.mjs';

export const SCHEMA_VERSION = 1;

// ---------------------------------------------------------------- parsing

const SHAPE = {
  schemaVersion: 'number',
  description: 'string',
  files: { total: 'count', byExtension: 'countMap', exhaustive: 'boolean' },
  groups: 'groups',
  totalBytes: 'count',
  paths: { required: 'strings', forbidden: 'strings' },
  names: { asciiOnly: 'boolean', forbiddenRegex: 'strings' },
  docs: { license: 'boolean', readme: 'boolean' },
  images: { contentMatchesExtension: 'boolean' },
  page: { required: 'strings', forbidden: 'strings', counts: 'pageCounts', dimensionsExist: 'boolean' },
};
const GROUP_KEYS = new Set(['name', 'glob', 'count', 'dimensions']);
const PAGE_COUNT_KEYS = new Set(['regex', 'group', 'extension', 'total']);

const UNITS = { b: 1, kb: 1e3, mb: 1e6, gb: 1e9, kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3 };

/** `1200`, `"1.5 MB"`, `"3 MiB"` -> bytes. */
export function parseBytes(v, where) {
  if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return v;
  const m = typeof v === 'string' && /^\s*(\d+(?:\.\d+)?)\s*([kmg]i?b|b)?\s*$/i.exec(v);
  if (!m) throw new Error(`${where}: expected a number or a size like "12 MB", got ${JSON.stringify(v)}`);
  return Math.round(Number(m[1]) * UNITS[(m[2] ?? 'b').toLowerCase()]);
}

/** A count is an exact number or {min, max}; returns {min, max}. */
function parseRange(v, where, bytes = false) {
  const one = (x, w) => {
    if (bytes) return parseBytes(x, w);
    if (!Number.isInteger(x) || x < 0) throw new Error(`${w}: expected a non-negative integer, got ${JSON.stringify(x)}`);
    return x;
  };
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
    for (const k of Object.keys(v)) if (k !== 'min' && k !== 'max') throw new Error(`${where}: unknown key "${k}"`);
    if (v.min === undefined && v.max === undefined) throw new Error(`${where}: needs min, max, or both`);
    const r = {
      min: v.min === undefined ? 0 : one(v.min, `${where}.min`),
      max: v.max === undefined ? Infinity : one(v.max, `${where}.max`),
    };
    if (r.min > r.max) throw new Error(`${where}: min is greater than max`);
    return r;
  }
  const n = one(v, where);
  return { min: n, max: n };
}

function parseDimension(s, where) {
  const m = typeof s === 'string' && /^\s*(\d+)\s*[x×]\s*(\d+)\s*$/i.exec(s);
  if (!m) throw new Error(`${where}: expected "WIDTHxHEIGHT", got ${JSON.stringify(s)}`);
  return `${Number(m[1])}x${Number(m[2])}`;
}

function strings(v, where) {
  if (!Array.isArray(v) || v.some((s) => typeof s !== 'string' || s === '')) {
    throw new Error(`${where}: expected an array of non-empty strings`);
  }
  return v;
}

function regex(src, where, flags) {
  try {
    return new RegExp(src, flags);
  } catch (err) {
    throw new Error(`${where}: invalid regex (${err.message})`);
  }
}

/**
 * Validate and normalise a parsed claims object. Throws on any unknown key or
 * malformed value; the message names the exact path.
 */
export function parseClaims(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('claims: expected a JSON object');
  const out = {};
  for (const [key, value] of Object.entries(raw)) {
    const shape = SHAPE[key];
    if (shape === undefined) throw new Error(`claims: unknown key "${key}"`);
    if (key === 'schemaVersion') {
      if (value !== SCHEMA_VERSION) throw new Error(`claims.schemaVersion: only ${SCHEMA_VERSION} is supported`);
      continue;
    }
    if (key === 'description') continue;
    if (key === 'totalBytes') {
      out.totalBytes = parseRange(value, 'claims.totalBytes', true);
      continue;
    }
    if (key === 'groups') {
      if (!Array.isArray(value)) throw new Error('claims.groups: expected an array');
      const names = new Set();
      out.groups = value.map((g, i) => {
        const w = `claims.groups[${i}]`;
        if (g === null || typeof g !== 'object') throw new Error(`${w}: expected an object`);
        for (const k of Object.keys(g)) if (!GROUP_KEYS.has(k)) throw new Error(`${w}: unknown key "${k}"`);
        if (typeof g.name !== 'string' || !g.name) throw new Error(`${w}.name: required`);
        if (names.has(g.name)) throw new Error(`${w}.name: duplicate group name "${g.name}"`);
        names.add(g.name);
        if (typeof g.glob !== 'string') throw new Error(`${w}.glob: required`);
        if (g.count === undefined && g.dimensions === undefined) throw new Error(`${w}: needs count, dimensions, or both`);
        let dims;
        if (g.dimensions !== undefined) {
          const list = typeof g.dimensions === 'string' ? [g.dimensions] : g.dimensions;
          if (!Array.isArray(list) || list.length === 0) throw new Error(`${w}.dimensions: expected a non-empty list`);
          dims = [...new Set(list.map((d, j) => parseDimension(d, `${w}.dimensions[${j}]`)))];
        }
        return {
          name: g.name,
          glob: g.glob,
          matcher: compileGlob(g.glob),
          count: g.count === undefined ? undefined : parseRange(g.count, `${w}.count`),
          dimensions: dims,
        };
      });
      continue;
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`claims.${key}: expected an object`);
    out[key] = {};
    for (const [sub, v] of Object.entries(value)) {
      const kind = shape[sub];
      const w = `claims.${key}.${sub}`;
      if (kind === undefined) throw new Error(`claims.${key}: unknown key "${sub}"`);
      if (kind === 'boolean') {
        if (typeof v !== 'boolean') throw new Error(`${w}: expected true or false`);
        out[key][sub] = v;
      } else if (kind === 'count') out[key][sub] = parseRange(v, w);
      else if (kind === 'strings') out[key][sub] = strings(v, w);
      else if (kind === 'countMap') {
        if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error(`${w}: expected an object`);
        out[key][sub] = Object.fromEntries(
          Object.entries(v).map(([ext, n]) => [ext.replace(/^\./, '').toLowerCase(), parseRange(n, `${w}.${ext}`)])
        );
      } else if (kind === 'pageCounts') {
        if (!Array.isArray(v)) throw new Error(`${w}: expected an array`);
        out[key][sub] = v.map((c, i) => {
          const cw = `${w}[${i}]`;
          if (c === null || typeof c !== 'object') throw new Error(`${cw}: expected an object`);
          for (const k of Object.keys(c)) if (!PAGE_COUNT_KEYS.has(k)) throw new Error(`${cw}: unknown key "${k}"`);
          if (typeof c.regex !== 'string') throw new Error(`${cw}.regex: required`);
          const re = regex(c.regex, `${cw}.regex`, 'giu');
          if (new RegExp(`${re.source}|`, 'u').exec('').length < 2) {
            throw new Error(`${cw}.regex: needs a capture group around the number`);
          }
          const targets = ['group', 'extension', 'total'].filter((k) => c[k] !== undefined);
          if (targets.length !== 1) throw new Error(`${cw}: needs exactly one of group, extension, total`);
          if (c.total !== undefined && c.total !== true) throw new Error(`${cw}.total: must be true`);
          return { ...c, re, extension: c.extension?.replace(/^\./, '').toLowerCase() };
        });
      }
    }
    if (key === 'names' && out.names.forbiddenRegex) {
      out.names.forbiddenRegexCompiled = out.names.forbiddenRegex.map((s, i) => regex(s, `claims.names.forbiddenRegex[${i}]`, 'iu'));
    }
    if (key === 'paths') {
      for (const list of ['required', 'forbidden']) {
        for (const [i, g] of (out.paths[list] ?? []).entries()) {
          try {
            compileGlob(g);
          } catch (err) {
            throw new Error(`claims.paths.${list}[${i}]: ${err.message}`);
          }
        }
      }
    }
  }
  for (const c of out.page?.counts ?? []) {
    if (c.group !== undefined && !out.groups?.some((g) => g.name === c.group)) {
      throw new Error(`claims.page.counts: group "${c.group}" is not defined in claims.groups`);
    }
  }
  return out;
}

// ---------------------------------------------------------------- page text

/** Strip an HTML page to its visible text. Deliberately simple; see README. */
export function htmlToText(html) {
  const entities = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  return html
    .replace(/<(script|style|template)\b[\s\S]*?<\/\1\s*>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
      if (e[0] === '#') {
        const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return Number.isFinite(cp) && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
      }
      return entities[e.toLowerCase()] ?? m;
    });
}

/**
 * Case-, width- and punctuation-folded text for phrase matching: "No‑AI",
 * "no  AI" and "ＮＯ ＡＩ" all read as "no ai". Hyphens fold to spaces on
 * purpose — a forbidden phrase must not slip through on a dash.
 */
export function foldText(s) {
  return s
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[‘’‚‛′]/g, "'")
    .replace(/[“”„‟″]/g, '"')
    .replace(/[-‐-―−_]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Every whole-word occurrence of `phrase` in folded `text`, with context. */
function findPhrase(text, phrase) {
  const p = foldText(phrase);
  const esc = p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?<![\\p{L}\\p{N}])${esc}(?![\\p{L}\\p{N}])`, 'gu');
  const hits = [];
  for (const m of text.matchAll(re)) {
    hits.push(`…${text.slice(Math.max(0, m.index - 30), m.index + p.length + 30)}…`);
  }
  return hits;
}

function parseNumber(s) {
  return Number(s.replace(/[\s,_'  .]/g, ''));
}

// ---------------------------------------------------------------- verifying

/** Every file and folder as {path, name}; folders carry a trailing slash. */
function namesOf({ files, dirs }) {
  const base = (p) => p.slice(p.lastIndexOf('/') + 1);
  return [...dirs.map((d) => ({ path: `${d}/`, name: base(d) })), ...files.map((f) => ({ path: f.path, name: base(f.path) }))];
}

/** Paths whose name is not printable ASCII — the deterministic stand-in for "English names". */
export function nonAsciiNames(source) {
  return namesOf(source).filter((n) => /[^\x20-\x7e]/.test(n.name)).map((n) => n.path);
}

/** One line per file whose image content and extension disagree. */
export function imageMismatches(files) {
  const bad = [];
  for (const f of files) {
    const want = IMAGE_EXTENSIONS[f.ext];
    if (want && f.image?.format !== want) bad.push(`${f.path}: named .${f.ext}, content is ${f.image?.format ?? 'not an image'}`);
    else if (!want && f.image) bad.push(`${f.path}: content is ${f.image.format}, name says .${f.ext || '(none)'}`);
  }
  return bad;
}

/** Basenames that count as a licence / readme for the `docs` claims. */
export const DOC_PATTERNS = { license: /^(licen[cs]e|copying|eula)([-_. ][^/]*)?$/i, readme: /^read[-_ ]?me([-_. ][^/]*)?$/i };

const fmtRange = (r, unit = '') => {
  const u = (n) => `${n.toLocaleString('en-US')}${unit}`;
  if (r.min === r.max) return u(r.min);
  if (r.max === Infinity) return `>= ${u(r.min)}`;
  if (r.min === 0) return `<= ${u(r.max)}`;
  return `${u(r.min)} .. ${u(r.max)}`;
};
const inRange = (n, r) => n >= r.min && n <= r.max;
const dimOf = (img) => (img && img.width !== null ? `${img.width}x${img.height}` : null);

/**
 * @param {object} claims  output of parseClaims
 * @param {object} source  output of loadSource
 * @param {string|null} pageText  raw page text (already HTML-stripped if needed)
 * @returns {Array<{id, claim, status, expected, actual, details}>}
 */
export function verifyClaims(claims, source, pageText = null) {
  const results = [];
  const add = (id, claim, ok, expected, actual, details = []) =>
    results.push({ id, claim, status: ok ? 'PASS' : 'FAIL', expected, actual, details });

  const { files, dirs } = source;
  const byExt = new Map();
  for (const f of files) byExt.set(f.ext, (byExt.get(f.ext) ?? 0) + 1);
  const extLabel = (e) => (e ? `.${e}` : '(no extension)');

  // Always on: the bytes must be readable before anything about them is true.
  add(
    'integrity',
    `${source.kind} is readable and self-consistent`,
    source.problems.length === 0,
    'no integrity problems',
    source.problems.length === 0 ? 'none' : `${source.problems.length} problem(s)`,
    source.problems
  );

  if (claims.files?.total) {
    const r = claims.files.total;
    add('files.total', 'total number of files', inRange(files.length, r), fmtRange(r), String(files.length));
  }
  for (const [ext, r] of Object.entries(claims.files?.byExtension ?? {})) {
    const n = byExt.get(ext) ?? 0;
    add(`files.byExtension.${ext || '(none)'}`, `number of ${extLabel(ext)} files`, inRange(n, r), fmtRange(r), String(n));
  }
  if (claims.files?.exhaustive) {
    const listed = new Set(Object.keys(claims.files.byExtension ?? {}));
    const extra = files.filter((f) => !listed.has(f.ext));
    add(
      'files.exhaustive',
      'no file types beyond those listed in byExtension',
      extra.length === 0,
      listed.size ? [...listed].map(extLabel).join(', ') : '(none listed)',
      extra.length === 0 ? 'no other types' : `${extra.length} other file(s)`,
      extra.map((f) => f.path)
    );
  }

  const groupCounts = new Map();
  for (const g of claims.groups ?? []) {
    const members = files.filter((f) => g.matcher.test(f.path, false));
    groupCounts.set(g.name, members.length);
    if (g.count) {
      add(`groups.${g.name}.count`, `"${g.name}" (${g.glob}) file count`, inRange(members.length, g.count), fmtRange(g.count), String(members.length));
    }
    if (g.dimensions) {
      const allowed = new Set(g.dimensions);
      const seen = new Map();
      const bad = [];
      for (const f of members) {
        const d = dimOf(f.image);
        if (d === null) bad.push(`${f.path}: ${f.image ? `unreadable ${f.image.format} header` : 'not a PNG/GIF/WebP/JPEG image'}`);
        else {
          seen.set(d, (seen.get(d) ?? 0) + 1);
          if (!allowed.has(d)) bad.push(`${f.path}: ${d}`);
        }
      }
      const missing = g.dimensions.filter((d) => !seen.has(d));
      const actual = members.length === 0
        ? 'no files matched'
        : [...seen].sort().map(([d, n]) => `${d} ×${n}`).join(', ') || 'no readable dimensions';
      add(
        `groups.${g.name}.dimensions`,
        `"${g.name}" image dimensions`,
        members.length > 0 && bad.length === 0 && missing.length === 0,
        `only ${g.dimensions.join(', ')}, each present`,
        actual,
        [...bad, ...missing.map((d) => `claimed ${d} but no file has it`)]
      );
    }
  }

  if (claims.totalBytes) {
    const total = files.reduce((s, f) => s + f.size, 0);
    add('totalBytes', 'total uncompressed size', inRange(total, claims.totalBytes), fmtRange(claims.totalBytes, ' B'), `${total.toLocaleString('en-US')} B`);
  }

  for (const [list, wantPresent] of [['required', true], ['forbidden', false]]) {
    for (const g of claims.paths?.[list] ?? []) {
      const m = compileGlob(g);
      const hits = [...dirs.filter((d) => m.test(d, true)).map((d) => `${d}/`), ...files.filter((f) => m.test(f.path, false)).map((f) => f.path)];
      add(
        `paths.${list}.${g}`,
        `${wantPresent ? 'contains' : 'does not contain'} ${g}`,
        wantPresent ? hits.length > 0 : hits.length === 0,
        wantPresent ? 'at least one match' : 'no match',
        hits.length === 0 ? 'no match' : `${hits.length} match(es)`,
        hits
      );
    }
  }

  const allNames = namesOf(source);
  if (claims.names?.asciiOnly) {
    const bad = nonAsciiNames(source);
    add('names.asciiOnly', 'every file and folder name is printable ASCII', bad.length === 0, 'ASCII names only', bad.length === 0 ? 'all ASCII' : `${bad.length} non-ASCII name(s)`, bad);
  }
  for (const [i, re] of (claims.names?.forbiddenRegexCompiled ?? []).entries()) {
    const src = claims.names.forbiddenRegex[i];
    const bad = allNames.filter((n) => re.test(n.name)).map((n) => n.path);
    add(`names.forbiddenRegex.${src}`, `no file or folder name matches /${src}/i`, bad.length === 0, 'no match', bad.length === 0 ? 'no match' : `${bad.length} match(es)`, bad);
  }

  for (const [kind, re] of Object.entries(DOC_PATTERNS)) {
    if (!claims.docs?.[kind]) continue;
    const hits = files.filter((f) => re.test(f.path.slice(f.path.lastIndexOf('/') + 1)) && f.size > 0).map((f) => f.path);
    add(`docs.${kind}`, `ships a non-empty ${kind} file`, hits.length > 0, `a ${kind} file`, hits.length ? hits.join(', ') : 'none found', []);
  }

  if (claims.images?.contentMatchesExtension) {
    const bad = imageMismatches(files);
    add('images.contentMatchesExtension', 'image content matches its file extension', bad.length === 0, 'every image named for its format', bad.length === 0 ? 'all match' : `${bad.length} mismatch(es)`, bad);
  }

  if (claims.page) {
    if (pageText === null) throw new Error('claims.page is set but no page text was given (--page <file>)');
    const folded = foldText(pageText);
    for (const phrase of claims.page.required ?? []) {
      const hits = findPhrase(folded, phrase);
      add(`page.required.${phrase}`, `page says "${phrase}"`, hits.length > 0, 'present', hits.length ? `found ×${hits.length}` : 'absent', []);
    }
    for (const phrase of claims.page.forbidden ?? []) {
      const hits = findPhrase(folded, phrase);
      add(`page.forbidden.${phrase}`, `page does not say "${phrase}"`, hits.length === 0, 'absent', hits.length ? `found ×${hits.length}` : 'absent', hits);
    }
    for (const c of claims.page.counts ?? []) {
      const [label, actual] =
        c.group !== undefined ? [`group "${c.group}"`, groupCounts.get(c.group)]
        : c.extension !== undefined ? [`${extLabel(c.extension)} files`, byExt.get(c.extension) ?? 0]
        : ['total files', files.length];
      // Matched on the NFKC text, not the folded one, so thousands separators
      // and the author's regex see the page as written.
      const stated = [...pageText.normalize('NFKC').matchAll(c.re)].map((m) => ({ text: m[0], n: parseNumber(m[1] ?? '') }));
      const wrong = stated.filter((s) => s.n !== actual);
      add(
        `page.counts.${c.regex}`,
        `every page number matching /${c.regex}/ equals the ${label} count`,
        stated.length > 0 && wrong.length === 0,
        String(actual),
        stated.length === 0 ? 'pattern not found on page' : stated.map((s) => `"${s.text}"`).join(', '),
        wrong.map((s) => `page says "${s.text}", archive has ${actual}`)
      );
    }
    if (claims.page.dimensionsExist) {
      const present = new Set(files.map((f) => dimOf(f.image)).filter(Boolean));
      const mentioned = [...new Set([...pageText.normalize('NFKC').matchAll(/(?<![\d.])(\d{1,5})\s*[x×]\s*(\d{1,5})(?!\d)/giu)].map((m) => `${Number(m[1])}x${Number(m[2])}`))];
      const missing = mentioned.filter((d) => !present.has(d));
      add(
        'page.dimensionsExist',
        'every WxH size the page mentions exists in the archive',
        mentioned.length > 0 && missing.length === 0,
        'each mentioned size present',
        mentioned.length === 0 ? 'page mentions no WxH sizes' : `mentions ${mentioned.join(', ')}`,
        missing.map((d) => `page mentions ${d}, no image has it`)
      );
    }
  }

  // Only the always-on integrity row: the claims file switched everything off
  // (or was empty), and a green run here would prove nothing about the page.
  if (results.length === 1) throw new Error('claims: the file declares no claims, so there is nothing to verify');
  return results;
}
