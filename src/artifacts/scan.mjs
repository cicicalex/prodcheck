/**
 * The artifact scanner: what ships, read as bytes.
 *
 * Source gates read the source. This reads the thing that was built — the
 * ISO, the wheel, the npm tarball, the .exe — because that is where a build
 * machine's `C:\Users\<name>\.rustup` actually ends up, and no source check
 * can see it there.
 *
 * Every object is read the same way, whatever it is:
 *
 *   1. If its bytes are a container this scanner can open, each entry is
 *      scanned recursively, down to `maxDepth` levels of nesting.
 *   2. Then its bytes are scanned whole, as raw text — so the metadata between
 *      the entries (zip and tar headers, ISO directory records, a tar's
 *      uname, appended data) is read too. A match already reported from an
 *      entry is the same byte reached twice and is not repeated.
 *   3. A leaf — anything that is not a container — is only step 2.
 *
 * Raw text means two channels over the same bytes: every byte as one 8-bit
 * character (ASCII and UTF-8 strings, as `strings` finds them), and UTF-16LE
 * at both byte alignments (Windows resources, PE version info, .NET string
 * heaps, Joliet names). Large objects are read in chunks with an overlap, so
 * a multi-gigabyte image is never held in memory and no match is cut in half.
 *
 * What it cannot read it says, as a *gap*: an encrypted or unsupported entry,
 * nesting past the limit, an xz or squashfs payload, a UDF-only image. A gap
 * is not clean, and the CLI does not exit 0 on one unless told to.
 */

import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { detect, Gap, readGzip, readIso, readTar, readZip } from './containers.mjs';
import { RULES } from './rules.mjs';
import { FileSource } from './sources.mjs';

export const DEFAULTS = {
  maxDepth: 10,
  maxInflate: 512 * 1024 * 1024,
  chunkSize: 8 * 1024 * 1024,
};

/** Bytes re-read on each side of a chunk. Larger than any rule's longest match. */
const OVERLAP = 8192;
const CONTEXT = 24;

/** Context is shown, but never a long token-shaped run inside it. */
function sanitize(s) {
  return s
    .replace(/[^\x20-\x7e]/g, '.')
    .replace(/[A-Za-z0-9+/=_-]{20,}/g, '[…]');
}

/** latin1 text holding UTF-8 bytes → what those bytes say. */
const fromBytes = (s) => Buffer.from(s, 'latin1').toString('utf8');

/**
 * All matches of every rule in one channel's text. The full list is kept even
 * for vetoed and out-of-window matches, because each snippet masks every
 * match it overlaps — a snippet must not reveal a neighbouring secret either.
 */
function matchAll(text, rules) {
  const hits = [];
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    for (let m = rule.re.exec(text); m; m = rule.re.exec(text)) {
      if (m[0].length === 0) {
        rule.re.lastIndex += 1;
        continue;
      }
      hits.push({ rule, m, start: m.index, end: m.index + m[0].length });
    }
  }
  return hits.sort((a, b) => a.start - b.start || b.end - a.end);
}

function snippet(text, hit, hits, decode) {
  const ws = Math.max(0, hit.start - CONTEXT);
  const we = Math.min(text.length, hit.end + CONTEXT);
  let out = ws > 0 ? '…' : '';
  let p = ws;
  // `hits` is sorted by start and no match is longer than OVERLAP, so only
  // the run starting just before the window can touch it.
  let lo = 0;
  let hi = hits.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (hits[mid].start < ws - OVERLAP) lo = mid + 1;
    else hi = mid;
  }
  for (let i = lo; i < hits.length && hits[i].start < we; i++) {
    const h = hits[i];
    if (h.end <= p) continue;
    if (h.start > p) out += sanitize(decode(text.slice(p, h.start)));
    // A match cut by the window's edge, or overlapping one already shown,
    // has no redaction that would be safe to show in part.
    out += h.start >= p ? h.rule.redact(h.m) : '[…]';
    p = h.end;
  }
  if (p < we) out += sanitize(decode(text.slice(p, we)));
  if (we < text.length) out += '…';
  return out;
}

/**
 * Reported ranges, bucketed by rule and 4 KiB of offset so a file with a
 * hundred thousand e-mail addresses is not a quadratic scan. A match is never
 * longer than OVERLAP, so a range can only overlap ranges that start in its
 * own bucket or the few before it.
 */
const BUCKET = 4096;

function remember(seen, rule, start, end) {
  const key = `${rule}:${Math.floor(start / BUCKET)}`;
  if (!seen.has(key)) seen.set(key, []);
  seen.get(key).push([start, end]);
}

function overlapsReported(seen, rule, start, end) {
  const last = Math.floor((end - 1) / BUCKET);
  for (let b = Math.floor((start - OVERLAP) / BUCKET); b <= last; b++) {
    const ranges = seen.get(`${rule}:${b}`);
    if (ranges?.some(([s, e]) => s < end && start < e)) return true;
  }
  return false;
}

/** The entry header containing `offset`, by binary search over sorted ranges. */
function headerAt(headers, offset) {
  let lo = 0;
  let hi = headers.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (headers[mid].start <= offset) lo = mid + 1;
    else hi = mid;
  }
  const h = headers[lo - 1];
  return h && offset < h.end ? h : undefined;
}

export class Scanner {
  constructor({ maxDepth, maxInflate, chunkSize, deny } = {}) {
    this.opts = {
      maxDepth: maxDepth ?? DEFAULTS.maxDepth,
      maxInflate: maxInflate ?? DEFAULTS.maxInflate,
      // Even, so the UTF-16 channels keep their alignment from chunk to chunk.
      chunkSize: Math.max(2 * OVERLAP, (chunkSize ?? DEFAULTS.chunkSize) & ~1),
    };
    this.rules = {
      bytes: deny ? [...RULES, deny.bytes] : RULES,
      utf16: deny ? [...RULES, deny.utf16] : RULES,
    };
    this.findings = [];
    this.gaps = [];
    this.stats = { artifacts: 0, objects: 0, bytes: 0 };
    /** root source -> reported byte ranges, bucketed (see remember()) */
    this.seen = new WeakMap();
  }

  gap(loc, reason) {
    this.gaps.push({ artifact: loc.artifact, path: [...loc.path], reason });
  }

  /** Scan one file or directory given on the command line. */
  scanInput(input) {
    // Shown as given, normalised, so `./dist/` and `dist` produce the same
    // locations and one allow-list glob matches both. An input named
    // explicitly is followed even if it is a symlink; links found while
    // walking a directory are not.
    const shown = path.normalize(input).split(path.sep).join('/').replace(/(.)\/$/, '$1');
    const info = statSync(input);
    if (info.isDirectory()) {
      this.walk(input, shown);
    } else if (info.isFile()) {
      this.scanFile(input, shown);
    } else {
      throw new Error(`not a file or directory: ${input}`);
    }
  }

  walk(dir, shown) {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      this.gap({ artifact: shown, path: [] }, `directory not readable (${err.code ?? err.message})`);
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      const rel = `${shown.replace(/\/$/, '')}/${e.name}`;
      if (e.isDirectory()) this.walk(abs, rel);
      else if (e.isFile()) this.scanFile(abs, rel);
      // Symlinks are not followed: the link is not the artifact's bytes.
    }
  }

  scanFile(file, shown) {
    let src;
    try {
      src = new FileSource(file);
    } catch (err) {
      this.gap({ artifact: shown, path: [] }, `file not readable (${err.code ?? err.message})`);
      return;
    }
    try {
      this.stats.artifacts += 1;
      this.scanObject(src, { artifact: shown, path: [], name: shown }, 0);
    } finally {
      src.close();
    }
  }

  /**
   * One object: a whole artifact, or anything found inside one. `loc.path` is
   * the chain of entry names from the artifact down to this object.
   */
  scanObject(src, loc, depth) {
    this.stats.objects += 1;
    const kind = detect(src, loc.name);
    const reader = { zip: readZip, gzip: readGzip, tar: readTar, iso: readIso }[kind];

    if (kind?.unsupported) {
      this.gap(loc, `${kind.unsupported} data: this scanner cannot decompress it, so only its raw bytes were scanned`);
    } else if (kind?.notIso) {
      this.gap(
        loc,
        kind.notIso === 'udf'
          ? 'UDF image without an ISO 9660 tree: the file tree was not read, only the raw image bytes were scanned'
          : 'named .iso but has no ISO 9660 volume descriptor: the file tree was not read, only the raw bytes were scanned'
      );
    }

    let headers = [];
    if (reader && depth >= this.opts.maxDepth) {
      this.gap(loc, `${kind} nested deeper than --max-depth ${this.opts.maxDepth}: entries not opened, only raw bytes scanned`);
    } else if (reader) {
      const listing = reader(src, this.opts, loc.name);
      headers = listing.headers;
      for (const g of listing.gaps) this.gap(g.name ? { ...loc, path: [...loc.path, g.name] } : loc, g.reason);
      for (const entry of listing.entries) {
        const child = entry.transparent
          ? { artifact: loc.artifact, path: loc.path, name: entry.name, transparent: entry.name }
          : { artifact: loc.artifact, path: [...loc.path, entry.name], name: entry.name };
        let inner;
        try {
          inner = entry.open();
        } catch (err) {
          if (!(err instanceof Gap)) throw err;
          this.gap(child.transparent ? { ...loc, path: [...loc.path, entry.name] } : child, err.message);
          continue;
        }
        this.scanObject(inner, child, depth + 1);
      }
    }

    headers.sort((a, b) => a.start - b.start);
    this.scanBytes(src, loc, headers, Boolean(reader));
  }

  /** Steps 2 and 3: the raw-text pass over one object's bytes. */
  scanBytes(src, loc, headers, container) {
    const { chunkSize } = this.opts;
    let seen = this.seen.get(src.root);
    if (!seen) this.seen.set(src.root, (seen = new Map()));
    // A gunzipped leaf has no name of its own in the path; give it one.
    const leafPath = loc.transparent ? [...loc.path, loc.transparent] : loc.path;

    for (let start = 0; start < src.size || start === 0; start += chunkSize) {
      const from = Math.max(0, start - OVERLAP);
      const buf = src.read(from, start + chunkSize + OVERLAP - from);
      if (!buf.length) break;
      this.stats.bytes += Math.min(chunkSize, src.size - start);
      const last = start + chunkSize >= src.size;
      const keep = (off) => off >= start && (last || off < start + chunkSize);

      const channels = [
        { name: 'ascii', text: buf.toString('latin1'), at: (i) => from + i, decode: fromBytes, rules: this.rules.bytes },
      ];
      for (const align of [0, 1]) {
        if (buf.length - align < 8) continue;
        // `from` is even, so alignment 0 here is alignment 0 in the object.
        const body = buf.subarray(align, align + ((buf.length - align) & ~1));
        channels.push({ name: 'utf-16le', text: body.toString('utf16le'), at: (i) => from + align + 2 * i, decode: (s) => s, rules: this.rules.utf16 });
      }

      for (const ch of channels) {
        const hits = matchAll(ch.text, ch.rules);
        for (const hit of hits) {
          const offset = ch.at(hit.start);
          if (!keep(offset)) continue;
          if (hit.rule.keep && !hit.rule.keep(hit.m)) continue;
          // The same occurrence reached twice need not be the same match: a
          // zip stores the entry name right before the data, so the container
          // pass reads `x.txt` + an e-mail at the start of the data as one
          // longer address. Any overlap with bytes already reported under the
          // same rule makes it the same occurrence.
          const abs = src.base + offset;
          const absEnd = abs + ch.at(hit.end) - ch.at(hit.start);
          if (overlapsReported(seen, hit.rule.id, abs, absEnd)) continue;
          remember(seen, hit.rule.id, abs, absEnd);

          const header = headerAt(headers, offset);
          const finding = {
            rule: hit.rule.id,
            artifact: loc.artifact,
            path: header ? [...loc.path, header.name] : container ? loc.path : leafPath,
            where: header ? 'header' : container ? 'container' : 'content',
            offset,
            encoding: ch.name,
            snippet: snippet(ch.text, hit, hits, ch.decode),
          };
          if (hit.rule.term) finding.term = hit.rule.term(hit.m);
          // The unredacted value, for allow-list patterns only. Not enumerable,
          // so no renderer and no JSON.stringify can ever emit it.
          Object.defineProperty(finding, 'value', { value: ch.decode(hit.m[0]), enumerable: false });
          this.findings.push(finding);
        }
      }
      if (last) break;
    }
  }
}

/** A finding's location as one string: `artifact!entry!nested-entry`. */
export function locationOf(f) {
  return [f.artifact, ...f.path].join('!');
}

export function scanArtifacts(inputs, opts = {}) {
  const t0 = performance.now();
  const scanner = new Scanner(opts);
  for (const input of inputs) scanner.scanInput(input);
  return {
    findings: scanner.findings,
    gaps: scanner.gaps,
    stats: { ...scanner.stats, durationMs: Math.round(performance.now() - t0) },
  };
}
