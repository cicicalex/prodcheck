/**
 * Container readers: zip (and everything built on it — .whl, .jar, .nupkg,
 * .apk, .docx), gzip, tar (POSIX ustar, GNU long names, pax), and ISO 9660
 * (with Joliet names when present). Pure JavaScript over node:zlib; no
 * dependency, nothing extracted to disk, nothing executed.
 *
 * Containers are recognised by their bytes, never by their extension: a
 * `.bin` that is a zip is read as a zip, and an `.iso` that is not ISO 9660
 * says so instead of reporting clean.
 *
 * Each reader returns
 *
 *   { entries: [{ name, open() -> Source }],
 *     headers: [{ start, end, name }],   // metadata ranges, per entry
 *     gaps:    [{ name, reason }] }       // what it saw and could not read
 *
 * `open` is lazy so that only one inflated entry is held in memory at a time.
 * It throws a Gap when an entry cannot be read (encrypted, an unsupported
 * method, over the inflate cap); the scanner records it and carries on.
 */

import { gunzipSync, inflateRawSync } from 'node:zlib';
import { BufferSource, readAll, slice } from './sources.mjs';

export class Gap extends Error {}

const SECTOR = 2048;

/** Formats recognised by magic that this scanner cannot open. */
const UNSUPPORTED = [
  { name: 'xz', test: (b) => b.subarray(0, 6).equals(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) },
  { name: 'bzip2', test: (b) => /^BZh[1-9]1AY&SY/.test(b.subarray(0, 10).toString('latin1')) },
  { name: 'zstd', test: (b) => b.readUInt32LE(0) === 0xfd2fb528 },
  { name: '7z', test: (b) => b.subarray(0, 6).equals(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) },
  { name: 'rar', test: (b) => b.subarray(0, 6).toString('latin1') === 'Rar!\x1a\x07' },
  { name: 'squashfs', test: (b) => ['hsqs', 'sqsh'].includes(b.subarray(0, 4).toString('latin1')) },
  { name: 'cab', test: (b) => b.subarray(0, 8).toString('latin1') === 'MSCF\0\0\0\0' },
  { name: 'lz4', test: (b) => b.readUInt32LE(0) === 0x184d2204 },
  { name: 'lzip', test: (b) => b.subarray(0, 4).toString('latin1') === 'LZIP' },
  { name: 'compress (.Z)', test: (b) => b[0] === 0x1f && b[1] === 0x9d },
];

/**
 * What `src` is: 'zip' | 'gzip' | 'tar' | 'iso' | {unsupported} | {notIso}
 * | 'raw'. `name` is only consulted to explain an `.iso` that is not one.
 */
export function detect(src, name = '') {
  const head = src.read(0, 512);
  const pad = Buffer.alloc(16);
  const h = head.length >= 16 ? head : Buffer.concat([head, pad]);

  const sig4 = h.readUInt32LE(0);
  if (sig4 === 0x04034b50 || sig4 === 0x06054b50 || sig4 === 0x08074b50) return 'zip';
  if (h[0] === 0x1f && h[1] === 0x8b && h[2] === 0x08) return 'gzip';

  if (src.size >= 16 * SECTOR + 6) {
    const vd = src.read(16 * SECTOR, 6).toString('latin1', 1, 6);
    if (vd === 'CD001') return 'iso';
    if (['BEA01', 'NSR02', 'NSR03', 'TEA01'].includes(vd) || /\.iso$/i.test(name)) {
      return { notIso: vd === 'BEA01' || vd.startsWith('NSR') ? 'udf' : 'unknown' };
    }
  } else if (/\.iso$/i.test(name)) {
    return { notIso: 'unknown' };
  }

  if (head.length === 512 && isTarHeader(head)) return 'tar';
  for (const u of UNSUPPORTED) if (u.test(h)) return { unsupported: u.name };
  return 'raw';
}

// ── zip ─────────────────────────────────────────────────────────────────────

const ZIP64_MARK = 0xffffffff;

function findEocd(src) {
  const tailLen = Math.min(src.size, 65535 + 22);
  const tail = src.read(src.size - tailLen, tailLen);
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) === 0x06054b50) return { pos: src.size - tailLen + i, rec: tail.subarray(i) };
  }
  return null;
}

export function readZip(src, { maxInflate }) {
  const out = { entries: [], headers: [], gaps: [] };
  const eocd = findEocd(src);
  if (!eocd) {
    out.gaps.push({ name: null, reason: 'zip without an end-of-central-directory record (truncated or corrupt): entries not read' });
    return out;
  }
  let count = eocd.rec.readUInt16LE(10);
  let cdSize = eocd.rec.readUInt32LE(12);
  let cdOffset = eocd.rec.readUInt32LE(16);
  let cdEnd = eocd.pos;

  if (count === 0xffff || cdSize === ZIP64_MARK || cdOffset === ZIP64_MARK) {
    const loc = src.read(eocd.pos - 20, 20);
    if (loc.length === 20 && loc.readUInt32LE(0) === 0x07064b50) {
      const z64pos = Number(loc.readBigUInt64LE(8));
      const z = src.read(z64pos, 56);
      if (z.length === 56 && z.readUInt32LE(0) === 0x06064b50) {
        count = Number(z.readBigUInt64LE(32));
        cdSize = Number(z.readBigUInt64LE(40));
        cdOffset = Number(z.readBigUInt64LE(48));
        cdEnd = z64pos; // the central directory ends where the ZIP64 record begins
      }
    }
  }

  // Bytes prepended to the archive (a self-extractor stub) shift every
  // recorded offset by the same amount; the central directory's real start
  // is known from where it ends.
  const delta = Math.max(0, cdEnd - cdSize - cdOffset);
  const cd = src.read(cdOffset + delta, cdSize);
  let p = 0;
  for (let i = 0; i < count; i++) {
    if (p + 46 > cd.length || cd.readUInt32LE(p) !== 0x02014b50) {
      out.gaps.push({ name: null, reason: `zip central directory ends after ${i} of ${count} entries (corrupt)` });
      break;
    }
    const flags = cd.readUInt16LE(p + 8);
    const method = cd.readUInt16LE(p + 10);
    let csize = cd.readUInt32LE(p + 20);
    let usize = cd.readUInt32LE(p + 24);
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    let lho = cd.readUInt32LE(p + 42);
    const nameBuf = cd.subarray(p + 46, p + 46 + nameLen);
    const name = nameBuf.toString(flags & 0x800 ? 'utf8' : 'latin1');
    const extra = cd.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
    const recStart = cdOffset + delta + p;
    const recEnd = recStart + 46 + nameLen + extraLen + commentLen;
    p += 46 + nameLen + extraLen + commentLen;

    // ZIP64 extended information: present fields follow in this fixed order.
    for (let e = 0; e + 4 <= extra.length; ) {
      const id = extra.readUInt16LE(e);
      const len = extra.readUInt16LE(e + 2);
      if (id === 0x0001) {
        let q = e + 4;
        if (usize === ZIP64_MARK && q + 8 <= e + 4 + len) (usize = Number(extra.readBigUInt64LE(q))), (q += 8);
        if (csize === ZIP64_MARK && q + 8 <= e + 4 + len) (csize = Number(extra.readBigUInt64LE(q))), (q += 8);
        if (lho === ZIP64_MARK && q + 8 <= e + 4 + len) lho = Number(extra.readBigUInt64LE(q));
      }
      e += 4 + len;
    }

    out.headers.push({ start: recStart, end: recEnd, name });
    const local = src.read(lho + delta, 30);
    if (local.length < 30 || local.readUInt32LE(0) !== 0x04034b50) {
      out.gaps.push({ name, reason: 'zip local header missing (corrupt archive): entry not read' });
      continue;
    }
    const dataStart = lho + delta + 30 + local.readUInt16LE(26) + local.readUInt16LE(28);
    out.headers.push({ start: lho + delta, end: dataStart, name });
    if (name.endsWith('/') && usize === 0) continue; // a directory

    out.entries.push({
      name,
      open: () => {
        if (flags & 0x1) throw new Gap('encrypted zip entry: content not readable');
        if (method === 0) return slice(src, dataStart, csize);
        if (method !== 8) throw new Gap(`zip compression method ${method} is not supported (only stored and deflate)`);
        if (usize > maxInflate || csize > maxInflate) {
          throw new Gap(`entry inflates to ${usize} bytes, over --max-inflate-mb`);
        }
        try {
          return new BufferSource(inflateRawSync(src.read(dataStart, csize), { maxOutputLength: maxInflate }));
        } catch (err) {
          throw new Gap(`deflate stream could not be inflated (${err.code ?? err.message})`);
        }
      },
    });
  }
  return out;
}

// ── gzip ────────────────────────────────────────────────────────────────────

/** The FNAME the gzip header carries, if any — the name of what is inside. */
function gzipName(head) {
  if (!(head[3] & 0x08)) return null;
  let p = 10;
  if (head[3] & 0x04) p += 2 + head.readUInt16LE(10);
  const end = head.indexOf(0, p);
  return end > p ? head.toString('latin1', p, end) : null;
}

export function readGzip(src, { maxInflate }, outerName) {
  const out = { entries: [], headers: [], gaps: [] };
  const fname = gzipName(src.read(0, 1024));
  const base = (outerName ?? '').split('/').pop();
  const name =
    fname ??
    (/\.tgz$/i.test(base) ? base.replace(/\.tgz$/i, '.tar') : base.replace(/\.gz$/i, '') || 'gunzipped');
  out.entries.push({
    name,
    transparent: true,
    open: () => {
      if (src.size > maxInflate) throw new Gap('gzip stream larger than --max-inflate-mb');
      try {
        return new BufferSource(gunzipSync(readAll(src), { maxOutputLength: maxInflate }));
      } catch (err) {
        throw new Gap(`gzip stream could not be inflated (${err.code ?? err.message})`);
      }
    },
  });
  return out;
}

// ── tar ─────────────────────────────────────────────────────────────────────

const cstr = (b, start, len) => {
  const s = b.subarray(start, start + len);
  const z = s.indexOf(0);
  return s.toString('utf8', 0, z === -1 ? s.length : z);
};

function tarNumber(b, start, len) {
  if (b[start] & 0x80) {
    // GNU base-256: big-endian, top bit of the first byte is the marker.
    let n = b[start] & 0x7f;
    for (let i = 1; i < len; i++) n = n * 256 + b[start + i];
    return n;
  }
  const s = cstr(b, start, len).trim();
  return s ? parseInt(s, 8) : 0;
}

function isTarHeader(h) {
  if (h.toString('latin1', 257, 262) === 'ustar') return true;
  // Old V7 archives have no magic; the header checksum is what identifies them.
  const stored = tarNumber(h, 148, 8);
  if (!stored || Number.isNaN(stored)) return false;
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i];
  return sum === stored && h[0] !== 0;
}

function parsePax(buf) {
  const out = {};
  const text = buf.toString('utf8');
  let p = 0;
  while (p < text.length) {
    const sp = text.indexOf(' ', p);
    if (sp === -1) break;
    const len = parseInt(text.slice(p, sp), 10);
    if (!len) break;
    const rec = text.slice(sp + 1, p + len - 1);
    const eq = rec.indexOf('=');
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    p += len;
  }
  return out;
}

export function readTar(src) {
  const out = { entries: [], headers: [], gaps: [] };
  let pos = 0;
  let entryStart = 0;
  let longName = null;
  let pax = {};
  while (pos + 512 <= src.size) {
    const h = src.read(pos, 512);
    if (h.every((b) => b === 0)) break; // end-of-archive marker
    if (!isTarHeader(h)) {
      out.gaps.push({ name: null, reason: `tar header at offset ${pos} is corrupt: the rest of the archive is not read as entries` });
      break;
    }
    const size = tarNumber(h, 124, 12);
    const type = String.fromCharCode(h[156] || 0x30);
    const dataStart = pos + 512;
    const next = dataStart + Math.ceil(size / 512) * 512;

    if (type === 'L' || type === 'x' || type === 'K' || type === 'g') {
      const data = src.read(dataStart, size);
      if (type === 'L') longName = cstr(data, 0, data.length);
      if (type === 'x') pax = parsePax(data);
      pos = next;
      continue; // these belong to the header of the entry that follows
    }

    const prefix = h.toString('latin1', 257, 262) === 'ustar' ? cstr(h, 345, 155) : '';
    const short = cstr(h, 0, 100);
    const name = pax.path ?? longName ?? (prefix ? `${prefix}/${short}` : short);
    out.headers.push({ start: entryStart, end: dataStart, name });
    if (type === '0' || type === '7' || h[156] === 0) {
      const data = slice(src, dataStart, size);
      out.entries.push({
        name,
        open: () => {
          if (data.truncated) throw new Gap('tar entry runs past the end of the archive (truncated)');
          return data;
        },
      });
    }
    longName = null;
    pax = {};
    pos = next;
    entryStart = next;
  }
  return out;
}

// ── ISO 9660 ────────────────────────────────────────────────────────────────

const MAX_DIR_BYTES = 64 * 1024 * 1024;

/**
 * Walk the directory tree of an ISO 9660 image: Joliet (UCS-2 names) when the
 * image has a Joliet supplementary descriptor, the primary tree otherwise.
 * Rock Ridge names are not decoded — a Rock Ridge-only image reports the
 * primary 8.3 names, which still locate the file.
 */
export function readIso(src) {
  const out = { entries: [], headers: [], gaps: [] };
  let primary = null;
  let joliet = null;
  for (let s = 16; s < 16 + 64; s++) {
    const vd = src.read(s * SECTOR, SECTOR);
    if (vd.length < SECTOR || vd.toString('latin1', 1, 6) !== 'CD001') break;
    if (vd[0] === 255) break;
    if (vd[0] === 1 && !primary) primary = vd;
    if (vd[0] === 2 && /^%\/[@CE]/.test(vd.toString('latin1', 88, 91))) joliet = vd;
  }
  const vd = joliet ?? primary;
  if (!vd) {
    out.gaps.push({ name: null, reason: 'ISO 9660 image without a primary volume descriptor: file tree not read' });
    return out;
  }
  const decode = joliet
    ? (b) => Buffer.from(b.subarray(0, b.length & ~1)).swap16().toString('utf16le')
    : (b) => b.toString('latin1');

  const visited = new Set();
  const walk = (lba, len, prefix) => {
    if (visited.has(lba)) return;
    visited.add(lba);
    if (len > MAX_DIR_BYTES) {
      out.gaps.push({ name: prefix || '/', reason: 'ISO directory larger than 64 MiB: not read' });
      return;
    }
    const d = src.read(lba * SECTOR, len);
    let p = 0;
    while (p < d.length) {
      const recLen = d[p];
      if (recLen === 0) {
        p = (Math.floor(p / SECTOR) + 1) * SECTOR; // records never span sectors
        continue;
      }
      if (p + 33 > d.length) break;
      const extent = d.readUInt32LE(p + 2);
      const size = d.readUInt32LE(p + 10);
      const flags = d[p + 25];
      const nameLen = d[p + 32];
      const raw = d.subarray(p + 33, p + 33 + nameLen);
      const start = lba * SECTOR + p;
      p += recLen;
      if (nameLen === 1 && (raw[0] === 0 || raw[0] === 1)) continue; // . and ..
      let name = decode(raw).replace(/;\d+$/, '');
      if (!(flags & 2)) name = name.replace(/\.$/, '');
      const full = prefix ? `${prefix}/${name}` : name;
      out.headers.push({ start, end: start + recLen, name: full });
      if (flags & 2) {
        walk(extent, size, full);
      } else {
        if (flags & 0x80) {
          out.gaps.push({ name: full, reason: 'multi-extent file: each extent is scanned separately' });
        }
        const data = slice(src, extent * SECTOR, size);
        out.entries.push({
          name: full,
          open: () => {
            if (data.truncated) throw new Gap('file extent runs past the end of the image (truncated)');
            return data;
          },
        });
      }
    }
  };
  walk(vd.readUInt32LE(156 + 2), vd.readUInt32LE(156 + 10), '');
  return out;
}
