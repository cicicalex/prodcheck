/**
 * A zero-dependency ZIP reader, built for verification rather than extraction.
 *
 * The central directory is what every unzip tool lists, but it is only the
 * archive's own description of itself: a size or a CRC in it can be wrong, and
 * the bytes a buyer extracts are the ones behind the local headers. So every
 * entry is actually decompressed, its length counted and its CRC-32 recomputed,
 * and any disagreement with the directory is reported as an integrity problem
 * instead of being trusted. Sizes handed to the verifier are the counted ones.
 *
 * Supported: stored (0) and deflate (8), ZIP64 sizes and offsets, UTF-8 names
 * (flag bit 11), the Info-ZIP Unicode Path extra field, unflagged names that are
 * valid UTF-8 (as Info-ZIP and macOS write them), and CP437 for the rest. Not
 * supported, and reported per entry rather than skipped: encryption, and every
 * other compression method.
 *
 * Nothing is written to disk, so a hostile name (`../x`) is just a string here.
 */

import { inflateRawSync } from 'node:zlib';

const SIG_EOCD = 0x06054b50;
const SIG_Z64_LOCATOR = 0x07064b50;
const SIG_Z64_EOCD = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

/** Code points 0x80-0xFF of IBM code page 437, the ZIP default when bit 11 is off. */
export const CP437_HIGH =
  'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐' +
  '└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function decodeCp437(bytes) {
  let s = '';
  for (const b of bytes) s += b < 0x80 ? String.fromCharCode(b) : CP437_HIGH[b - 0x80];
  return s;
}

const utf8 = new TextDecoder('utf-8', { fatal: true });

function decodeName(nameBytes, flags, extra) {
  // Info-ZIP Unicode Path (0x7075): a UTF-8 name, valid only while the CRC of
  // the legacy name it shadows still matches — otherwise a later tool renamed
  // the entry and the extra field is stale.
  for (const field of extraFields(extra)) {
    if (field.id === 0x7075 && field.data.length >= 5 && field.data[0] === 1) {
      if (field.data.readUInt32LE(1) === crc32(nameBytes)) {
        try {
          return { name: utf8.decode(field.data.subarray(5)), encoding: 'utf-8 (unicode path field)' };
        } catch {
          /* fall through to the header name */
        }
      }
    }
  }
  if (flags & 0x800) {
    try {
      return { name: utf8.decode(nameBytes), encoding: 'utf-8' };
    } catch {
      return { name: decodeCp437(nameBytes), encoding: 'invalid utf-8, read as cp437' };
    }
  }
  // Unflagged. Strictly that means CP437, but Info-ZIP and macOS write raw
  // UTF-8 here without setting the flag, and extractors on those systems show
  // it as UTF-8. Non-ASCII bytes that form valid UTF-8 are almost never
  // intended CP437 box-drawing, so prefer UTF-8 and fall back to CP437.
  if (nameBytes.some((b) => b >= 0x80)) {
    try {
      return { name: utf8.decode(nameBytes), encoding: 'utf-8 (unflagged)' };
    } catch {
      /* not UTF-8: genuine CP437 */
    }
  }
  return { name: decodeCp437(nameBytes), encoding: 'cp437' };
}

function* extraFields(extra) {
  let p = 0;
  while (p + 4 <= extra.length) {
    const id = extra.readUInt16LE(p);
    const len = extra.readUInt16LE(p + 2);
    if (p + 4 + len > extra.length) return;
    yield { id, data: extra.subarray(p + 4, p + 4 + len) };
    p += 4 + len;
  }
}

function u64(buf, at) {
  const v = buf.readBigUInt64LE(at);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('zip: 64-bit value too large');
  return Number(v);
}

function findEndOfCentralDirectory(buf) {
  const stop = Math.max(0, buf.length - 22 - 0xffff);
  for (let p = buf.length - 22; p >= stop; p--) {
    if (buf.readUInt32LE(p) !== SIG_EOCD) continue;
    // The comment length must reach exactly to the end of the file, or this
    // signature is just four bytes inside an entry or the comment itself.
    if (p + 22 + buf.readUInt16LE(p + 20) === buf.length) return p;
  }
  throw new Error('not a zip archive (no end-of-central-directory record)');
}

/**
 * Read every entry of a ZIP held in `buf`.
 *
 * `onEntry(entry, bytes)` is called for each file entry with its decompressed
 * bytes, so callers can inspect content without the reader keeping every file
 * in memory at once.
 *
 * @returns {{ entries: Array<object>, problems: string[] }}
 *   entries: { name, isDir, size, declaredSize, compressedSize, method, encoding }
 *   problems: one human-readable line per integrity failure
 */
export function readZip(buf, onEntry = () => {}) {
  if (buf.length < 22) throw new Error('not a zip archive (too short)');
  const eocd = findEndOfCentralDirectory(buf);
  let total = buf.readUInt16LE(eocd + 10);
  let cdSize = buf.readUInt32LE(eocd + 12);
  let cdOffset = buf.readUInt32LE(eocd + 16);

  if (total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc < 0 || buf.readUInt32LE(loc) !== SIG_Z64_LOCATOR) {
      throw new Error('zip64 values present but no zip64 locator');
    }
    const z = u64(buf, loc + 8);
    if (z + 56 > buf.length || buf.readUInt32LE(z) !== SIG_Z64_EOCD) {
      throw new Error('zip64 end-of-central-directory record missing');
    }
    total = u64(buf, z + 32);
    cdSize = u64(buf, z + 40);
    cdOffset = u64(buf, z + 48);
  }
  if (cdOffset + cdSize > buf.length) throw new Error('central directory runs past end of file');

  const entries = [];
  const problems = [];
  const seen = new Set();
  let p = cdOffset;

  for (let i = 0; i < total; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CENTRAL) {
      throw new Error(`central directory entry ${i + 1} of ${total} is corrupt`);
    }
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    let csize = buf.readUInt32LE(p + 20);
    let usize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let localOffset = buf.readUInt32LE(p + 42);
    const nameBytes = buf.subarray(p + 46, p + 46 + nameLen);
    const extra = buf.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
    p += 46 + nameLen + extraLen + commentLen;

    for (const field of extraFields(extra)) {
      if (field.id !== 0x0001) continue;
      let q = 0;
      if (usize === 0xffffffff) (usize = u64(field.data, q)), (q += 8);
      if (csize === 0xffffffff) (csize = u64(field.data, q)), (q += 8);
      if (localOffset === 0xffffffff) localOffset = u64(field.data, q);
    }

    const { name, encoding } = decodeName(nameBytes, flags, extra);
    const isDir = name.endsWith('/');
    const entry = { name, isDir, size: 0, declaredSize: usize, compressedSize: csize, method, encoding };
    entries.push(entry);

    if (seen.has(name)) problems.push(`${name}: duplicate entry name`);
    seen.add(name);
    if (isDir) continue;

    if (flags & 0x1) {
      problems.push(`${name}: encrypted entry, content cannot be verified`);
      continue;
    }
    if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== SIG_LOCAL) {
      problems.push(`${name}: local header missing at offset ${localOffset}`);
      continue;
    }
    const start = localOffset + 30 + buf.readUInt16LE(localOffset + 26) + buf.readUInt16LE(localOffset + 28);
    if (start + csize > buf.length) {
      problems.push(`${name}: compressed data runs past end of file`);
      continue;
    }
    const raw = buf.subarray(start, start + csize);

    let bytes;
    try {
      if (method === 0) bytes = raw;
      else if (method === 8) bytes = inflateRawSync(raw);
      else {
        problems.push(`${name}: unsupported compression method ${method}`);
        continue;
      }
    } catch (err) {
      problems.push(`${name}: cannot decompress (${err.message})`);
      continue;
    }

    entry.size = bytes.length;
    if (bytes.length !== usize) {
      problems.push(`${name}: directory says ${usize} bytes, data is ${bytes.length} bytes`);
    }
    const actualCrc = crc32(bytes);
    if (actualCrc !== crc) {
      problems.push(
        `${name}: CRC-32 mismatch (directory ${crc.toString(16).padStart(8, '0')}, data ${actualCrc.toString(16).padStart(8, '0')})`
      );
    }
    onEntry(entry, bytes);
  }

  return { entries, problems };
}
