/**
 * Test-time builders for the claims verifier: a small ZIP writer and minimal
 * image headers. Archives are built per test, in memory or under a temp dir,
 * so no binary fixture is committed and every byte a test depends on is
 * visible in the test that depends on it.
 *
 * The writer can also produce the broken archives the reader must catch: a
 * wrong CRC, a wrong declared size, an unsupported method, an encrypted flag,
 * raw name bytes, and ZIP64 records.
 */

import { deflateRawSync } from 'node:zlib';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { crc32 } from '../../src/claims/zip.mjs';

/**
 * @param {Array<{name: string, data?: Buffer|string, deflate?: boolean, nameBytes?: Buffer,
 *   utf8Flag?: boolean, crc?: number, declaredSize?: number, method?: number,
 *   encrypted?: boolean, extra?: Buffer}>} entries
 * @param {{zip64?: boolean}} [opts] zip64 writes every size/offset through ZIP64 records
 */
export function buildZip(entries, { zip64 = false } = {}) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? '');
    const isDir = e.name.endsWith('/');
    const deflate = e.deflate ?? (!isDir && data.length > 0);
    const body = deflate ? deflateRawSync(data) : data;
    const method = e.method ?? (deflate ? 8 : 0);
    const nameBytes = e.nameBytes ?? Buffer.from(e.name, 'utf8');
    const utf8Flag = e.utf8Flag ?? /[^\x00-\x7f]/.test(e.name);
    const flags = (utf8Flag ? 0x800 : 0) | (e.encrypted ? 1 : 0);
    const crc = e.crc ?? crc32(data);
    const usize = e.declaredSize ?? data.length;

    const z64 = zip64
      ? (() => {
          const b = Buffer.alloc(4 + 24);
          b.writeUInt16LE(0x0001, 0);
          b.writeUInt16LE(24, 2);
          b.writeBigUInt64LE(BigInt(usize), 4);
          b.writeBigUInt64LE(BigInt(body.length), 12);
          b.writeBigUInt64LE(BigInt(offset), 20);
          return b;
        })()
      : Buffer.alloc(0);
    const extra = Buffer.concat([z64, e.extra ?? Buffer.alloc(0)]);
    const M = 0xffffffff;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(zip64 ? 45 : 20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(zip64 ? M : body.length, 18);
    local.writeUInt32LE(zip64 ? M : usize, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(extra.length, 28);
    const localAll = Buffer.concat([local, nameBytes, extra, body]);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x031e, 4);
    central.writeUInt16LE(zip64 ? 45 : 20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(zip64 ? M : body.length, 20);
    central.writeUInt32LE(zip64 ? M : usize, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(extra.length, 30);
    central.writeUInt32LE(zip64 ? M : offset, 42);
    centrals.push(Buffer.concat([central, nameBytes, extra]));
    locals.push(localAll);
    offset += localAll.length;
  }
  const cd = Buffer.concat(centrals);
  const tail = [];
  if (zip64) {
    const rec = Buffer.alloc(56);
    rec.writeUInt32LE(0x06064b50, 0);
    rec.writeBigUInt64LE(44n, 4);
    rec.writeUInt16LE(45, 12);
    rec.writeUInt16LE(45, 14);
    rec.writeBigUInt64LE(BigInt(entries.length), 24);
    rec.writeBigUInt64LE(BigInt(entries.length), 32);
    rec.writeBigUInt64LE(BigInt(cd.length), 40);
    rec.writeBigUInt64LE(BigInt(offset), 48);
    const loc = Buffer.alloc(20);
    loc.writeUInt32LE(0x07064b50, 0);
    loc.writeBigUInt64LE(BigInt(offset + cd.length), 8);
    loc.writeUInt32LE(1, 16);
    tail.push(rec, loc);
  }
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(zip64 ? 0xffff : entries.length, 8);
  eocd.writeUInt16LE(zip64 ? 0xffff : entries.length, 10);
  eocd.writeUInt32LE(zip64 ? 0xffffffff : cd.length, 12);
  eocd.writeUInt32LE(zip64 ? 0xffffffff : offset, 16);
  return Buffer.concat([...locals, cd, ...tail, eocd]);
}

// ---------------------------------------------------------------- images

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

export function png(w, h) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

export function gif(w, h) {
  const b = Buffer.alloc(14);
  b.write('GIF89a', 0, 'latin1');
  b.writeUInt16LE(w, 6);
  b.writeUInt16LE(h, 8);
  b[13] = 0x3b;
  return b;
}

function riff(fourcc, payload) {
  const head = Buffer.alloc(20);
  head.write('RIFF', 0, 'latin1');
  head.writeUInt32LE(12 + payload.length, 4);
  head.write('WEBP', 8, 'latin1');
  head.write(fourcc, 12, 'latin1');
  head.writeUInt32LE(payload.length, 16);
  return Buffer.concat([head, payload]);
}

export function webpLossy(w, h) {
  const p = Buffer.alloc(10);
  p[3] = 0x9d;
  p[4] = 0x01;
  p[5] = 0x2a;
  p.writeUInt16LE(w, 6);
  p.writeUInt16LE(h, 8);
  return riff('VP8 ', p);
}

export function webpLossless(w, h) {
  const p = Buffer.alloc(5);
  p[0] = 0x2f;
  p.writeUInt32LE(((w - 1) & 0x3fff) | (((h - 1) & 0x3fff) << 14), 1);
  return riff('VP8L', p);
}

export function webpExtended(w, h) {
  const p = Buffer.alloc(10);
  p.writeUIntLE(w - 1, 4, 3);
  p.writeUIntLE(h - 1, 7, 3);
  return riff('VP8X', p);
}

/** JPEG with an APP0 segment before the frame header; sof 0xc0 baseline, 0xc2 progressive. */
export function jpeg(w, h, sof = 0xc0) {
  const app0 = Buffer.from([0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0]);
  const frame = Buffer.alloc(19);
  frame[0] = 0xff;
  frame[1] = sof;
  frame.writeUInt16BE(17, 2);
  frame[4] = 8;
  frame.writeUInt16BE(h, 5);
  frame.writeUInt16BE(w, 7);
  frame[9] = 3;
  return Buffer.concat([Buffer.from([0xff, 0xd8]), app0, frame, Buffer.from([0xff, 0xd9])]);
}

// ---------------------------------------------------------------- on disk

/** A fresh temp directory for one test. */
export function tempDir() {
  return mkdtempSync(path.join(tmpdir(), 'prodcheck-claims-'));
}

/** Write {relPath: bytes} under a new temp dir; returns the dir. */
export function writeTree(files) {
  const root = tempDir();
  for (const [rel, data] of Object.entries(files)) {
    const abs = path.join(root, ...rel.split('/'));
    if (rel.endsWith('/')) {
      mkdirSync(abs, { recursive: true });
      continue;
    }
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, data);
  }
  return root;
}

/** Same tree as a zip on disk; returns the zip path. */
export function writeZip(files, opts) {
  const zipPath = path.join(tempDir(), 'pack.zip');
  writeFileSync(zipPath, buildZip(Object.entries(files).map(([name, data]) => ({ name, data })), opts));
  return zipPath;
}

/** n distinct w×h PNG icons under `dir/`, named icon-000.png … */
export function icons(n, w = 32, h = 32, dir = 'icons') {
  const out = {};
  for (let i = 0; i < n; i++) out[`${dir}/icon-${String(i).padStart(3, '0')}.png`] = png(w, h);
  return out;
}
