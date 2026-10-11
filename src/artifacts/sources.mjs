/**
 * Byte sources: one read interface over a file on disk, a buffer in memory,
 * and a window into either.
 *
 * Artifacts are big — an ISO is gigabytes — and most of what sits inside a
 * container is stored, not compressed: the files of an ISO 9660 image, the
 * members of a tar, a stored zip entry. Those become *slices* of their parent
 * and are never copied. Only decompression creates new bytes, and it starts a
 * new root.
 *
 * `root` and `base` exist for one purpose: the scanner reads every container's
 * bytes twice — once entry by entry, once whole, to catch what lives between
 * the entries (headers, padding, appended data) — and must not report the same
 * bytes twice. A match at offset `o` of a slice is at `base + o` of its root,
 * and that pair names the byte whichever way it was reached.
 */

import { closeSync, fstatSync, openSync, readSync } from 'node:fs';

export class FileSource {
  constructor(file) {
    this.fd = openSync(file, 'r');
    this.size = fstatSync(this.fd).size;
    this.root = this;
    this.base = 0;
  }

  read(pos, len) {
    const n = Math.max(0, Math.min(len, this.size - pos));
    const buf = Buffer.allocUnsafe(n);
    let got = 0;
    while (got < n) {
      const r = readSync(this.fd, buf, got, n - got, pos + got);
      if (!r) break;
      got += r;
    }
    return buf.subarray(0, got);
  }

  close() {
    closeSync(this.fd);
  }
}

export class BufferSource {
  constructor(buf) {
    this.buf = buf;
    this.size = buf.length;
    this.root = this;
    this.base = 0;
  }

  read(pos, len) {
    return this.buf.subarray(Math.max(0, pos), Math.max(0, Math.min(this.size, pos + len)));
  }
}

/** A window [start, start+len) of `parent`, clamped to the parent's end. */
export function slice(parent, start, len) {
  const s = Math.max(0, Math.min(start, parent.size));
  const size = Math.max(0, Math.min(len, parent.size - s));
  return {
    size,
    root: parent.root,
    base: parent.base + s,
    truncated: size < len,
    read: (pos, n) => parent.read(s + pos, Math.max(0, Math.min(n, size - pos))),
  };
}

/** The whole of `src` as one buffer — only for what must be decompressed. */
export function readAll(src) {
  return src.read(0, src.size);
}
