/**
 * Image dimensions from header bytes, for PNG, GIF, WebP and JPEG.
 *
 * The format is decided by magic bytes, never by the file name — a `.png` that
 * is really a JPEG is exactly the kind of thing a page can get wrong, so the
 * caller gets both and can compare. Only headers are parsed; no pixel data is
 * decoded, so a file whose header is intact but whose body is garbage still
 * reports its declared size. That is a stated limit, not an oversight.
 */

/** Canonical format name per lowercase extension, for the content-vs-name check. */
export const IMAGE_EXTENSIONS = {
  png: 'png',
  gif: 'gif',
  webp: 'webp',
  jpg: 'jpeg',
  jpeg: 'jpeg',
  jpe: 'jpeg',
  jfif: 'jpeg',
};

function png(b) {
  // Signature, then IHDR as the first chunk: length(4) "IHDR" width height.
  if (b.length < 24) return null;
  if (b.readUInt32BE(0) !== 0x89504e47 || b.readUInt32BE(4) !== 0x0d0a1a0a) return null;
  if (b.toString('latin1', 12, 16) !== 'IHDR') return { format: 'png', width: null, height: null };
  return { format: 'png', width: b.readUInt32BE(16), height: b.readUInt32BE(20) };
}

function gif(b) {
  if (b.length < 10) return null;
  const sig = b.toString('latin1', 0, 6);
  if (sig !== 'GIF87a' && sig !== 'GIF89a') return null;
  return { format: 'gif', width: b.readUInt16LE(6), height: b.readUInt16LE(8) };
}

function webp(b) {
  if (b.length < 16) return null;
  if (b.toString('latin1', 0, 4) !== 'RIFF' || b.toString('latin1', 8, 12) !== 'WEBP') return null;
  const chunk = b.toString('latin1', 12, 16);
  const unknown = { format: 'webp', width: null, height: null };
  if (chunk === 'VP8 ') {
    // Lossy: frame tag (3) then start code 9d 01 2a, then 14-bit sizes.
    if (b.length < 30 || b[23] !== 0x9d || b[24] !== 0x01 || b[25] !== 0x2a) return unknown;
    return { format: 'webp', width: b.readUInt16LE(26) & 0x3fff, height: b.readUInt16LE(28) & 0x3fff };
  }
  if (chunk === 'VP8L') {
    // Lossless: signature 0x2f, then width-1 and height-1 as packed 14-bit fields.
    if (b.length < 25 || b[20] !== 0x2f) return unknown;
    const bits = b.readUInt32LE(21);
    return { format: 'webp', width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
  }
  if (chunk === 'VP8X') {
    // Extended: canvas width-1 and height-1 as 24-bit little-endian.
    if (b.length < 30) return unknown;
    return { format: 'webp', width: b.readUIntLE(24, 3) + 1, height: b.readUIntLE(27, 3) + 1 };
  }
  return unknown;
}

function jpeg(b) {
  if (b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) return null;
  let p = 2;
  while (p + 4 <= b.length) {
    if (b[p] !== 0xff) return { format: 'jpeg', width: null, height: null };
    const marker = b[p + 1];
    if (marker === 0xff) {
      p += 1; // fill byte
      continue;
    }
    // Standalone markers carry no length.
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
      p += 2;
      continue;
    }
    if (marker === 0xd9 || marker === 0xda) break; // end of image / start of scan
    const len = b.readUInt16BE(p + 2);
    // SOF0..SOF15, excluding DHT (c4), JPG (c8) and DAC (cc).
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      if (p + 9 > b.length) break;
      return { format: 'jpeg', width: b.readUInt16BE(p + 7), height: b.readUInt16BE(p + 5) };
    }
    p += 2 + len;
  }
  return { format: 'jpeg', width: null, height: null };
}

/**
 * @param {Buffer} bytes
 * @returns {{format: string, width: number|null, height: number|null} | null}
 *   null when the bytes are none of the four formats.
 */
export function imageSize(bytes) {
  return png(bytes) ?? gif(bytes) ?? webp(bytes) ?? jpeg(bytes);
}
