/**
 * Fixture builders for the artifact scanner tests.
 *
 * Every artifact the tests scan is built here, at test time, from a few lines
 * of JavaScript: no binary blob is committed. The writers are deliberately
 * independent of the readers in src/artifacts — they follow the format specs
 * (APPNOTE for zip, POSIX ustar, ECMA-119 for ISO 9660), not the scanner's
 * code — so a reader bug cannot be cancelled out by the same bug in a writer.
 *
 * Planted secrets are assembled from pieces at runtime, so no file in this
 * repository contains a complete token shape for a secret scanner to trip on.
 */

import { deflateRawSync, gzipSync } from 'node:zlib';

// ── planted values ──────────────────────────────────────────────────────────

const rep = (s, n) => s.repeat(n);

export const PLANTED = {
  winPath: 'C:\\Users\\' + 'buildbot' + '\\.rustup\\toolchains\\stable',
  winPathSlash: 'C:/Users/' + 'buildbot' + '/.cargo/registry',
  winPathEscaped: 'C:\\\\Users\\\\' + 'buildbot' + '\\\\AppData',
  linuxHome: '/home/' + 'ci-runner' + '/work/app/target/release',
  macHome: '/Users/' + 'jdoe' + '/Library/Caches',
  email: 'release-' + 'owner' + '@' + 'corp-mail.io',
  aws: 'AKIA' + 'Z7Q3' + rep('K', 4) + 'EXAMPLE1',
  awsSecret: 'aws_secret_access_key = ' + rep('wJalrXUtnFEMI', 3) + 'K',
  ghp: 'ghp' + '_' + rep('a1B2c3', 6),
  githubPat: 'github' + '_pat_' + rep('11ABCDEFG', 4),
  privateKey: '-----BEGIN ' + 'RSA ' + 'PRIVATE KEY-----\n' + rep('MIIEpAIBAAKCAQEA', 4) + '\n',
  jwt:
    'eyJ' + 'hbGciOiJIUzI1NiJ9' + '.' + 'eyJ' + 'zdWIiOiIxMjM0NTY3ODkwIn0' + '.' + 'c2lnbmF0dXJlLXZhbHVl',
  npm: 'npm' + '_' + rep('Ab1', 12),
  slack: 'xox' + 'b-' + '123456789012-' + rep('x', 24),
  stripe: 'sk' + '_live_' + rep('4eC39HqLyjWDarjt', 2),
  google: 'AI' + 'za' + rep('Sy', 1) + rep('D3f', 11),
  // A deny term: something only the user knows is sensitive.
  denyTerm: 'Wombat' + 'Foundry',
};

/** One expected rule per planted value; deny-term needs --deny-terms. */
export const RULE_OF = {
  winPath: 'windows-home-path',
  winPathSlash: 'windows-home-path',
  winPathEscaped: 'windows-home-path',
  linuxHome: 'unix-home-path',
  macHome: 'unix-home-path',
  email: 'email-address',
  aws: 'aws-access-key-id',
  awsSecret: 'aws-secret-access-key',
  ghp: 'github-token',
  githubPat: 'github-token',
  privateKey: 'private-key',
  jwt: 'jwt',
  npm: 'npm-token',
  slack: 'slack-token',
  stripe: 'stripe-live-key',
  google: 'google-api-key',
  denyTerm: 'deny-term',
};

/** Text that looks close to every rule and must not match any of them. */
export const CLEAN_TEXT = [
  'Install to C:\\Users\\<name>\\.rustup or %USERPROFILE%; see C:\\Users\\Public\\Desktop\\',
  'Shared data lives in /Users/Shared/app/ and docs say /home/$USER/.config/',
  'https://example.com/home/page/ and /users/42/ are routes, not homes',
  'icons: logo@2x.png logo@3x.webp; clone git@github.com:org/repo.git; mail me at a@example.com',
  'versions: lodash@4.17.21 @types/node@20.1.0; BEGIN PUBLIC KEY is fine',
  'AKIA alone is not a key; ghp_short; eyJhbGciOiJIUzI1NiJ9 without a payload',
].join('\n');

export const utf16 = (s) => Buffer.from(s, 'utf16le');

// ── deterministic noise ─────────────────────────────────────────────────────

/** Bytes from a fixed LCG: binary-looking, identical on every run. */
export function noise(n, seed = 1) {
  const b = Buffer.alloc(n);
  let x = seed >>> 0;
  for (let i = 0; i < n; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    b[i] = x >>> 24;
  }
  return b;
}

// ── zip (APPNOTE 6.3) ───────────────────────────────────────────────────────

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

export function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * entries: [{ name, data, method?: 0|8|<other>, encrypted?: bool }]
 * A method other than 0/8 is written with the data stored, to exercise the
 * reader's "unsupported method" path.
 */
export function makeZip(entries, { zip64 = false } = {}) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? '');
    const method = e.method ?? 8;
    const body = method === 8 ? deflateRawSync(data) : data;
    const name = Buffer.from(e.name, 'utf8');
    const flags = 0x800 | (e.encrypted ? 1 : 0);
    const crc = crc32(data);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(flags, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    locals.push(lh, name, body);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(flags, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    if (zip64) {
      // Offset moved to the ZIP64 extended-information extra field (0x0001).
      ch.writeUInt32LE(0xffffffff, 42);
      const extra = Buffer.alloc(12);
      extra.writeUInt16LE(0x0001, 0);
      extra.writeUInt16LE(8, 2);
      extra.writeBigUInt64LE(BigInt(offset), 4);
      ch.writeUInt16LE(extra.length, 30);
      centrals.push(ch, name, extra);
    } else {
      centrals.push(ch, name);
    }
    offset += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
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
    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(0x07064b50, 0);
    locator.writeBigUInt64LE(BigInt(offset + cd.length), 8);
    locator.writeUInt32LE(1, 16);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(0xffff, 8);
    end.writeUInt16LE(0xffff, 10);
    end.writeUInt32LE(0xffffffff, 12);
    end.writeUInt32LE(0xffffffff, 16);
    return Buffer.concat([...locals, cd, rec, locator, end]);
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

/** A wheel is a zip with a dist-info directory; that is all the scanner sees. */
export function makeWheel(pkg, files) {
  return makeZip([
    ...files,
    { name: `${pkg}-1.0.dist-info/METADATA`, data: `Metadata-Version: 2.1\nName: ${pkg}\nVersion: 1.0\n` },
    { name: `${pkg}-1.0.dist-info/WHEEL`, data: 'Wheel-Version: 1.0\nRoot-Is-Purelib: true\n' },
    { name: `${pkg}-1.0.dist-info/RECORD`, data: '' },
  ]);
}

// ── tar (POSIX ustar) ───────────────────────────────────────────────────────

function octal(n, len) {
  return `${n.toString(8).padStart(len - 1, '0')}\0`;
}

/** entries: [{ name, data, uname?, type? }] */
export function makeTar(entries) {
  const blocks = [];
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? '');
    const h = Buffer.alloc(512);
    h.write(e.name, 0, 100, 'utf8');
    h.write(octal(0o644, 8), 100, 'latin1');
    h.write(octal(1000, 8), 108, 'latin1');
    h.write(octal(1000, 8), 116, 'latin1');
    h.write(octal(data.length, 12), 124, 'latin1');
    h.write(octal(0, 12), 136, 'latin1');
    h.write('        ', 148, 'latin1');
    h.write(e.type ?? '0', 156, 'latin1');
    h.write('ustar\x0000', 257, 'latin1');
    h.write(e.uname ?? 'builder', 265, 32, 'utf8');
    h.write('users', 297, 32, 'latin1');
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

/** An npm package: a gzipped tar whose entries live under `package/`. */
export function makeNpmTgz(files) {
  return gzipSync(
    makeTar([
      { name: 'package/package.json', data: '{"name":"fixture","version":"1.0.0"}' },
      ...files.map((f) => ({ ...f, name: `package/${f.name}` })),
    ])
  );
}

// ── ISO 9660 (ECMA-119) ─────────────────────────────────────────────────────

const SECTOR = 2048;

function both16(n) {
  const b = Buffer.alloc(4);
  b.writeUInt16LE(n, 0);
  b.writeUInt16BE(n, 2);
  return b;
}
function both32(n) {
  const b = Buffer.alloc(8);
  b.writeUInt32LE(n, 0);
  b.writeUInt32BE(n, 4);
  return b;
}

function dirRecord(name, extent, size, isDir) {
  const id = typeof name === 'number' ? Buffer.from([name]) : Buffer.from(name, 'latin1');
  const len = 33 + id.length + (id.length % 2 === 0 ? 1 : 0);
  const r = Buffer.alloc(len);
  r[0] = len;
  both32(extent).copy(r, 2);
  both32(size).copy(r, 10);
  Buffer.from([126, 1, 1, 0, 0, 0, 0]).copy(r, 18); // 2026-01-01 00:00:00
  r[25] = isDir ? 2 : 0;
  both16(1).copy(r, 28);
  r[32] = id.length;
  id.copy(r, 33);
  return r;
}

/**
 * files: [{ path: 'DIR/NAME.EXT' | 'NAME.EXT', data }] — at most one level of
 * directories, names in ISO 9660 d-characters. Enough to put bytes where a
 * real image puts them: in file extents, addressed by directory records.
 */
export function makeIso(files, { volumeId = 'FIXTURE' } = {}) {
  const dirs = [...new Set(files.filter((f) => f.path.includes('/')).map((f) => f.path.split('/')[0]))];
  // Layout: 0-15 system area, 16 PVD, 17 terminator, 18 and 19 the L and M
  // path tables, 20 root directory, one sector per subdirectory, file data.
  const ROOT = 20;
  let next = ROOT + 1 + dirs.length;
  const placed = files.map((f) => {
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data);
    const extent = next;
    next += Math.max(1, Math.ceil(data.length / SECTOR));
    return { ...f, data, extent };
  });
  const dirExtent = (d) => ROOT + 1 + dirs.indexOf(d);

  const dirSector = (selfExtent, parentExtent, children) => {
    const recs = [dirRecord(0, selfExtent, SECTOR, true), dirRecord(1, parentExtent, SECTOR, true), ...children];
    const s = Buffer.concat(recs);
    if (s.length > SECTOR) throw new Error('fixture directory too large');
    return Buffer.concat([s, Buffer.alloc(SECTOR - s.length)]);
  };

  const rootChildren = [
    ...dirs.map((d) => dirRecord(d, dirExtent(d), SECTOR, true)),
    ...placed.filter((f) => !f.path.includes('/')).map((f) => dirRecord(`${f.path};1`, f.extent, f.data.length, false)),
  ];
  const image = Buffer.alloc(next * SECTOR);
  dirSector(ROOT, ROOT, rootChildren).copy(image, ROOT * SECTOR);
  for (const d of dirs) {
    const kids = placed
      .filter((f) => f.path.startsWith(`${d}/`))
      .map((f) => dirRecord(`${f.path.slice(d.length + 1)};1`, f.extent, f.data.length, false));
    dirSector(dirExtent(d), ROOT, kids).copy(image, dirExtent(d) * SECTOR);
  }
  for (const f of placed) f.data.copy(image, f.extent * SECTOR);

  const pvd = Buffer.alloc(SECTOR, 0x20);
  pvd[0] = 1;
  pvd.write('CD001', 1, 'latin1');
  pvd[6] = 1;
  pvd[7] = 0;
  pvd.write(volumeId.padEnd(32), 40, 'latin1');
  pvd.fill(0, 72, 80);
  both32(next).copy(pvd, 80);
  pvd.fill(0, 88, 120);
  both16(1).copy(pvd, 120);
  both16(1).copy(pvd, 124);
  both16(SECTOR).copy(pvd, 128);
  const pathTable = (be) =>
    Buffer.concat(
      [['\0', ROOT], ...dirs.map((d) => [d, dirExtent(d)])].map(([name, extent]) => {
        const id = Buffer.from(name, 'latin1');
        const r = Buffer.alloc(8 + id.length + (id.length % 2));
        r[0] = id.length;
        if (be) r.writeUInt32BE(extent, 2), r.writeUInt16BE(1, 6);
        else r.writeUInt32LE(extent, 2), r.writeUInt16LE(1, 6);
        id.copy(r, 8);
        return r;
      })
    );
  const lTable = pathTable(false);
  pathTable(true).copy(image, 19 * SECTOR);
  lTable.copy(image, 18 * SECTOR);
  both32(lTable.length).copy(pvd, 132);
  pvd.writeUInt32LE(18, 140);
  pvd.writeUInt32BE(19, 148);
  dirRecord(0, ROOT, SECTOR, true).copy(pvd, 156);
  pvd[881] = 1;
  pvd.fill(0, 882);
  pvd.copy(image, 16 * SECTOR);

  const term = Buffer.alloc(SECTOR);
  term[0] = 255;
  term.write('CD001', 1, 'latin1');
  term[6] = 1;
  term.copy(image, 17 * SECTOR);
  return image;
}

/** A UDF-only image: an extended-area descriptor and no ISO 9660 tree. */
export function makeUdfOnly(payload) {
  const image = Buffer.alloc(20 * SECTOR);
  image.write('\0BEA01\x01', 16 * SECTOR, 'latin1');
  image.write('\0NSR02\x01', 17 * SECTOR, 'latin1');
  image.write('\0TEA01\x01', 18 * SECTOR, 'latin1');
  return Buffer.concat([image, Buffer.from(payload)]);
}

// ── PE-shaped binary ────────────────────────────────────────────────────────

/**
 * Not a runnable executable — the scanner does not parse PE, it reads bytes —
 * but laid out like one: an MZ stub, a PE signature, binary noise, then
 * strings the way a compiler and a resource compiler leave them: ASCII in
 * .rdata, UTF-16LE in .rsrc.
 */
export function makePe({ ascii = [], utf16le = [], seed = 7 } = {}) {
  const stub = Buffer.alloc(0x80);
  stub.write('MZ', 0, 'latin1');
  stub.writeUInt32LE(0x80, 0x3c);
  stub.write('This program cannot be run in DOS mode.\r\r\n$', 0x4e, 'latin1');
  const parts = [stub, Buffer.from('PE\0\0', 'latin1'), noise(4096, seed)];
  for (const s of ascii) parts.push(Buffer.from(`${s}\0`, 'utf8'), noise(512, seed + 1));
  // An odd-length pad first: UTF-16 text at an odd file offset must still be found.
  parts.push(Buffer.from([0]));
  for (const s of utf16le) parts.push(utf16(`${s}\0`), noise(512, seed + 2));
  return Buffer.concat(parts);
}
