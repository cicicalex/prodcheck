/**
 * Tests for the byte-level half of the claims verifier: the ZIP reader, the
 * image header parser, the glob matcher, and the zip/directory manifest.
 *
 * Every archive is built at test time by tests/helpers/claims-fixtures.mjs.
 * Each capability has a positive control (it reads what is there) and a
 * negative one (it refuses or reports what is wrong).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { symlinkSync } from 'node:fs';
import path from 'node:path';
import { readZip, crc32, CP437_HIGH } from '../src/claims/zip.mjs';
import { imageSize } from '../src/claims/imagesize.mjs';
import { compileGlob } from '../src/claims/glob.mjs';
import { loadSource } from '../src/claims/source.mjs';
import {
  buildZip, png, gif, webpLossy, webpLossless, webpExtended, jpeg, writeTree, writeZip,
} from './helpers/claims-fixtures.mjs';

// ---------------------------------------------------------------- images

test('imageSize: PNG width and height from IHDR', () => {
  assert.deepEqual(imageSize(png(128, 64)), { format: 'png', width: 128, height: 64 });
});

test('imageSize: GIF logical screen size', () => {
  assert.deepEqual(imageSize(gif(300, 2)), { format: 'gif', width: 300, height: 2 });
});

test('imageSize: WebP lossy (VP8), lossless (VP8L) and extended (VP8X)', () => {
  assert.deepEqual(imageSize(webpLossy(100, 30)), { format: 'webp', width: 100, height: 30 });
  assert.deepEqual(imageSize(webpLossless(17, 9)), { format: 'webp', width: 17, height: 9 });
  assert.deepEqual(imageSize(webpLossless(16384, 1)), { format: 'webp', width: 16384, height: 1 });
  assert.deepEqual(imageSize(webpExtended(5000, 3000)), { format: 'webp', width: 5000, height: 3000 });
});

test('imageSize: JPEG baseline and progressive, frame header after APP0', () => {
  assert.deepEqual(imageSize(jpeg(64, 48)), { format: 'jpeg', width: 64, height: 48 });
  assert.deepEqual(imageSize(jpeg(1920, 1080, 0xc2)), { format: 'jpeg', width: 1920, height: 1080 });
});

test('imageSize: negative controls — not an image, truncated, JPEG without a frame', () => {
  assert.equal(imageSize(Buffer.from('just some text, not pixels')), null);
  assert.equal(imageSize(png(32, 32).subarray(0, 20)), null);
  assert.equal(imageSize(Buffer.alloc(0)), null);
  // DHT (0xc4) sits in the SOF range and must not be read as a frame header.
  const dht = Buffer.from([0xff, 0xc4, 0x00, 0x0a, 0, 0, 0x40, 0, 0x30, 0, 0, 0]);
  const noFrame = Buffer.concat([Buffer.from([0xff, 0xd8]), dht, Buffer.from([0xff, 0xd9])]);
  assert.deepEqual(imageSize(noFrame), { format: 'jpeg', width: null, height: null });
});

// ---------------------------------------------------------------- zip

test('readZip: stored and deflated entries round-trip with counted sizes', () => {
  const big = Buffer.alloc(10000, 7);
  const zip = buildZip([
    { name: 'a.txt', data: 'hello', deflate: false },
    { name: 'dir/' },
    { name: 'dir/b.bin', data: big, deflate: true },
  ]);
  const seen = {};
  const { entries, problems } = readZip(zip, (e, bytes) => (seen[e.name] = bytes));
  assert.deepEqual(problems, []);
  assert.deepEqual(entries.map((e) => [e.name, e.isDir, e.size, e.method]), [
    ['a.txt', false, 5, 0],
    ['dir/', true, 0, 0],
    ['dir/b.bin', false, 10000, 8],
  ]);
  assert.equal(seen['a.txt'].toString(), 'hello');
  assert.ok(seen['dir/b.bin'].equals(big));
});

test('readZip: ZIP64 end records and extra fields', () => {
  const { entries, problems } = readZip(buildZip([{ name: 'x.png', data: png(8, 8) }, { name: 'y.txt', data: 'yy' }], { zip64: true }));
  assert.deepEqual(problems, []);
  assert.deepEqual(entries.map((e) => [e.name, e.size]), [['x.png', png(8, 8).length], ['y.txt', 2]]);
});

test('readZip: a CRC that does not match the data is a problem, not trusted', () => {
  const { problems } = readZip(buildZip([{ name: 'a.txt', data: 'hello', crc: 0xdeadbeef }]));
  assert.equal(problems.length, 1);
  assert.match(problems[0], /a\.txt: CRC-32 mismatch \(directory deadbeef/);
});

test('readZip: a declared size that lies is reported, and the counted size wins', () => {
  const { entries, problems } = readZip(buildZip([{ name: 'a.txt', data: 'hello', declaredSize: 999 }]));
  assert.match(problems[0], /directory says 999 bytes, data is 5 bytes/);
  assert.equal(entries[0].size, 5);
});

test('readZip: unsupported method, encryption and duplicate names are reported', () => {
  const { problems } = readZip(buildZip([
    { name: 'bz.bin', data: 'x', method: 12, deflate: false },
    { name: 'secret.txt', data: 'x', encrypted: true },
    { name: 'dup.txt', data: '1' },
    { name: 'dup.txt', data: '2' },
  ]));
  assert.deepEqual(problems, [
    'bz.bin: unsupported compression method 12',
    'secret.txt: encrypted entry, content cannot be verified',
    'dup.txt: duplicate entry name',
  ]);
});

test('readZip: not a zip, or a truncated one, throws', () => {
  assert.throws(() => readZip(Buffer.from('definitely not a zip file, just text here')), /not a zip archive/);
  const zip = buildZip([{ name: 'a.txt', data: 'hello' }]);
  assert.throws(() => readZip(zip.subarray(0, zip.length - 5)), /not a zip archive/);
});

test('readZip: name encodings — UTF-8 flag, unflagged UTF-8, CP437, Unicode Path field', () => {
  assert.equal(CP437_HIGH.length, 128);
  const unicodePath = (legacy, name) => {
    const utf = Buffer.from(name, 'utf8');
    const b = Buffer.alloc(9 + utf.length);
    b.writeUInt16LE(0x7075, 0);
    b.writeUInt16LE(5 + utf.length, 2);
    b[4] = 1;
    b.writeUInt32LE(crc32(legacy), 5);
    utf.copy(b, 9);
    return b;
  };
  const legacy = Buffer.from('pictograme/x.png');
  const { entries } = readZip(buildZip([
    { name: 'ștergere.txt', data: 'a', utf8Flag: true },
    { name: 'ștergere2.txt', data: 'a', utf8Flag: false },
    { name: 'cp', nameBytes: Buffer.from([0x63, 0x61, 0x66, 0x82]), utf8Flag: false, data: 'a' }, // "caf" + é in CP437
    { name: 'u', nameBytes: legacy, utf8Flag: false, extra: unicodePath(legacy, 'pictograme/ș.png'), data: 'a' },
  ]));
  assert.deepEqual(entries.map((e) => [e.name, e.encoding]), [
    ['ștergere.txt', 'utf-8'],
    ['ștergere2.txt', 'utf-8 (unflagged)'],
    ['café', 'cp437'],
    ['pictograme/ș.png', 'utf-8 (unicode path field)'],
  ]);
});

test('readZip: a stale Unicode Path field (CRC of another name) is ignored', () => {
  const b = Buffer.alloc(9 + 5);
  b.writeUInt16LE(0x7075, 0);
  b.writeUInt16LE(10, 2);
  b[4] = 1;
  b.writeUInt32LE(crc32(Buffer.from('old-name')), 5);
  Buffer.from('wrong').copy(b, 9);
  const { entries } = readZip(buildZip([{ name: 'real.txt', data: 'a', extra: b }]));
  assert.equal(entries[0].name, 'real.txt');
});

// ---------------------------------------------------------------- glob

test('glob: unanchored names match at any depth; anchored paths from the root', () => {
  const ds = compileGlob('.DS_Store');
  assert.ok(ds.test('.DS_Store', false));
  assert.ok(ds.test('a/b/.DS_Store', false));
  assert.ok(!ds.test('a/x.DS_Store', false));
  const icons = compileGlob('icons/*.png');
  assert.ok(icons.test('icons/a.png', false));
  assert.ok(!icons.test('pack/icons/a.png', false));
  assert.ok(!icons.test('icons/sub/a.png', false));
});

test('glob: ** spans segments (including none), {a,b} alternates, trailing / is directories only', () => {
  const deep = compileGlob('**/icons/**/*.png');
  assert.ok(deep.test('icons/a.png', false));
  assert.ok(deep.test('Pack/icons/32/a.png', false));
  assert.ok(!deep.test('Pack/icons/32/a.PNG', false), 'case-sensitive');
  const alt = compileGlob('**/*.{png,PNG}');
  assert.ok(alt.test('a.PNG', false) && alt.test('x/a.png', false));
  const mac = compileGlob('__MACOSX/');
  assert.ok(mac.test('__MACOSX', true));
  assert.ok(mac.test('Pack/__MACOSX', true));
  assert.ok(!mac.test('__MACOSX', false), 'a file with that name is not the folder');
  assert.ok(compileGlob('a.b').test('a.b', false) && !compileGlob('a.b').test('axb', false), 'dot is literal');
});

// ---------------------------------------------------------------- manifest

test('loadSource: a zip and the same directory produce the same manifest', () => {
  const tree = { 'icons/a.png': png(32, 32), 'icons/b.gif': gif(16, 16), 'README.md': '# hi', 'empty/': null };
  const fromDir = loadSource(writeTree(tree));
  const fromZip = loadSource(writeZip(tree));
  assert.equal(fromDir.kind, 'directory');
  assert.equal(fromZip.kind, 'zip');
  assert.deepEqual(fromZip.files, fromDir.files);
  assert.deepEqual(fromZip.dirs, ['empty', 'icons']);
  assert.deepEqual(fromDir.dirs, ['empty', 'icons']);
  assert.deepEqual(fromZip.files.map((f) => [f.path, f.ext, f.image?.width ?? null]), [
    ['README.md', 'md', null],
    ['icons/a.png', 'png', 32],
    ['icons/b.gif', 'gif', 16],
  ]);
});

test('loadSource: path traversal and backslashes in a zip are integrity problems', () => {
  const zip = writeZip({ '../evil.txt': 'x', 'win\\style.txt': 'y' });
  const { problems } = loadSource(zip);
  assert.deepEqual(problems, [
    '../evil.txt: path escapes the extraction directory',
    'win\\style.txt: backslash in entry name, extracts differently per platform',
  ]);
});

test('loadSource: a symlink in a directory is reported, not followed', (t) => {
  const root = writeTree({ 'a.txt': 'a' });
  try {
    symlinkSync(path.join(root, 'a.txt'), path.join(root, 'link.txt'));
  } catch (err) {
    t.skip(`cannot create symlinks here: ${err.code}`);
    return;
  }
  const { files, problems } = loadSource(root);
  assert.deepEqual(files.map((f) => f.path), ['a.txt']);
  assert.match(problems[0], /^link\.txt: not a regular file/);
});

test('loadSource: a missing path throws', () => {
  assert.throws(() => loadSource('/nonexistent/prodcheck/pack.zip'), /cannot read path/);
});
