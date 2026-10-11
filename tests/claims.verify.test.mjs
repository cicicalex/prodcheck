/**
 * Tests for the claims half of the verifier: every claim type in a claims file
 * gets a positive control (true claim -> PASS) and a negative control (false
 * claim -> FAIL with expected vs actual), checked against archives built at
 * test time. Then the strict parser, the generator, and the CLI contract.
 *
 * The motivating incident is the first test: a page saying "128 icons" over an
 * archive holding 127.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseClaims, verifyClaims, foldText, htmlToText, parseBytes } from '../src/claims/verify.mjs';
import { generateClaims, pageFacts } from '../src/claims/generate.mjs';
import { loadSource } from '../src/claims/source.mjs';
import { buildZip, png, gif, jpeg, webpLossy, writeTree, writeZip, icons, tempDir } from './helpers/claims-fixtures.mjs';

const CLI = fileURLToPath(new URL('../src/claims/cli.mjs', import.meta.url));

/** Verify `claims` against a zip of `tree`; returns {id: result}. */
function run(tree, claims, page = null) {
  const results = verifyClaims(parseClaims({ schemaVersion: 1, ...claims }), loadSource(writeZip(tree)), page);
  return Object.fromEntries(results.map((r) => [r.id, r]));
}
const pass = (r) => assert.equal(r?.status, 'PASS', JSON.stringify(r));
const fail = (r) => assert.equal(r?.status, 'FAIL', JSON.stringify(r));

const ICON_CLAIMS = {
  groups: [{ name: 'icons', glob: 'icons/*.png', count: 128, dimensions: ['32x32'] }],
  page: { counts: [{ regex: '(\\d[\\d,]*)\\s+icons', group: 'icons' }] },
};
const PAGE = 'A pack of 128 icons, hand-drawn, 32x32.';

// ---------------------------------------------------------------- the incident

test('incident: page says "128 icons", archive has 127 -> both count claims FAIL', () => {
  const r = run(icons(127), ICON_CLAIMS, PAGE);
  fail(r['groups.icons.count']);
  assert.equal(r['groups.icons.count'].expected, '128');
  assert.equal(r['groups.icons.count'].actual, '127');
  const pageCount = r['page.counts.(\\d[\\d,]*)\\s+icons'];
  fail(pageCount);
  assert.equal(pageCount.expected, '127');
  assert.deepEqual(pageCount.details, ['page says "128 icons", archive has 127']);
});

test('incident control: 128 icons on the page and 128 in the archive -> PASS', () => {
  const r = run(icons(128), ICON_CLAIMS, PAGE);
  pass(r['groups.icons.count']);
  pass(r['page.counts.(\\d[\\d,]*)\\s+icons']);
  pass(r['groups.icons.dimensions']);
});

// ---------------------------------------------------------------- files

test('files.total: exact and range, pass and fail', () => {
  const tree = { 'a.txt': 'a', 'b.txt': 'b', 'c.png': png(1, 1) };
  pass(run(tree, { files: { total: 3 } })['files.total']);
  pass(run(tree, { files: { total: { min: 2, max: 5 } } })['files.total']);
  const r = run(tree, { files: { total: 4 } })['files.total'];
  fail(r);
  assert.equal(r.actual, '3');
});

test('files.byExtension: per-extension counts, dot and case insensitive keys', () => {
  const tree = { 'a.PNG': png(1, 1), 'b.png': png(1, 1), 'c.txt': 'c', Makefile: 'm' };
  const ok = run(tree, { files: { byExtension: { '.png': 2, txt: 1, '': 1 } } });
  pass(ok['files.byExtension.png']);
  pass(ok['files.byExtension.txt']);
  pass(ok['files.byExtension.(none)']);
  const bad = run(tree, { files: { byExtension: { png: 3, svg: 1 } } });
  fail(bad['files.byExtension.png']);
  fail(bad['files.byExtension.svg']);
  assert.equal(bad['files.byExtension.svg'].actual, '0');
});

test('files.exhaustive: an unlisted file type FAILs and is named', () => {
  const tree = { 'a.png': png(1, 1), 'notes.psd': 'x' };
  pass(run({ 'a.png': png(1, 1) }, { files: { byExtension: { png: 1 }, exhaustive: true } })['files.exhaustive']);
  const r = run(tree, { files: { byExtension: { png: 1 }, exhaustive: true } })['files.exhaustive'];
  fail(r);
  assert.deepEqual(r.details, ['notes.psd']);
});

// ---------------------------------------------------------------- groups / dimensions

test('groups.dimensions: allowed set, every claimed size must exist', () => {
  const tree = { 'i/a.png': png(16, 16), 'i/b.png': png(32, 32) };
  pass(run(tree, { groups: [{ name: 'i', glob: 'i/*', dimensions: ['16x16', '32x32'] }] })['groups.i.dimensions']);
  pass(run({ 'i/a.png': png(16, 16) }, { groups: [{ name: 'i', glob: 'i/*', dimensions: '16 x 16' }] })['groups.i.dimensions']);

  const off = run(tree, { groups: [{ name: 'i', glob: 'i/*', dimensions: ['16x16'] }] })['groups.i.dimensions'];
  fail(off);
  assert.deepEqual(off.details, ['i/b.png: 32x32']);

  const missing = run(tree, { groups: [{ name: 'i', glob: 'i/*', dimensions: ['16x16', '32x32', '64x64'] }] })['groups.i.dimensions'];
  fail(missing);
  assert.deepEqual(missing.details, ['claimed 64x64 but no file has it']);
});

test('groups.dimensions: all four formats, a non-image member, and an empty group', () => {
  const tree = { 'i/a.png': png(8, 8), 'i/b.gif': gif(8, 8), 'i/c.jpg': jpeg(8, 8), 'i/d.webp': webpLossy(8, 8) };
  pass(run(tree, { groups: [{ name: 'i', glob: 'i/*', count: 4, dimensions: ['8x8'] }] })['groups.i.dimensions']);

  const notImage = run({ ...tree, 'i/e.png': 'not a png' }, { groups: [{ name: 'i', glob: 'i/*', dimensions: ['8x8'] }] })['groups.i.dimensions'];
  fail(notImage);
  assert.deepEqual(notImage.details, ['i/e.png: not a PNG/GIF/WebP/JPEG image']);

  const empty = run(tree, { groups: [{ name: 'g', glob: 'nowhere/*.png', dimensions: ['8x8'] }] })['groups.g.dimensions'];
  fail(empty);
  assert.equal(empty.actual, 'no files matched');
});

// ---------------------------------------------------------------- size

test('totalBytes: uncompressed bytes in range, units accepted', () => {
  const tree = { 'a.bin': Buffer.alloc(1500), 'b.bin': Buffer.alloc(500) }; // deflates to almost nothing
  pass(run(tree, { totalBytes: 2000 }).totalBytes);
  pass(run(tree, { totalBytes: { min: '1 KB', max: '2 KB' } }).totalBytes);
  const r = run(tree, { totalBytes: { min: '1 MB' } }).totalBytes;
  fail(r);
  assert.equal(r.actual, '2,000 B');
  assert.equal(parseBytes('1.5 MiB', 'x'), 1572864);
  assert.throws(() => parseBytes('lots', 'claims.totalBytes'), /size like "12 MB"/);
});

// ---------------------------------------------------------------- paths / names / docs

test('paths.required: files and folders, anchored and unanchored', () => {
  const tree = { 'Pack/icons/a.png': png(1, 1), 'Pack/LICENSE.txt': 'MIT' };
  const r = run(tree, { paths: { required: ['Pack/icons/', 'LICENSE.txt', 'Pack/*.txt'] } });
  pass(r['paths.required.Pack/icons/']);
  pass(r['paths.required.LICENSE.txt']);
  pass(r['paths.required.Pack/*.txt']);
  const missing = run(tree, { paths: { required: ['README*', '/icons/', 'icons/'] } });
  fail(missing['paths.required.README*']);
  fail(missing['paths.required./icons/'], 'a leading / anchors: icons/ is not at the root');
  pass(missing['paths.required.icons/'], 'no inner / means any depth, as in .gitignore');
});

test('paths.forbidden: junk folders and files anywhere in the tree', () => {
  const clean = run({ 'a.png': png(1, 1) }, { paths: { forbidden: ['__MACOSX/', '.DS_Store'] } });
  pass(clean['paths.forbidden.__MACOSX/']);
  pass(clean['paths.forbidden..DS_Store']);
  const dirty = run(
    { 'a.png': png(1, 1), '__MACOSX/._a.png': 'x', 'icons/.DS_Store': 'x' },
    { paths: { forbidden: ['__MACOSX/', '.DS_Store'] } }
  );
  fail(dirty['paths.forbidden.__MACOSX/']);
  assert.deepEqual(dirty['paths.forbidden.__MACOSX/'].details, ['__MACOSX/']);
  assert.deepEqual(dirty['paths.forbidden..DS_Store'].details, ['icons/.DS_Store']);
});

test('names.asciiOnly: a non-English (non-ASCII) folder name FAILs', () => {
  pass(run({ 'icons/delete.png': png(1, 1) }, { names: { asciiOnly: true } })['names.asciiOnly']);
  const r = run({ 'pictograme/ștergere.png': png(1, 1) }, { names: { asciiOnly: true } })['names.asciiOnly'];
  fail(r);
  assert.deepEqual(r.details, ['pictograme/ștergere.png']);
});

test('names.forbiddenRegex: an ASCII non-English folder name is caught by a word list', () => {
  const claims = { names: { forbiddenRegex: ['^(pictograme|imagini|iconite)$'] } };
  pass(run({ 'icons/a.png': png(1, 1) }, claims)['names.forbiddenRegex.^(pictograme|imagini|iconite)$']);
  const r = run({ 'Pictograme/a.png': png(1, 1) }, claims)['names.forbiddenRegex.^(pictograme|imagini|iconite)$'];
  fail(r);
  assert.deepEqual(r.details, ['Pictograme/']);
});

test('docs.license / docs.readme: present and non-empty, anywhere', () => {
  const ok = run({ 'Pack/LICENSE.md': 'MIT', 'Pack/ReadMe.txt': 'hi' }, { docs: { license: true, readme: true } });
  pass(ok['docs.license']);
  pass(ok['docs.readme']);
  const bad = run({ 'Pack/LICENSE': '', 'Pack/icons.png': png(1, 1) }, { docs: { license: true, readme: true } });
  fail(bad['docs.license'], 'an empty licence file is not a licence');
  fail(bad['docs.readme']);
});

test('images.contentMatchesExtension: a JPEG named .png FAILs', () => {
  pass(run({ 'a.png': png(1, 1), 'b.jpeg': jpeg(1, 1), 'c.txt': 't' }, { images: { contentMatchesExtension: true } })['images.contentMatchesExtension']);
  const r = run({ 'a.png': jpeg(1, 1), 'b.gif': 'text', 'c.dat': png(1, 1) }, { images: { contentMatchesExtension: true } })['images.contentMatchesExtension'];
  fail(r);
  assert.deepEqual(r.details, [
    'a.png: named .png, content is jpeg',
    'b.gif: named .gif, content is not an image',
    'c.dat: content is png, name says .dat',
  ]);
});

// ---------------------------------------------------------------- page

test('page.required: phrase present (folded) passes, absent fails', () => {
  const r = run({ 'a.png': png(1, 1) }, { page: { required: ['MIT licence', 'commercial use'] } }, 'Released under the MIT   Licence.');
  pass(r['page.required.MIT licence']);
  fail(r['page.required.commercial use']);
});

test('page.forbidden: "no AI" and "on disk" caught through case, hyphens and width', () => {
  const claims = { page: { forbidden: ['no AI', 'on disk'] } };
  const clean = run({ 'a.png': png(1, 1) }, claims, 'Drawn by hand. Download the ZIP.');
  pass(clean['page.forbidden.no AI']);
  pass(clean['page.forbidden.on disk']);
  for (const text of ['NO AI used', 'Made with No-AI tools', 'ｎｏ ＡＩ', 'no\nAI', 'Stored ON  DISK']) {
    const r = run({ 'a.png': png(1, 1) }, claims, text);
    assert.ok(r['page.forbidden.no AI'].status === 'FAIL' || r['page.forbidden.on disk'].status === 'FAIL', text);
  }
});

test('page.forbidden: whole words only — "piano air" does not contain "no ai"', () => {
  pass(run({ 'a.png': png(1, 1) }, { page: { forbidden: ['no AI'] } }, 'piano air, casino aisle, Piano AI.')['page.forbidden.no AI']);
});

test('page.counts: thousands separators, every occurrence checked, absent pattern FAILs', () => {
  const tree = icons(1024, 8, 8);
  const claims = { groups: [{ name: 'icons', glob: 'icons/*', count: 1024 }], page: { counts: [{ regex: '(\\d[\\d,]*)\\s+icons', group: 'icons' }] } };
  pass(run(tree, claims, '1,024 icons in total. Yes, 1024 icons.')['page.counts.(\\d[\\d,]*)\\s+icons']);
  const twoNumbers = run(tree, claims, '1,024 icons here, 1000 icons there.')['page.counts.(\\d[\\d,]*)\\s+icons'];
  fail(twoNumbers);
  assert.deepEqual(twoNumbers.details, ['page says "1000 icons", archive has 1024']);
  const absent = run(tree, claims, 'A lot of pictures.')['page.counts.(\\d[\\d,]*)\\s+icons'];
  fail(absent);
  assert.equal(absent.actual, 'pattern not found on page');
});

test('page.counts: by extension and by total', () => {
  const tree = { 'a.png': png(1, 1), 'b.png': png(1, 1), 'c.svg': '<svg/>' };
  const claims = { page: { counts: [{ regex: '(\\d+) PNG', extension: '.png' }, { regex: '(\\d+) files', total: true }] } };
  const ok = run(tree, claims, '2 PNG, 3 files');
  pass(ok['page.counts.(\\d+) PNG']);
  pass(ok['page.counts.(\\d+) files']);
  const bad = run(tree, claims, '3 PNG, 2 files');
  fail(bad['page.counts.(\\d+) PNG']);
  fail(bad['page.counts.(\\d+) files']);
});

test('page.dimensionsExist: every WxH on the page exists in the archive', () => {
  const tree = { 'a.png': png(32, 32), 'b.png': png(64, 64) };
  pass(run(tree, { page: { dimensionsExist: true } }, 'Sizes: 32x32 and 64 × 64 px.')['page.dimensionsExist']);
  const r = run(tree, { page: { dimensionsExist: true } }, 'Sizes: 32x32, 128x128.')['page.dimensionsExist'];
  fail(r);
  assert.deepEqual(r.details, ['page mentions 128x128, no image has it']);
  fail(run(tree, { page: { dimensionsExist: true } }, 'No sizes listed.')['page.dimensionsExist']);
});

test('page text helpers: HTML stripped to visible text, folding is stable', () => {
  assert.equal(
    htmlToText('<style>p{}</style><p>128&nbsp;icons &amp; <b>more</b><!-- no AI --></p><script>"no AI"</script>').replace(/\s+/g, ' ').trim(),
    '128 icons & more'
  );
  assert.equal(foldText('  “No‑AI” Tools '), '"no ai" tools');
});

// ---------------------------------------------------------------- integrity

test('integrity: always reported; a corrupt entry FAILs the run', () => {
  const ok = run({ 'a.txt': 'a' }, { files: { total: 1 } });
  pass(ok.integrity);
  const zipPath = path.join(tempDir(), 'bad.zip');
  writeFileSync(zipPath, buildZip([{ name: 'a.txt', data: 'hello', crc: 1 }]));
  const results = verifyClaims(parseClaims({ files: { total: 1 } }), loadSource(zipPath), null);
  fail(results.find((r) => r.id === 'integrity'));
});

// ---------------------------------------------------------------- strict parsing

test('parseClaims: typos, bad values and empty files are errors, not silent passes', () => {
  assert.throws(() => parseClaims({ page: { forbiden: ['x'] } }), /claims\.page: unknown key "forbiden"/);
  assert.throws(() => parseClaims({ fils: {} }), /unknown key "fils"/);
  assert.throws(() => parseClaims({ files: { total: -1 } }), /non-negative integer/);
  assert.throws(() => parseClaims({ files: { total: { min: 5, max: 2 } } }), /min is greater than max/);
  assert.throws(() => parseClaims({ groups: [{ name: 'a', glob: '*', dimensions: ['big'] }] }), /WIDTHxHEIGHT/);
  assert.throws(() => parseClaims({ groups: [{ name: 'a', glob: '*' }] }), /needs count, dimensions, or both/);
  assert.throws(() => parseClaims({ page: { counts: [{ regex: '\\d+ icons', total: true }] } }), /capture group/);
  assert.throws(() => parseClaims({ page: { counts: [{ regex: '(\\d+)', group: 'nope' }] } }), /group "nope" is not defined/);
  assert.throws(() => parseClaims({ names: { forbiddenRegex: ['('] } }), /invalid regex/);
  assert.throws(() => parseClaims({ schemaVersion: 2, files: { total: 1 } }), /only 1 is supported/);
  const src = loadSource(writeZip({ 'a.txt': 'a' }));
  assert.throws(() => verifyClaims(parseClaims({}), src, null), /declares no claims/);
  assert.throws(() => verifyClaims(parseClaims({ docs: { license: false } }), src, null), /declares no claims/);
  assert.throws(() => verifyClaims(parseClaims({ page: { required: ['x'] } }), src, null), /no page text was given/);
});

// ---------------------------------------------------------------- generator

test('generate: claims from an archive pass on that archive, and catch one icon removed', () => {
  const tree = {
    ...icons(128),
    'icons/big/hero.jpg': jpeg(640, 480),
    'icons/anim.gif': gif(32, 32),
    'LICENSE.txt': 'MIT',
    'README.md': '# Pack',
  };
  const claims = generateClaims(loadSource(writeZip(tree)));
  assert.deepEqual(claims.groups.map((g) => [g.name, g.count, g.dimensions]), [
    ['gif images', 1, ['32x32']],
    ['jpg images', 1, ['640x480']],
    ['png images', 128, ['32x32']],
  ]);
  assert.deepEqual(claims.docs, { license: true, readme: true });
  assert.deepEqual(claims.names, { asciiOnly: true });
  const results = verifyClaims(parseClaims(claims), loadSource(writeZip(tree)), null);
  assert.deepEqual(results.filter((r) => r.status === 'FAIL'), []);

  const fewer = { ...tree };
  delete fewer['icons/icon-127.png'];
  const after = verifyClaims(parseClaims(claims), loadSource(writeZip(fewer)), null);
  assert.deepEqual(
    after.filter((r) => r.status === 'FAIL').map((r) => r.id),
    ['files.total', 'files.byExtension.png', 'groups.png images.count', 'totalBytes']
  );
});

test('generate: a dirty archive yields only claims it passes; a corrupt one is refused', () => {
  const tree = { 'Pictograme/ș.png': jpeg(4, 4), '.DS_Store': 'x', 'a.png': 'text' };
  const src = loadSource(writeTree(tree));
  const claims = generateClaims(src);
  assert.equal(claims.names, undefined);
  assert.equal(claims.images, undefined);
  assert.ok(!claims.paths.forbidden.includes('.DS_Store'));
  assert.equal(claims.groups[0].dimensions, undefined, 'a non-image .png leaves dimensions unclaimed');
  assert.deepEqual(verifyClaims(parseClaims(claims), src, null).filter((r) => r.status === 'FAIL'), []);

  const zipPath = path.join(tempDir(), 'bad.zip');
  writeFileSync(zipPath, buildZip([{ name: 'a.txt', data: 'hello', crc: 1 }]));
  assert.throws(() => generateClaims(loadSource(zipPath)), /integrity problems/);
});

test('generate: page facts carry manifest numbers, sizes ordered numerically', () => {
  const facts = pageFacts(loadSource(writeTree({ ...icons(3, 128, 128), 'icons/s.png': png(16, 16), 'LICENSE': 'MIT' })));
  assert.equal(facts, [
    '5 files, ' + facts.split('\n')[0].split(', ')[1],
    '4 PNG images, 16x16, 128x128 px.',
    'Licence: LICENSE.',
    '',
  ].join('\n'));
});

// ---------------------------------------------------------------- CLI

function cli(...args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '' } });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

test('cli: verify exits 1 on the 127-icon archive, 0 on 128, with a readable report', () => {
  const dir = tempDir();
  const claimsFile = path.join(dir, 'claims.json');
  const pageFile = path.join(dir, 'page.html');
  writeFileSync(claimsFile, JSON.stringify(ICON_CLAIMS));
  writeFileSync(pageFile, `<h1>Icons</h1><p>${PAGE}</p>`);

  const bad = cli('verify', writeZip(icons(127)), '--claims', claimsFile, '--page', pageFile);
  assert.equal(bad.code, 1, bad.stderr);
  assert.match(bad.stdout, /FAIL {2}groups\.icons\.count/);
  assert.match(bad.stdout, /expected: 128\n {8}actual: {3}127/);
  assert.match(bad.stdout, /page says "128 icons", archive has 127/);
  assert.match(bad.stdout, /2 FAIL/);

  const good = cli('verify', writeZip(icons(128)), '--claims', claimsFile, '--page', pageFile);
  assert.equal(good.code, 0, good.stdout + good.stderr);
  assert.match(good.stdout, /all pass/);
});

test('cli: --json is the documented shape and agrees with the exit code', () => {
  const dir = tempDir();
  const claimsFile = path.join(dir, 'claims.json');
  writeFileSync(claimsFile, JSON.stringify({ files: { total: 2 } }));
  const out = cli('verify', writeTree({ 'a.txt': 'a' }), '--claims', claimsFile, '--json');
  assert.equal(out.code, 1);
  const json = JSON.parse(out.stdout);
  assert.equal(Object.keys(json)[0], 'schemaVersion');
  assert.deepEqual(json.summary, { total: 2, pass: 1, fail: 1 });
  assert.equal(json.source.kind, 'directory');
  assert.deepEqual(json.results[1], {
    id: 'files.total', claim: 'total number of files', status: 'FAIL', expected: '2', actual: '1', details: [],
  });
});

test('cli: generate writes claims that verify clean; --facts prints page lines', () => {
  const zip = writeZip({ ...icons(5), 'LICENSE.txt': 'MIT' });
  const out = path.join(tempDir(), 'claims.json');
  assert.equal(cli('generate', zip, '--out', out).code, 0);
  assert.equal(JSON.parse(readFileSync(out, 'utf8')).groups[0].count, 5);
  assert.equal(cli('verify', zip, '--claims', out).code, 0);
  const facts = cli('generate', zip, '--facts');
  assert.equal(facts.code, 0);
  assert.match(facts.stdout, /^5 PNG images, 32x32 px\.$/m);
});

test('cli: exit 2 for a bad flag, missing claims, bad JSON, a non-zip, and a page claim without --page', () => {
  const dir = tempDir();
  const bad = path.join(dir, 'bad.json');
  writeFileSync(bad, '{ not json');
  const pageClaims = path.join(dir, 'page.json');
  writeFileSync(pageClaims, JSON.stringify({ page: { forbidden: ['no AI'] } }));
  const notZip = path.join(dir, 'x.zip');
  writeFileSync(notZip, 'hello');
  const zip = writeZip({ 'a.txt': 'a' });

  for (const [args, msg] of [
    [['verify', zip, '--claims', bad, '--wat'], /unknown option/],
    [['verify', zip], /needs --claims/],
    [['verify', zip, '--claims', bad], /not valid JSON/],
    [['verify', notZip, '--claims', pageClaims], /not a zip archive/],
    [['verify', zip, '--claims', pageClaims], /no page text was given/],
    [['explode', zip], /expected a command/],
  ]) {
    const r = cli(...args);
    assert.equal(r.code, 2, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, msg);
  }
});
