/**
 * Tests for `prodcheck artifacts` (src/artifacts/).
 *
 * Every artifact here is built at test time by tests/artifacts/build.mjs and
 * written to a fresh temporary directory — nothing binary is committed, and
 * the deny-terms file in particular only ever exists under os.tmpdir().
 *
 * Shape of the suite:
 *   - positive controls: every rule, planted in every container type, must be
 *     found at the right inner path;
 *   - negative controls: the same containers holding only near-miss text must
 *     come back clean (exit 0), so a positive result means something;
 *   - the two cases the incident turned on: a planted term inside a nested
 *     archive, and inside a UTF-16LE string in a binary, must FAIL the CLI;
 *   - what it cannot read (a gap) must not exit 0;
 *   - no output path may print a planted value in full.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

import { scanArtifacts } from '../src/artifacts/scan.mjs';
import { denyRules } from '../src/artifacts/rules.mjs';
import {
  CLEAN_TEXT,
  PLANTED,
  RULE_OF,
  makeIso,
  makeNpmTgz,
  makePe,
  makeTar,
  makeUdfOnly,
  makeWheel,
  makeZip,
  noise,
  utf16,
} from './artifacts/build.mjs';

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));

function tmp(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'prodcheck-artifacts-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function put(dir, name, data) {
  const file = path.join(dir, name);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, data);
  return file;
}

function run(args, cwd) {
  return spawnSync(process.execPath, [CLI, 'artifacts', ...args, '--no-color'], { encoding: 'utf8', cwd });
}

function json(args, cwd) {
  const r = run([...args, '--json'], cwd);
  assert.notEqual(r.status, 2, `scan failed: ${r.stderr}`);
  return { status: r.status, out: JSON.parse(r.stdout), raw: r.stdout };
}

const DENY = [{ term: PLANTED.denyTerm, line: 1 }];
const scan = (inputs, opts = {}) => scanArtifacts(inputs, { deny: denyRules(DENY), ...opts });

/** Every planted value on its own line, as a text file would carry it. */
const ALL_TEXT = Object.values(PLANTED).join('\n');

/** Which rules a scan reported for one inner path. */
function rulesAt(result, innerPath) {
  return new Set(result.findings.filter((f) => f.path.join('!') === innerPath).map((f) => f.rule));
}

const EXPECTED_RULES = new Set(Object.values(RULE_OF));

// ── every rule, in a plain file ─────────────────────────────────────────────

for (const [key, value] of Object.entries(PLANTED)) {
  test(`rule ${RULE_OF[key]} fires on planted ${key} in a plain file`, (t) => {
    const dir = tmp(t);
    const file = put(dir, 'plain.txt', `prefix text\n${value}\nsuffix text\n`);
    const result = scan([file]);
    const rules = result.findings.map((f) => f.rule);
    assert.ok(rules.includes(RULE_OF[key]), `expected ${RULE_OF[key]}, got ${JSON.stringify(rules)}`);
    const f = result.findings.find((x) => x.rule === RULE_OF[key]);
    assert.equal(f.where, 'content');
    assert.ok(f.offset >= 'prefix text\n'.length - 1 && f.offset < 'prefix text\n'.length + value.length);
  });
}

test('negative control: near-miss text is clean under every rule', (t) => {
  const dir = tmp(t);
  const file = put(dir, 'clean.txt', CLEAN_TEXT);
  const result = scan([file]);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.gaps, []);
});

test('deny terms are case-insensitive and found as UTF-8 and as UTF-16LE', (t) => {
  const dir = tmp(t);
  const a = put(dir, 'upper.txt', `x ${PLANTED.denyTerm.toUpperCase()} y`);
  const b = put(dir, 'wide.bin', Buffer.concat([noise(64), utf16(PLANTED.denyTerm.toLowerCase()), noise(64)]));
  const result = scan([a, b]);
  assert.deepEqual(
    result.findings.map((f) => [f.artifact.split('/').pop(), f.rule, f.encoding, f.term]),
    [
      ['upper.txt', 'deny-term', 'ascii', 1],
      ['wide.bin', 'deny-term', 'utf-16le', 1],
    ]
  );
});

// ── every rule × every container type ───────────────────────────────────────

/**
 * Each container type, built twice: once around ALL_TEXT (every planted
 * value), once around CLEAN_TEXT. `inner` is where the payload must be
 * reported.
 */
const CONTAINERS = {
  'zip (deflate)': { name: 'app.zip', build: (p) => makeZip([{ name: 'cfg/app.txt', data: p }]), inner: 'cfg/app.txt' },
  'zip (stored)': { name: 'app.zip', build: (p) => makeZip([{ name: 'app.txt', data: p, method: 0 }]), inner: 'app.txt' },
  tar: { name: 'app.tar', build: (p) => makeTar([{ name: 'etc/app.txt', data: p }]), inner: 'etc/app.txt' },
  'tar.gz': { name: 'app.tar.gz', build: (p) => gzipSync(makeTar([{ name: 'app.txt', data: p }])), inner: 'app.txt' },
  'npm package (.tgz)': { name: 'fixture-1.0.0.tgz', build: (p) => makeNpmTgz([{ name: 'dist/index.js', data: p }]), inner: 'package/dist/index.js' },
  'wheel (.whl)': { name: 'pkg-1.0-py3-none-any.whl', build: (p) => makeWheel('pkg', [{ name: 'pkg/__init__.py', data: p }]), inner: 'pkg/__init__.py' },
  iso: { name: 'disc.iso', build: (p) => makeIso([{ path: 'TOOLS/APP.CFG', data: p }]), inner: 'TOOLS/APP.CFG' },
  'binary (ASCII strings)': { name: 'app.exe', build: (p) => makePe({ ascii: p.split('\n') }), inner: '' },
  'binary (UTF-16LE strings)': { name: 'app.dll', build: (p) => makePe({ utf16le: p.split('\n') }), inner: '' },
  'gzip (single file)': { name: 'notes.txt.gz', build: (p) => gzipSync(Buffer.from(p)), inner: 'notes.txt' },
};

for (const [label, c] of Object.entries(CONTAINERS)) {
  test(`positive control: every rule is found inside ${label}`, (t) => {
    const dir = tmp(t);
    const file = put(dir, c.name, c.build(ALL_TEXT));
    const result = scan([file]);
    assert.deepEqual(result.gaps, []);
    assert.deepEqual(rulesAt(result, c.inner), EXPECTED_RULES, `findings: ${JSON.stringify(result.findings.map((f) => [f.rule, f.path]))}`);
  });

  test(`negative control: ${label} holding near-miss text is clean (CLI exit 0)`, (t) => {
    const dir = tmp(t);
    put(dir, c.name, c.build(CLEAN_TEXT));
    const deny = put(dir, 'deny.txt', `${PLANTED.denyTerm}\n`);
    const r = run([c.name, '--deny-terms', deny], dir);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /clean/);
  });
}

test('positive and negative control: a directory of artifacts', (t) => {
  const dir = tmp(t);
  put(dir, 'dist/clean/readme.txt', CLEAN_TEXT);
  put(dir, 'dist/clean/app.zip', makeZip([{ name: 'a.txt', data: CLEAN_TEXT }]));
  assert.equal(run(['dist'], dir).status, 0);

  put(dir, 'dist/leaky/build-info.txt', PLANTED.winPath);
  const r = json(['dist'], dir);
  assert.equal(r.status, 1);
  assert.deepEqual(
    r.out.findings.map((f) => [f.artifact, f.rule]),
    [['dist/leaky/build-info.txt', 'windows-home-path']]
  );
});

// ── the incident: nested archives and UTF-16LE in binaries must FAIL ────────

test('CLI FAILS on a deny term inside a nested archive (iso > zip > tgz > tar entry)', (t) => {
  const dir = tmp(t);
  const tgz = makeNpmTgz([{ name: 'lib/build.js', data: `const root = "${PLANTED.denyTerm}";` }]);
  const zip = makeZip([{ name: 'vendor/pkg.tgz', data: tgz }]);
  put(dir, 'release.iso', makeIso([{ path: 'PAYLOAD/BUNDLE.ZIP', data: zip }, { path: 'README.TXT', data: 'hello' }]));
  const deny = put(dir, 'deny.txt', `# my private terms\n${PLANTED.denyTerm.toLowerCase()}\n`);

  const r = json(['release.iso', '--deny-terms', deny], dir);
  assert.equal(r.status, 1);
  assert.equal(r.out.findings.length, 1);
  const [f] = r.out.findings;
  assert.equal(f.rule, 'deny-term');
  assert.equal(f.denyTermLine, 2);
  assert.deepEqual(f.path, ['PAYLOAD/BUNDLE.ZIP', 'vendor/pkg.tgz', 'package/lib/build.js']);
  assert.equal(f.offset, 'const root = "'.length);
  assert.equal(f.where, 'content');
});

test('CLI FAILS on a deny term in a UTF-16LE string of a binary', (t) => {
  const dir = tmp(t);
  put(dir, 'setup.exe', makePe({ utf16le: [`CompanyName ${PLANTED.denyTerm} Ltd`] }));
  const deny = put(dir, 'deny.txt', `${PLANTED.denyTerm}\n`);
  const r = json(['setup.exe', '--deny-terms', deny], dir);
  assert.equal(r.status, 1);
  assert.deepEqual(r.out.findings.map((f) => [f.rule, f.encoding]), [['deny-term', 'utf-16le']]);
  // The same binary without the deny-terms file has nothing else in it.
  assert.equal(run(['setup.exe'], dir).status, 0);
});

test('the incident itself: a build path inside a binary inside an ISO', (t) => {
  const dir = tmp(t);
  const exe = makePe({ ascii: [`${PLANTED.winPath}\\lib\\rustlib\\src\\rust\\library\\core\\src\\panicking.rs`] });
  put(dir, 'os.iso', makeIso([{ path: 'BOOT/LOADER.EFI', data: exe }]));
  const r = json(['os.iso'], dir);
  assert.equal(r.status, 1);
  assert.deepEqual(r.out.findings.map((f) => [f.rule, f.path.join('!')]), [['windows-home-path', 'BOOT/LOADER.EFI']]);
  assert.match(r.out.findings[0].snippet, /C:\\Users\\b\*\*\*\\\.rustup/);
});

// ── offsets, metadata, de-duplication ───────────────────────────────────────

test('strings packed back to back, as compilers emit them, are still found', (t) => {
  const dir = tmp(t);
  // Rust (and C) string constants sit next to each other in .rdata with no
  // separator, so a home path is preceded by the last letter of another string.
  const packed = `called \`Option::unwrap()\` on a \`None\` value${PLANTED.winPath}\\src\\main.rsassertion failed${PLANTED.linuxHome}/src/lib.rs`;
  put(dir, 'tool.exe', makePe({ ascii: [packed] }));
  const result = scan([path.join(dir, 'tool.exe')]);
  assert.deepEqual(result.findings.map((f) => f.rule), ['windows-home-path', 'unix-home-path']);
});

test('offset is the byte offset within the innermost entry, for both encodings', (t) => {
  const dir = tmp(t);
  const pe = makePe({ ascii: [PLANTED.linuxHome], utf16le: [PLANTED.macHome] });
  put(dir, 'bin.zip', makeZip([{ name: 'bin/tool', data: pe }]));
  const result = scan([path.join(dir, 'bin.zip')]);
  const unix = result.findings.filter((f) => f.rule === 'unix-home-path');
  assert.deepEqual(
    unix.map((f) => [f.encoding, f.offset]),
    [
      ['ascii', pe.indexOf(Buffer.from(PLANTED.linuxHome))],
      ['utf-16le', pe.indexOf(utf16(PLANTED.macHome))],
    ]
  );
  assert.ok(pe.indexOf(utf16(PLANTED.macHome)) % 2 === 1, 'fixture should put the UTF-16 string at an odd offset');
});

test('ZIP64 archive: entries are located through the ZIP64 records', (t) => {
  const dir = tmp(t);
  put(
    dir,
    'big.zip',
    makeZip(
      [
        { name: 'first.txt', data: CLEAN_TEXT },
        { name: 'second/leak.txt', data: PLANTED.npm },
      ],
      { zip64: true }
    )
  );
  const result = scan([path.join(dir, 'big.zip')]);
  assert.deepEqual(result.gaps, []);
  assert.deepEqual(result.findings.map((f) => [f.rule, f.path.join('!'), f.where]), [['npm-token', 'second/leak.txt', 'content']]);
});

test('a stored entry is reported once, not again by the container pass', (t) => {
  const dir = tmp(t);
  put(dir, 'a.zip', makeZip([{ name: 'x.txt', data: PLANTED.email, method: 0 }]));
  put(dir, 'a.iso', makeIso([{ path: 'X.TXT', data: PLANTED.email }]));
  put(dir, 'a.tar', makeTar([{ name: 'x.txt', data: PLANTED.email }]));
  for (const name of ['a.zip', 'a.iso', 'a.tar']) {
    const result = scan([path.join(dir, name)]);
    assert.equal(result.findings.length, 1, `${name}: ${JSON.stringify(result.findings)}`);
    assert.equal(result.findings[0].where, 'content');
  }
});

test('metadata is scanned: tar uname and zip entry names', (t) => {
  const dir = tmp(t);
  put(dir, 'meta.tar', makeTar([{ name: 'ok.txt', data: 'fine', uname: PLANTED.denyTerm.slice(0, 20) }]));
  put(dir, 'names.zip', makeZip([{ name: `${PLANTED.linuxHome}/notes.txt`.slice(1), data: 'fine' }]));
  const tar = scan([path.join(dir, 'meta.tar')]);
  assert.deepEqual(tar.findings.map((f) => [f.rule, f.where, f.path.join('!')]), [['deny-term', 'header', 'ok.txt']]);

  // A zip name containing `home/<name>/` (zip names have no leading slash):
  // found twice, in the local header and in the central directory.
  put(dir, 'names2.zip', makeZip([{ name: `x${PLANTED.linuxHome}/notes.txt`, data: 'fine' }]));
  const zip = scan([path.join(dir, 'names2.zip')]);
  assert.deepEqual(zip.findings.map((f) => [f.rule, f.where]), [
    ['unix-home-path', 'header'],
    ['unix-home-path', 'header'],
  ]);
});

test('a match straddling a chunk boundary is found once, at the right offset', (t) => {
  const dir = tmp(t);
  const chunk = 16384;
  const at = chunk - 7;
  const buf = Buffer.concat([noise(at), Buffer.from(PLANTED.ghp), noise(3 * chunk)]);
  const file = put(dir, 'big.bin', buf);
  const result = scan([file], { chunkSize: chunk });
  assert.deepEqual(result.findings.map((f) => [f.rule, f.offset]), [['github-token', at]]);
});

// ── what it cannot read is not clean ────────────────────────────────────────

test('gaps: encrypted, unsupported method, xz, UDF-only, too deep — each exits 3', (t) => {
  const dir = tmp(t);
  const cases = {
    'enc.zip': makeZip([{ name: 'secret.txt', data: CLEAN_TEXT, method: 0, encrypted: true }]),
    'bz.zip': makeZip([{ name: 'a.txt', data: CLEAN_TEXT, method: 12 }]),
    'data.xz': Buffer.concat([Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), noise(256)]),
    'udf.iso': makeUdfOnly('nothing to see'),
    'fake.iso': Buffer.from('not an image at all'),
  };
  for (const [name, data] of Object.entries(cases)) {
    put(dir, name, data);
    const r = json([name], dir);
    assert.equal(r.status, 3, `${name}: ${r.raw}`);
    assert.equal(r.out.findings.length, 0);
    assert.equal(r.out.gaps.length, 1, `${name}: ${JSON.stringify(r.out.gaps)}`);
    assert.equal(run([name, '--allow-gaps'], dir).status, 0);
  }
  assert.match(json(['udf.iso'], dir).out.gaps[0].reason, /UDF/);
  assert.match(json(['bz.zip'], dir).out.gaps[0].reason, /method 12/);

  // Nesting past --max-depth: the deflated entry inside is never opened.
  const nested = makeZip([{ name: 'in.zip', data: makeZip([{ name: 'a.txt', data: PLANTED.jwt }]) }]);
  put(dir, 'deep.zip', nested);
  const deep = json(['deep.zip', '--max-depth', '1'], dir);
  assert.equal(deep.status, 3);
  assert.match(deep.out.gaps[0].reason, /--max-depth 1/);
  assert.equal(json(['deep.zip'], dir).status, 1, 'with the default depth the JWT is found');
});

test('a gap still has its raw bytes scanned: a UDF image with a planted path fails', (t) => {
  const dir = tmp(t);
  put(dir, 'udf.iso', makeUdfOnly(`installer built in ${PLANTED.winPathSlash}`));
  const r = json(['udf.iso'], dir);
  assert.equal(r.status, 1);
  assert.equal(r.out.gaps.length, 1);
  assert.equal(r.out.findings[0].rule, 'windows-home-path');
});

// ── allow-list ──────────────────────────────────────────────────────────────

test('allow-list suppresses by location glob, rule and pattern; reports unused lines', (t) => {
  const dir = tmp(t);
  put(dir, 'pkg.tgz', makeNpmTgz([{ name: 'README.md', data: `${PLANTED.email}\n${PLANTED.macHome}\n` }]));
  const allow = put(
    dir,
    'allow.txt',
    [
      '# known false positives',
      `pkg.tgz!package/README.md email-address ${PLANTED.email.split('@')[1]}`,
      '**/*.md unix-home-path /^\\/Users\\/nobody\\//',
      'other.zip!** * ',
    ].join('\n')
  );
  const r = json(['pkg.tgz', '--allow', allow], dir);
  assert.equal(r.status, 1, 'the /Users/ path is not covered by the regex on line 3');
  assert.deepEqual(r.out.findings.map((f) => f.rule), ['unix-home-path']);
  assert.equal(r.out.summary.allowed, 1);
  assert.deepEqual(r.out.summary.unusedAllowLines, [3, 4]);

  put(dir, 'allow2.txt', `**/README.md *\n`);
  assert.equal(run(['pkg.tgz', '--allow', path.join(dir, 'allow2.txt')], dir).status, 0);
});

test('allow-list with an unknown rule id is an error, not a silent no-op', (t) => {
  const dir = tmp(t);
  put(dir, 'a.txt', 'x');
  const allow = put(dir, 'allow.txt', '** emial-address\n');
  const r = run(['a.txt', '--allow', allow], dir);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown rule "emial-address"/);
});

// ── deny-terms file handling ────────────────────────────────────────────────

test('deny-terms file: empty or too-short terms fail the scan without echoing terms', (t) => {
  const dir = tmp(t);
  put(dir, 'a.txt', 'x');
  const empty = put(dir, 'empty.txt', '# only a comment\n\n');
  const short = put(dir, 'short.txt', `${PLANTED.denyTerm}\nQz\n`);
  const r1 = run(['a.txt', '--deny-terms', empty], dir);
  assert.equal(r1.status, 2);
  assert.match(r1.stderr, /no terms/);
  const r2 = run(['a.txt', '--deny-terms', short], dir);
  assert.equal(r2.status, 2);
  assert.match(r2.stderr, /line 2/);
  assert.ok(!r2.stderr.includes('Qz') && !r2.stderr.includes(PLANTED.denyTerm));
  assert.equal(run(['a.txt', '--deny-terms', path.join(dir, 'missing.txt')], dir).status, 2);
});

// ── redaction ───────────────────────────────────────────────────────────────

test('no output ever contains a planted value, user name or deny term in full', (t) => {
  const dir = tmp(t);
  put(dir, 'all.zip', makeZip([{ name: 'a.txt', data: ALL_TEXT }, { name: 'b.bin', data: makePe({ utf16le: ALL_TEXT.split('\n') }) }]));
  const deny = put(dir, 'deny.txt', `${PLANTED.denyTerm}\n`);
  const report = run(['all.zip', '--deny-terms', deny], dir);
  const asJson = run(['all.zip', '--deny-terms', deny, '--json'], dir);
  assert.equal(report.status, 1);
  assert.equal(asJson.status, 1);

  const secrets = [
    ...Object.entries(PLANTED)
      .filter(([k]) => k !== 'privateKey' && k !== 'awsSecret')
      .map(([, v]) => v.split('\n')[0]),
    PLANTED.awsSecret.split('= ')[1], // the value, not the variable name in front of it
    PLANTED.privateKey.split('\n')[1], // the key material, not its public header
    'buildbot',
    'ci-runner',
    'jdoe',
    'release-owner',
  ];
  for (const out of [report.stdout, asJson.stdout]) {
    for (const s of secrets) {
      // The token shapes are long; a 12-character piece is enough to leak one.
      const piece = s.length > 16 ? s.slice(4, 16) : s;
      assert.ok(!out.includes(piece), `output leaked ${JSON.stringify(piece)}`);
    }
  }
  assert.equal(JSON.parse(asJson.stdout).summary.total, 2 * Object.keys(PLANTED).length);
});

// ── CLI surface ─────────────────────────────────────────────────────────────

test('CLI: --help exits 0, no input exits 2, missing path exits 2', (t) => {
  const dir = tmp(t);
  const help = run(['--help'], dir);
  assert.equal(help.status, 0);
  assert.match(help.stdout, /--deny-terms <file>/);
  assert.equal(run([], dir).status, 2);
  assert.equal(run(['nope.zip'], dir).status, 2);
  assert.equal(run(['--bogus'], dir).status, 2);
});

test('the source scanner is unchanged: `prodcheck sample` still exits 1', () => {
  const r = spawnSync(process.execPath, [CLI, fileURLToPath(new URL('../sample', import.meta.url)), '--no-color'], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /webhook-swallows-2xx/);
});

// ── real-world producers (skipped, with the reason, when a tool is absent) ──

function have(cmd, args = ['--version']) {
  const r = spawnSync(cmd, args, { encoding: 'utf8' });
  return r.status === 0;
}

test('real tar + gzip archive (system tar) with a planted path', { skip: have('tar') ? false : 'system `tar` not installed' }, (t) => {
  const dir = tmp(t);
  put(dir, 'src/build/info.txt', `built at ${PLANTED.linuxHome}`);
  put(dir, 'src/ok.txt', CLEAN_TEXT);
  assert.equal(spawnSync('tar', ['czf', 'out.tar.gz', '-C', 'src', '.'], { cwd: dir }).status, 0);
  const result = scan([path.join(dir, 'out.tar.gz')]);
  assert.deepEqual(result.findings.map((f) => [f.rule, f.path.join('!')]), [['unix-home-path', './build/info.txt']]);
});

test('real zip (Python zipfile, deflate) with a planted token', { skip: have('python3') ? false : 'python3 not installed' }, (t) => {
  const dir = tmp(t);
  const r = spawnSync('python3', ['-I', '-c', [
    'import sys, zipfile',
    "z = zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_DEFLATED)",
    "z.writestr('pkg/settings.py', 'TOKEN = \"' + sys.argv[2] + '\"\\n' * 50)",
    "z.writestr('pkg/clean.py', sys.argv[3])",
    'z.close()',
  ].join('\n'), path.join(dir, 'pkg-1.0-py3-none-any.whl'), PLANTED.ghp, CLEAN_TEXT]);
  assert.equal(r.status, 0, String(r.stderr));
  const result = scan([path.join(dir, 'pkg-1.0-py3-none-any.whl')]);
  assert.deepEqual(result.findings.map((f) => [f.rule, f.path.join('!')]), [['github-token', 'pkg/settings.py']]);
});

test('real npm package (npm pack) with a planted e-mail', { skip: have('npm') ? false : 'npm not installed' }, (t) => {
  const dir = tmp(t);
  put(dir, 'pkg/package.json', '{"name":"planted-fixture","version":"1.0.0","files":["index.js"]}');
  put(dir, 'pkg/index.js', `module.exports = "${PLANTED.email}";\n`);
  const r = spawnSync('npm', ['pack', '--silent', '--pack-destination', dir], { cwd: path.join(dir, 'pkg'), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const result = scan([path.join(dir, 'planted-fixture-1.0.0.tgz')]);
  assert.deepEqual(result.findings.map((f) => [f.rule, f.path.join('!')]), [['email-address', 'package/index.js']]);
});
