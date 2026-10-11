/**
 * Turns a .zip or a directory into one manifest: the files that ship, the
 * directories they sit in, and what each image's header says about it.
 *
 * Both inputs produce the same shape, so every claim is checked the same way
 * whether the pack is still a folder on the build machine or the archive that
 * was uploaded to the store.
 *
 *   {
 *     kind: 'zip' | 'directory',
 *     files: [{ path, size, ext, image: {format,width,height} | null }],
 *     dirs: ['icons', 'icons/32'],   // every ancestor of a file, plus empty dir entries
 *     problems: [string],            // integrity failures (bad CRC, unreadable file, …)
 *   }
 *
 * Paths are POSIX, relative, without a leading `./`, sorted.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { readZip } from './zip.mjs';
import { imageSize } from './imagesize.mjs';

/** Lowercase extension without the dot; '' when the name has none. */
export function extOf(p) {
  const base = p.slice(p.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : '';
}

function fileRecord(p, size, bytes) {
  return { path: p, size, ext: extOf(p), image: imageSize(bytes) };
}

function finish(kind, files, explicitDirs, problems) {
  const dirs = new Set(explicitDirs);
  for (const f of files) {
    const parts = f.path.split('/');
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
  }
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { kind, files, dirs: [...dirs].sort(), problems };
}

function fromZip(abs) {
  const files = [];
  const dirs = [];
  const { entries, problems } = readZip(readFileSync(abs), (entry, bytes) => {
    files.push(fileRecord(entry.name.replace(/^\.\//, ''), bytes.length, bytes));
  });
  for (const e of entries) {
    if (e.isDir) dirs.push(e.name.replace(/^\.\//, '').replace(/\/+$/, ''));
    if (e.name.startsWith('/') || e.name.split('/').includes('..')) {
      problems.push(`${e.name}: path escapes the extraction directory`);
    }
    if (e.name.includes('\\')) {
      problems.push(`${e.name}: backslash in entry name, extracts differently per platform`);
    }
  }
  return finish('zip', files, dirs.filter(Boolean), problems);
}

function fromDirectory(root) {
  const files = [];
  const dirs = [];
  const problems = [];
  const walk = (rel) => {
    const abs = path.join(root, rel);
    let entries;
    try {
      entries = readdirSync(abs, { withFileTypes: true });
    } catch (err) {
      problems.push(`${rel || '.'}: cannot read directory (${err.code ?? err.message})`);
      return;
    }
    for (const entry of entries) {
      const childRel = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        dirs.push(childRel);
        walk(childRel);
      } else if (entry.isFile()) {
        let bytes;
        try {
          bytes = readFileSync(path.join(root, childRel));
        } catch (err) {
          problems.push(`${childRel}: cannot read file (${err.code ?? err.message})`);
          continue;
        }
        files.push(fileRecord(childRel, bytes.length, bytes));
      } else {
        // A symlink or a device would ship (or not) depending on how the
        // folder is packed, so the manifest cannot say what the buyer gets.
        problems.push(`${childRel}: not a regular file or directory (symlink?), cannot verify what ships`);
      }
    }
  };
  walk('');
  return finish('directory', files, dirs, problems);
}

/** @param {string} target path to a .zip file or a directory */
export function loadSource(target) {
  let info;
  try {
    info = statSync(target);
  } catch {
    throw new Error(`cannot read path: ${target}`);
  }
  if (info.isDirectory()) return fromDirectory(target);
  return fromZip(target);
}
