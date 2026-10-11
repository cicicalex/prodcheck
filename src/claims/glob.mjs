/**
 * Glob patterns for claims files, with gitignore-like anchoring.
 *
 *   *        any run of characters inside one path segment
 *   ?        one character inside a segment
 *   **       any number of whole segments (`**\/x`, `a/**`, `a/**\/b`)
 *   {a,b}    alternation
 *   trailing /   directories only
 *
 * A pattern with no `/` (other than a trailing one) matches at any depth:
 * `.DS_Store` finds it in every folder, `__MACOSX/` finds that folder wherever
 * it is. A pattern containing `/` (a leading one included, so `/icons/` means
 * the root folder only) is anchored at the archive root. Matching is
 * case-sensitive, like the file systems the archive is extracted onto.
 */

function escape(ch) {
  return /[\\^$.|+()[\]{}]/.test(ch) ? `\\${ch}` : ch;
}

function body(glob) {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        // `**/` may also match zero segments, so `**/x.png` finds a root x.png.
        if ((i === 0 || glob[i - 1] === '/') && glob[i + 2] === '/') {
          out += '(?:.*/)?';
          i += 2;
        } else {
          out += '.*';
          i += 1;
        }
      } else out += '[^/]*';
    } else if (ch === '?') out += '[^/]';
    else if (ch === '{') {
      const close = glob.indexOf('}', i);
      if (close === -1) throw new Error(`unclosed { in glob: ${glob}`);
      out += `(?:${glob.slice(i + 1, close).split(',').map(body).join('|')})`;
      i = close;
    } else out += escape(ch);
  }
  return out;
}

/**
 * @param {string} glob
 * @returns {{ test(path: string, isDir: boolean): boolean }}
 */
export function compileGlob(glob) {
  if (typeof glob !== 'string' || glob === '' || glob === '/') throw new Error(`empty glob`);
  const dirOnly = glob.endsWith('/');
  let g = dirOnly ? glob.replace(/\/+$/, '') : glob;
  g = g.replace(/^\.\//, '');
  if (!g.includes('/')) g = `**/${g}`;
  else g = g.replace(/^\//, '');
  const re = new RegExp(`^${body(g)}$`);
  return { test: (p, isDir) => (!dirOnly || isDir) && re.test(p) };
}
