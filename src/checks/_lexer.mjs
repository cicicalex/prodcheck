/**
 * _lexer.mjs — the lexical channel both detectors read.
 *
 * Neither rule has a parser (zero runtime dependencies is a hard rule for this
 * tool), so every question they ask is asked of a character classification:
 * which characters are CODE and which are DATA. Both detectors carried their
 * own copy of that classifier and both copies had the same hole, so it lives
 * here now, once, and a fix to it is a fix to both by construction.
 *
 * Two views of one scan:
 *
 *   codeMask(src)      → Uint8Array, 1 where the character is code
 *   stripComments(src) → the same text with COMMENTS blanked and everything
 *                        else — strings, templates, regex bodies — kept
 *
 * Both preserve indices: the output has the same length as the input, so an
 * offset found in one maps straight onto the other and onto the original source
 * for line math.
 *
 * ── THE INVARIANT ───────────────────────────────────────────────────────────
 *
 *   (1) NO INPUT MAY LEAVE THE LEXER HOLDING AN UNCLOSED FRAME AT EOF.
 *   (2) NO CHARACTER MAY BE CLASSIFIED NOT-CODE BECAUSE OF A DISPUTED `/`
 *       READING.
 *
 * Together they say one thing: WHEN THIS LEXER IS UNSURE, IT KEEPS MORE OF THE
 * FILE ON THE CODE CHANNEL, NEVER LESS.
 *
 * If a template literal, a block comment, a string or a regex is still open
 * when the scan reaches the end of the file, the scan lost synchronisation with
 * the source and everything it said after the opener is untrustworthy. The
 * lexer must then FAIL OPEN — hand the rules a channel that over-reports — and
 * never FAIL BLIND, which is what an unclosed frame does: every character from
 * the opener to EOF is classified not-code, every search in both rules skips
 * not-code, and the file reports clean whatever it contains.
 *
 * Clause (2) is clause (1)'s other half, and it exists because a lost frame
 * does not have to reach EOF to blind a file. It only has to reach the next
 * character that happens to close it. A refused regex holding a backtick pairs
 * with the next backtick anywhere below — an ordinary `${...}` template, forty
 * lines down — and everything between the two goes dark while the scan ends
 * perfectly balanced. Clause (1) alone reports that file clean. So the second
 * clause is anchored on the one place this lexer knowingly guesses: a `/` that
 * could open a regex and was read as division instead.
 *
 * Clause (2) IS UNCONDITIONAL, and that is the whole of round 12. It used to
 * read "…may outlive that `/`'s line AND cost more of the code channel than
 * reading the `/` as a regex would", and every word of that qualification was a
 * hole. Three mechanisms falsified it, all of them with valid JavaScript that
 * `node --check` accepts:
 *
 *   M1  SAME-LINE FRAME. `i > top.suspect.lineEnd` and `close > disputed.lineEnd`
 *       are vacuously false when the frame the disputed text opens also CLOSES
 *       on that `/`'s own line. Clause (1) stayed quiet because the frame
 *       closed; clause (2) stayed quiet because it never outlived its line. The
 *       darkness is the rest of the line — and on a minified file "the rest of
 *       the line" is the rest of the file. Two inline `<rect … />` in one line
 *       of JSX are enough: the `/` of the first `/>` is a refused regex whose
 *       span runs to the next `/>`, and every attribute string between them is
 *       classified not-code on the strength of a guess.
 *   M2  COST GUARD WITH NO FALLBACK. When `frameCostsMore` declined the
 *       overturn, NOTHING replaced it and the darkness simply stood, across
 *       lines. A 123-character line of valid JavaScript silenced an ordinary
 *       Next.js route; tuned per file it silenced two of the four real
 *       production bugs this tool was built from, and
 *       `05-upstash-template.ts` — the very file the round-10 notes cite as
 *       clause (2)'s reason to exist.
 *   M3  QUOTE RE-PHASING. A refused regex whose body holds `'` or `"` opens no
 *       second frame at all: it flips STRING PARITY for the rest of the line.
 *       In `if (1) /'/.test('x'); const ip = req.headers['x-forwarded-for'];`
 *       the surrounding `req.headers['…']` lands on the data channel and
 *       nothing in either rule can match it.
 *
 * A conditional invariant has a condition to evade. The unconditional one does
 * not: when the lexer cannot decide whether a `/` starts a regex or divides,
 * EVERY consequence of that indecision fails open. No line test, no cost test,
 * no exceptions. Concretely — if the DIVISION reading opens any frame at all
 * inside the disputed span, then the whole affected extent (the span, plus
 * everything that frame reaches, plus the rest of the line when the frame was a
 * STRING and quote parity is therefore in doubt) is CODE.
 *
 * That repair cannot misfire, because it only ever moves characters ONTO the
 * code channel. It is not a re-reading that might be wrong in the other
 * direction; it is a refusal to darken anything on the strength of a guess.
 *
 * For a security scanner the two errors are not comparable. Over-reporting
 * costs one spurious finding that a human reads and dismisses. Under-reporting
 * costs a live bypass delivered as a clean bill of health, and nobody ever
 * learns it happened. So clause (1) is enforced as a post-condition rather than
 * aimed at — `scan` runs the mask, and if a frame was open at EOF it REPAIRS
 * and runs again (see `resolve` and `scanLineBounded` below) — while clause (2)
 * is discharged inside the pass that finds it, because refusing to darken needs
 * no second reading to be safe.
 *
 * This is the fourth attempt at this class of bug and the first one with no
 * condition in it. Rounds 1-9 chased individual mutes and each round found a new
 * one; round 10 modelled regex literals and MOVED the hole rather than closing
 * it (see below); round 11 wrote clause (2) with two qualifications and M1, M2
 * and M3 are what those qualifications cost. What is left has nothing to evade:
 * whatever new spelling opens a frame, that frame either survives to EOF, where
 * clause (1) demotes its opener, or it was opened inside a disputed span, where
 * clause (2) refuses every character it darkens.
 *
 * ── why regex literals are modelled here ────────────────────────────────────
 *
 * They were not, and that was a correctness bug rather than a recall gap. The
 * old classifier treated `/` as an ordinary code character, so a regex literal
 * was read as whatever its BODY happened to look like:
 *
 *     const RE_TICK = /`/;      the backtick opened a template frame that was
 *                               never popped — every character from that line
 *                               to EOF was classified not-code
 *     const RE_TICK2 = /[`]/;   the same, one character wider
 *     const RE_C = /[/*]/;      the `/*` inside the class opened a block
 *                               comment that ran to the next comment
 *                               terminator in the file, or to EOF
 *
 * Each of those is valid JavaScript, passes `node --check`, and silenced an
 * entire file: every search in both rules — header reads, limiter calls,
 * keyGenerator bodies, socket writes, catch blocks, the 2xx offence — skips
 * characters the mask calls not-code, so the file reported clean.
 *
 * This is not a hypothetical. Scanning 513 real files in this author's own
 * repositories found `zpl-finance/src/lib/csv-export.ts` dark from line 11 to
 * EOF, caused by nothing more adversarial than CSV quoting:
 *
 *     `"${str.replace(/"/g, '""')}"`
 *
 * — a regex literal holding a double quote, inside a template interpolation.
 * Nothing was lost there only because that file happens to contain no limiter.
 *
 * ── the `/` ambiguity, and why it is no longer load-bearing ─────────────────
 *
 * `/` divides or opens a regex depending on what came before it, which is why
 * the old comment called this parser territory. It is not: the decision is
 * LEXICAL, and the standard rule is "a regex may start wherever an expression
 * may start". So the scanner remembers the previous significant token and lets
 * a regex begin after a punctuator that wants an operand (`( , = : [ ! & | ? {
 * } ; + - * % ~ ^ < >`, and `=>` by way of its `>`), after a keyword that wants
 * one (`return typeof case in of new delete void instanceof do else yield await
 * throw default`), or at the start of input or of a `${` interpolation — and
 * never after an identifier, a number, `)`, `]`, or the close of a string,
 * template or regex, where `/` is far more often division.
 *
 * An earlier version of this header justified that bias with a claim that is
 * FALSE, and it is recorded here because the claim is what let round 10 ship a
 * hole while believing it had closed one:
 *
 *     "a regex read as division loses the regex's own contents from the data
 *      channel. Small: … at worst one spurious match."
 *
 * It is not one spurious match. When a REFUSED regex's body holds a backtick or
 * a `/*`, that character does not stay inert in the code channel — it OPENS A
 * FRAME of its own, and that frame runs to EOF. The file goes dark from the
 * refused position down, exactly as it did before regex literals were modelled
 * at all:
 *
 *     if (1) /`/.test(x);              refused after `)` → backtick opens a
 *                                      template frame → file dark to EOF
 *     while (false) /`/.test(x);       the same
 *     function f() { throw /`/; }      `throw` was missing from EXPR_KEYWORD
 *     const n = 4 / /`/.source.length; refused after a division `/`
 *     if (1) /[/*]/.test(x);           refused after `)` → `/*` opens a block
 *                                      comment → dark to the next `*` `/`
 *
 * A 32,631-run mutation harness over eight corpora found 1,310 total silences,
 * every one of them from nine one-liners of that shape, hitting every loud file
 * at every insertion anchor — including all four real production bugs the rules
 * were built from and a webhook CRITICAL. Every one is valid JavaScript, clean
 * under `node --check`, and semantically inert.
 *
 * Enforcing clause (1) alone took that to 31, and the 31 are why clause (2)
 * exists: in those files the loose backtick found a real template literal below
 * it and the loose `/*` found a real `*` `/`, so the frame CLOSED, the scan
 * balanced, and the file went dark only in the middle. `05-upstash-template.ts`
 * keys its limiter inside `` `app_${…}` ``; that template's own backtick is what
 * closed the frame the inserted line opened.
 *
 * So the bias survives, but nothing rests on it any more. Preferring division
 * in an ambiguous position is now a PRECISION choice — after `)` and `]` and a
 * division `/`, `/` really is division far more often than not, and a regex
 * misread as division only over-reports its own body — and the INVARIANT above,
 * not the bias, is what keeps a wrong guess from blinding a file. Both
 * directions of error are bounded now:
 *
 *   - a regex read as division may leave a frame opener loose in the code
 *     channel. Wherever that frame ends — the next line, forty lines down, EOF —
 *     clause (2) fails the whole affected extent open: no test, no threshold,
 *     nothing for a new spelling to slip past. If it ended at EOF, clause (1)
 *     also demotes the opener and the scan runs again.
 *   - division read as a regex is bounded by `regexEnd`, which abandons any
 *     candidate that reaches a newline before its closing `/`. It no longer
 *     needs a second bound, because clause (2) no longer REREADS anything: a
 *     minified bundle whose `(Number(u)-Number(e))/Number(s)` finds a closing
 *     `/` 39,000 characters later is not promoted to a 39,468-character "regex
 *     literal" — the span is merely refused permission to darken.
 *
 * ── the three repairs ───────────────────────────────────────────────────────
 *
 * `scanOnce` reports three things. `unclosed` holds the opener index of every
 * frame still open at EOF. `overturn` holds the position of every refused `/`
 * whose span let a frame loose that then ran to EOF. `failOpen` holds the
 * character ranges clause (2) refuses to darken. `resolve` then:
 *
 *   DEMOTES each `unclosed` index — the character there is read as ordinary
 *     code and may not open a comment, string, template or regex;
 *   PROMOTES each `overturn` index — the `/` there is read as a regex literal
 *     regardless of what the previous token was;
 *
 * and scans again, repeating while new positions surface. Neither repair can
 * be undone by a later pass — a demoted index cannot open a frame, a promoted
 * one cannot be refused — so every pass that runs adds a position and the loop
 * terminates. `MAX_RECOVERY_PASSES` bounds it regardless, and
 * `scanLineBounded` is the floor beneath that: every line scanned from the
 * neutral state, which cannot leave a frame open past its own line at all.
 *
 * `failOpen` is not a re-scan and does not need one. It is applied to the mask
 * of the pass that produced it, at the end of that pass, and it only ever sets
 * bits to 1 (and clears the comment channel over the same range, so
 * `stripComments` cannot blank the text either). Each pass recomputes it from
 * scratch, so when a clause-(1) repair removes the frame the extent goes with
 * it; on a scan that never settles, the extent from the last pass still stands.
 *
 * That is what makes clause (2) safe in the way its predecessor was not: the
 * repair has no direction it can be wrong in. RE-READING the span could be
 * wrong, which is how M2's cost guard came to decline repairs and how declining
 * came to mean "leave it dark". Refusing to darken cannot be.
 *
 * Be honest about the reach, because it is the whole price of the round. The
 * extent failed open is the disputed span itself PLUS everything the frame it
 * let loose covers, and a frame can span lines: a backtick a refused `/` leaves
 * loose pairs with a real template forty lines below, and those forty lines are
 * now read as code rather than as template text. When the loose frame is a
 * STRING the extent runs to the end of the line as well, because a string
 * closing mid-line leaves QUOTE PARITY inverted for everything after it (M3)
 * and only the newline restores it. All of that is the over-reporting
 * direction, which costs a spurious finding a human dismisses; the direction it
 * refuses to take costs a live bypass delivered as a clean bill of health.
 *
 * Measured, on the four repositories this tool is validated against — 517
 * files, 59 of which contain a disputed `/` at all: clause (2) fails open in
 * 31 of them, moving 2,375 characters from the data channel to the code
 * channel and 0 characters the other way, and the finding set does not change
 * at all — nothing added, nothing removed, on those 517 files or on the
 * 105-file adversarial fixture corpus. `zpl-finance/src/app/dashboard/layout.tsx`
 * — five inline SVG icons of `<rect … />` and `<path … />` — is the largest
 * single case at 826 characters, in one run of 732.
 *
 * Their node_modules trees are the stress measurement: 57,747 files under the
 * 1 MiB reader cap, where the minified bundles live. Clause (2) fails open in
 * 598 of them, 6,301,805 characters, still nothing in the other direction, and
 * the widest single run is 69,430 characters of a Prisma runtime bundle. That
 * is what the clause costs when a "line" is 600 KB long — and this tool never
 * walks node_modules, so it is a number to know rather than a price anyone pays.
 */

/** Flags a regex literal may carry, consumed as part of the literal. */
const REGEX_FLAGS = 'dgimsuvy';

/**
 * Keywords after which a `/` opens a regex rather than dividing.
 *
 * `throw` and `default` were missing and both legitimately precede one:
 * `throw /re/` is how a thrown literal is spelled, `export default /re/` how a
 * module exports one. Their absence was not merely a recall gap — a refused
 * regex leaves its body in the code channel, so `throw /`/` opened a template
 * frame and took the file dark.
 */
const EXPR_KEYWORD =
  /^(?:return|typeof|case|in|of|new|delete|void|instanceof|do|else|yield|await|throw|default)$/;

/**
 * Punctuators after which a `/` opens a regex. `)` and `]` are absent because
 * `/` after them is division far more often than not — `if (x) /re/.test(y)` is
 * legal and rare, `(a + b) / c` is everywhere — so this is a precision choice
 * and nothing more. It used to be defended as the thing standing between this
 * module and a blinded file; it never was, and the invariant at the top of this
 * file is. `>` is present so that the `>` of `=>` permits one.
 */
const EXPR_PUNCT = new Set([...'(,=:[!&|?{};+-*%~^<>']);

/** Characters that can appear in an identifier or a numeric literal. */
const WORD_CHAR = /[A-Za-z0-9_$]/;

/** A fresh code frame. `prev` is null at the start of an expression context. */
const codeFrame = (fromTpl) => ({ tpl: false, fromTpl, depth: 0, prev: null });

/**
 * How many repair-and-rescan passes the recovery may take before falling back
 * to line-bounded lexing. Each pass demotes or promotes at least one position
 * that no later pass can undo, so the loop terminates on its own; this only
 * bounds the work an adversarial file can ask for.
 */
const MAX_RECOVERY_PASSES = 16;

/** Shared, never mutated: the repair sets of an ordinary first pass. */
const NO_REPAIRS = new Set();

/** The index of the newline ending the line `at` sits on, or the input length. */
function lineEndFrom(src, at) {
  const nl = src.indexOf('\n', at);
  return nl === -1 ? src.length : nl;
}

/**
 * Is overturning this disputed `/` the reading that leaves MORE of the file on
 * the code channel? `open`..`close` is the frame the division reading let loose.
 *
 * This is a PRECISION test and only a precision test. It chooses which reading
 * the lexer STATE should follow for a frame that ran all the way to EOF, where
 * clause (1) has to pick one repair or the other: reading the `/` as a regex
 * moves its whole span to the data channel, while leaving it as division moves
 * the frame's whole extent there instead, so prefer the regex only when its
 * span is the smaller of the two. Both branches are fail-open — overturning
 * means the frame never opens, demoting means the opener is ordinary code — so
 * neither can leave darkness behind and the test can only pick the tidier one.
 *
 * It is deliberately NOT consulted anywhere else any more. It used to gate
 * clause (2) as well, and there its arithmetic was load-bearing in a way it
 * could not survive: declining an overturn left the darkness in place with
 * nothing to replace it (M2 in the header). What made declining safe was never
 * the arithmetic but the absence of an alternative, and clause (2) now has one
 * that costs nothing to take — refusing to darken the span at all.
 *
 * The number that forced this test into existence is still the reason to keep
 * it honest: a MINIFIED bundle has no newlines, and
 * `(Number(u)-Number(e))/Number(s)>=n` in tsx's `dist/cli.mjs` — plain division
 * — has a closing `/` 39,000 characters later on the same line. Promoting that
 * to a "regex literal" would take 39,468 characters OFF the code channel. No
 * clause may do that to avoid a frame that costs fewer.
 */
const frameCostsMore = (disputed, open, close) => disputed.end - disputed.at < close - open;

/**
 * May a `/` at this point open a regex literal? `prev` is the previous
 * significant token of the current frame, or null at the start of one.
 */
function regexAllowed(prev) {
  if (!prev) return true; // start of input, or of a `${` interpolation
  if (prev.kind === 'value') return false; // a string, template, regex or number closed
  if (prev.kind === 'word') return EXPR_KEYWORD.test(prev.word);
  // `a++ / b` and `a-- / b` divide; the `+`/`-` there ends an operand.
  if ((prev.ch === '+' && prev.ch2 === '+') || (prev.ch === '-' && prev.ch2 === '-')) return false;
  return EXPR_PUNCT.has(prev.ch);
}

/**
 * The index just past the regex literal opening at `start`, including its
 * flags, or -1 when the text there is not one after all.
 *
 * Escapes are honoured and a character class is tracked, because a `/` inside
 * `[...]` does not close the literal — `/[/*]/` is one regex, not a regex and a
 * comment. Reaching a newline — or the end of the file — first means this was
 * never a regex: the caller falls back to reading the `/` as division, so this
 * function can never be the frame that is open at EOF.
 */
function regexEnd(src, start) {
  const n = src.length;
  let i = start + 1;
  let inClass = false;
  let closed = false;

  while (i < n) {
    const c = src[i];
    if (c === '\n') return -1; // a regex literal never spans a line
    // …and a backslash does not buy one. A line terminator is illegal inside a
    // regex literal whether or not it is escaped, so `\` + newline ends the
    // candidate rather than continuing it.
    if (c === '\\') {
      if (src[i + 1] === '\n') return -1;
      i += 2;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      i += 1;
      continue;
    }
    if (c === '[') { inClass = true; i += 1; continue; }
    if (c === '/') { i += 1; closed = true; break; }
    i += 1;
  }
  if (!closed) return -1;

  while (i < n && REGEX_FLAGS.includes(src[i])) i += 1;
  return i;
}

/**
 * One pass, five results: `mask[i]` is 1 where the character is code,
 * `comment[i]` is 1 where it belongs to a line or block comment, and the three
 * repair channels the module header describes — `unclosed`, the opener index of
 * every frame still open when the scan ran off the end of the input;
 * `overturn`, the position of every refused `/` whose span let such a frame
 * loose; and `failOpen`, already applied to `mask` and `comment` before this
 * function returns. `unclosed` and `overturn` both empty is the post-condition
 * `resolve` iterates towards; `failOpen` needs no iteration, because it is not
 * a re-reading — it is a refusal to darken.
 *
 * `demoted` and `promoted` are the repairs applied on entry. A DEMOTED index's
 * character is read as ordinary code and may not open a comment, a string, a
 * template or a regex. A PROMOTED index's `/` opens a regex literal whatever
 * the previous token was. Between them they reinterpret exactly the positions
 * that went wrong and leave every other literal in the file classified as it
 * was.
 *
 * Template interpolations `${...}` are code again, tracked with a small stack
 * so nested templates and braces inside interpolations resolve correctly. Each
 * code frame carries its own previous-token state, so a `/` at the start of an
 * interpolation reads as the start of an expression rather than inheriting
 * whatever token preceded the template.
 */
function scanOnce(src, demoted, promoted) {
  const n = src.length;
  const mask = new Uint8Array(n);
  const comment = new Uint8Array(n);
  const stack = [codeFrame(false)];
  const unclosed = [];
  const overturn = [];
  // The disputed `/` spans the scan is currently inside, outermost first, each
  // {at, end, lineEnd}. A frame opened inside one of these spans exists only
  // under the DIVISION reading — the regex reading would have swallowed its
  // opener as pattern text — so every character it darkens is a consequence of
  // a guess, and clause (2) refuses all of them. This is a LIST rather than the
  // single slot round 11 kept, because a `/` inside a character class can open
  // a second disputed span while the first is still live and must not erase it.
  const disputes = [];
  // Flat [from, to) pairs: the extents clause (2) forces onto the code channel.
  const failOpen = [];
  let i = 0;

  const markComment = (from, to) => {
    for (let k = from; k < to && k < n; k++) comment[k] = 1;
  };

  /**
   * `open`..`close` is a frame the scan just finished reading. If it OPENED
   * inside a disputed span then the division reading is what created it, and
   * clause (2) fails the whole affected extent open.
   *
   * The extent is the span itself plus everything the frame covers: the span,
   * because M1's frames open and close inside it and darken it from within; the
   * frame's full reach, because M2's cross the span's end and keep going. When
   * the frame is a STRING that escaped the span, the extent runs to the end of
   * the line as well — a string that opens inside the span and closes outside it
   * has inverted QUOTE PARITY for every quote after it, and only the newline
   * puts that right (M3). `actives` is the dispute list as it stood when the
   * frame opened, or null when there was none.
   */
  const letLoose = (open, close, actives, isString) => {
    if (actives === null) return;
    for (const d of actives) {
      if (open <= d.at || open >= d.end) continue; // not opened inside this span
      let to = close > d.end ? close : d.end;
      if (isString && close > d.end && d.lineEnd > to) to = d.lineEnd;
      failOpen.push(d.at, to);
    }
  };

  /**
   * The dispute list to hand `letLoose`, or null when nothing is disputed.
   *
   * This is the LIVE array, not a copy, so it is only safe for a frame the loop
   * consumes inside one iteration — a string, a comment, an accepted regex. The
   * list is compacted at the top of the loop and nowhere else, so nothing can
   * move under those. A template frame spans iterations and takes a snapshot.
   */
  const activeNow = () => (disputes.length === 0 ? null : disputes);

  while (i < n) {
    const top = stack[stack.length - 1];
    const ch = src[i];
    if (disputes.length !== 0) {
      let keep = 0;
      for (let k = 0; k < disputes.length; k++) if (disputes[k].end > i) disputes[keep++] = disputes[k];
      disputes.length = keep;
    }

    if (top.tpl) {
      if (ch === '\\') { i += 2; continue; }
      if (ch === '`') {
        stack.pop();
        // Clause (2): this frame was opened by a character a refused `/` left
        // loose, and it has now closed — against an unrelated backtick that
        // belongs to a real template, anywhere from later on the same line to
        // forty lines down. Everything between the two went dark while the scan
        // stayed perfectly balanced, which is why clause (1) alone cannot see
        // it. There is no line test and no cost test: whatever the frame
        // covers, and the span that let it loose, are code.
        letLoose(top.open, i + 1, top.suspects, false);
        stack[stack.length - 1].prev = { kind: 'value' };
        i += 1;
        continue;
      }
      if (ch === '$' && src[i + 1] === '{') {
        stack.push(codeFrame(true));
        i += 2;
        continue;
      }
      i += 1;
      continue;
    }

    const opensComment = ch === '/' && !demoted.has(i) && !promoted.has(i);
    if (opensComment && src[i + 1] === '/') {
      const from = i;
      const actives = activeNow();
      i += 2;
      while (i < n && src[i] !== '\n') i += 1;
      markComment(from, i);
      // A `//` reached from inside a disputed span is `/[//]/`'s character class
      // read the other way. Clause (2) again.
      letLoose(from, i, actives, false);
      continue;
    }
    if (opensComment && src[i + 1] === '*') {
      const from = i;
      const actives = activeNow();
      let k = i + 2;
      while (k < n && !(src[k] === '*' && src[k + 1] === '/')) k += 1;
      const close = k >= n ? n : k + 2;
      if (k >= n) {
        // Clause (1): no terminator anywhere below, so this comment eats the
        // rest of the file. Report it rather than return a mask whose tail is
        // dark.
        unclosed.push(from);
      }
      markComment(from, close);
      letLoose(from, close, actives, false); // clause (2): `/[/*]/` read as division
      i = close;
      continue;
    }
    // A regex literal is DATA, exactly like a string: its body never counts as
    // code, so a header name or a trust word inside one cannot match either.
    if (ch === '/' && !demoted.has(i)) {
      const end = regexEnd(src, i);
      if (end !== -1) {
        if (promoted.has(i) || regexAllowed(top.prev)) {
          // An accepted literal is still a frame, and if it opened inside a
          // disputed span it is still one the regex reading would not have.
          letLoose(i, end, activeNow(), false);
          top.prev = { kind: 'value' };
          i = end;
          continue;
        }
        // Refused — but a well-formed regex literal does read here, so this is
        // the one guess this lexer makes. Watch what the division reading lets
        // loose for as long as the disputed span lasts.
        disputes.push({ at: i, end, lineEnd: lineEndFrom(src, i) });
      }
      // Not a regex after all — fall through and read the `/` as division.
    }
    if ((ch === "'" || ch === '"') && !demoted.has(i)) {
      const quote = ch;
      const from = i;
      const actives = activeNow();
      i += 1;
      // Stop at an unescaped closing quote, or at a newline — a string literal
      // is confined to its own line here, which is damage control for the
      // unterminated case and, more importantly, closes the one exception that
      // let a string escape its line at all.
      //
      // `'a\` + newline is a legal LINE CONTINUATION: real JavaScript carries
      // the string onto the next line, and honouring that let one appended line
      // swallow everything down to the next quote in the file — the round-11
      // family again, wearing a backslash. Continuations are extinct in real
      // code (ESLint's no-multi-str forbids them), and refusing to follow one
      // costs only that the continued lines read as CODE, which is the
      // over-reporting direction. So `\` never skips a newline.
      while (i < n && src[i] !== quote && src[i] !== '\n') {
        i += src[i] === '\\' && src[i + 1] !== '\n' ? 2 : 1;
      }
      if (i >= n) unclosed.push(from); // ran off the end with no closing quote
      i += 1;
      // Clause (2), and M3's whole mechanism: a quote inside a refused regex
      // body opens no frame the regex reading would have opened, and if the
      // string it starts closes outside the span then every quote after it on
      // that line is read as the wrong half of a pair. `isString` is what
      // carries the extent past the frame to the newline that re-phases them.
      letLoose(from, i < n ? i : n, actives, true);
      top.prev = { kind: 'value' };
      continue;
    }
    if (ch === '`' && !demoted.has(i)) {
      // A template opened inside a disputed span is watched all the way to its
      // closing backtick, or to EOF: whichever it reaches, the `/` that let it
      // loose is what put it there.
      stack.push({ tpl: true, open: i, suspects: disputes.length === 0 ? null : disputes.slice() });
      i += 1;
      continue;
    }
    if (ch === '{') {
      top.depth += 1;
      mask[i] = 1;
      top.prev = { kind: 'punct', ch: '{', ch2: '' };
      i += 1;
      continue;
    }
    if (ch === '}') {
      if (top.fromTpl && top.depth === 0) { stack.pop(); i += 1; continue; }
      if (top.depth > 0) top.depth -= 1;
      mask[i] = 1;
      top.prev = { kind: 'punct', ch: '}', ch2: '' };
      i += 1;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      mask[i] = 1; // whitespace is code, and never moves the previous token
      i += 1;
      continue;
    }
    if (WORD_CHAR.test(ch)) {
      let k = i;
      while (k < n && WORD_CHAR.test(src[k])) { mask[k] = 1; k += 1; }
      top.prev = { kind: 'word', word: src.slice(i, k) };
      i = k;
      continue;
    }
    mask[i] = 1;
    top.prev = {
      kind: 'punct',
      ch,
      ch2: top.prev && top.prev.kind === 'punct' ? top.prev.ch : '',
    };
    i += 1;
  }

  // Every template frame still on the stack ran to EOF. An interpolation frame
  // (`fromTpl`) can only be open while the template that opened it is too, so
  // repairing the backtick is enough to unwind both. A frame a disputed `/` let
  // loose is preferably repaired by overturning that `/` — the more precise of
  // the two repairs, since it restores the literal real JavaScript reads there
  // — and `frameCostsMore` is the only place that preference is still weighed.
  // Both branches are fail-open, so the weighing decides tidiness, not safety.
  for (const frame of stack) {
    if (!frame.tpl) continue;
    letLoose(frame.open, n, frame.suspects, false);
    const suspect = frame.suspects === null ? null : frame.suspects[frame.suspects.length - 1];
    if (suspect !== null && frameCostsMore(suspect, frame.open, n)) overturn.push(suspect.at);
    else unclosed.push(frame.open);
  }

  // Clause (2), applied. It is deliberately the last thing that touches either
  // channel and it only ever adds to the code channel and removes from the
  // comment channel, so no earlier decision in this pass can be darkened by it.
  for (let k = 0; k < failOpen.length; k += 2) {
    const to = failOpen[k + 1] < n ? failOpen[k + 1] : n;
    for (let x = failOpen[k]; x < to; x++) {
      mask[x] = 1;
      comment[x] = 0;
    }
  }

  return { mask, comment, unclosed, overturn };
}

/**
 * Did this pass leave anything for the next one to repair?
 *
 * Clause (2) is not asked about here, and that is the point of the round: it is
 * discharged inside the pass that finds it, by `failOpen`, which is already in
 * the mask by the time `scanOnce` returns. Only clause (1) — a frame open at
 * EOF, and the overturn that is sometimes the tidier way to unwind one — needs
 * another pass to take effect.
 */
const settled = (out) => out.unclosed.length === 0 && out.overturn.length === 0;

/**
 * `scanOnce`, repeated with each pass's repairs applied, until both clauses of
 * the invariant hold or `MAX_RECOVERY_PASSES` is spent.
 *
 * Progress is guaranteed: a demoted index cannot open a frame and a promoted
 * one cannot be refused, so neither can be reported again, so every pass that
 * runs adds at least one new position. All of a pass's findings are applied
 * together, so a file with twenty independent breakages is repaired in two
 * passes rather than twenty-one; a second pass is needed only when a repair
 * uncovers text the previous pass had buried inside a frame. The pass count is
 * a belt-and-braces bound on how much work an adversarial file can ask for,
 * not a correctness requirement.
 */
function resolve(src) {
  let out = scanOnce(src, NO_REPAIRS, NO_REPAIRS);
  if (settled(out)) return out;

  const demoted = new Set();
  const promoted = new Set();
  for (let pass = 0; pass < MAX_RECOVERY_PASSES; pass++) {
    let grew = false;
    for (const at of out.unclosed) {
      if (at >= 0 && !demoted.has(at)) { demoted.add(at); grew = true; }
    }
    for (const at of out.overturn) {
      if (at >= 0 && !promoted.has(at)) { promoted.add(at); grew = true; }
    }
    if (!grew) break; // cannot happen while repairs are new; bail anyway
    out = scanOnce(src, demoted, promoted);
    if (settled(out)) return out;
  }
  return out;
}

/**
 * The floor under the recovery: each LINE lexed independently, starting from
 * the neutral state, so no frame can survive past the newline that ends the
 * line that opened it.
 *
 * This costs the multi-line frames — a template literal or a block comment
 * spanning lines is read as ordinary code from its second line on, which can
 * only ADD findings, never remove them, and that is the direction this module
 * is allowed to be wrong in. It is the right price at this point: `resolve`
 * has already failed to reach a clean scan, so the file's frame structure is
 * not something this lexer can model, and every measured multi-line frame in
 * real code closes long before EOF.
 */
function scanLineBounded(src) {
  const n = src.length;
  const mask = new Uint8Array(n);
  const comment = new Uint8Array(n);

  let from = 0;
  while (from <= n) {
    let nl = src.indexOf('\n', from);
    if (nl === -1) nl = n;
    if (nl > from) {
      const line = resolve(src.slice(from, nl));
      mask.set(line.mask, from);
      comment.set(line.comment, from);
    }
    if (nl < n) mask[nl] = 1; // the newline itself is whitespace, and code
    from = nl + 1;
  }

  return { mask, comment, unclosed: [], overturn: [] };
}

/**
 * The scan, with the module's invariant enforced as a post-condition: whatever
 * the input, the result never has a frame open at EOF, and no character it
 * calls not-code is one a disputed `/` darkened.
 */
function scan(src) {
  const out = resolve(src);
  return settled(out) ? out : scanLineBounded(src);
}

/**
 * Classify each character of `src` as code (1) or not-code (0).
 *
 * Not-code: string literals, template literal text, regex literals, line and
 * block comments.
 *
 * Guaranteed: no unclosed frame survives to EOF, so the tail of the returned
 * mask is never dark because the scanner lost its place. See the invariant at
 * the top of this file.
 */
export function codeMask(src) {
  return scan(src).mask;
}

/**
 * `src` with comments blanked and everything else — including string and regex
 * literals — kept. Used for the candidacy hints and as the text every lexical
 * search runs over: header names live in strings, and blanking them would blind
 * the rules to exactly the files they exist to find. The mask above is what
 * decides whether a match is code; this decides what text there is to match.
 *
 * Carries the same guarantee, from the same scan: an unterminated block comment
 * cannot blank the rest of the file, because a block comment with no terminator
 * is a frame open at EOF and the recovery demotes it.
 */
export function stripComments(src) {
  const { comment } = scan(src);
  const out = src.split('');
  for (let i = 0; i < out.length; i++) if (comment[i]) out[i] = ' ';
  return out.join('');
}
