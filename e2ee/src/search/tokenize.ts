// SPDX-License-Identifier: MPL-2.0
/**
 * Text processing of the local search index (design note 4.4 "Search"): normalization, the tokenizer, the
 * lookup keys of a text and of a query, the verification of candidates and the snippet builder.
 *
 * A word is a maximal run of letters and digits (plus the combining marks following them). Runs of CJK characters (Han,
 * Hiragana, Katakana, Hangul) have no word boundaries, so they are indexed as unigrams and bigrams
 * with exact keys; every other word gets its prefixes of 3..8 code points as keys (`p:`), words
 * shorter than 3 code points an exact key (`x:`). Each word is indexed both as written (normalized)
 * and diacritic-folded, so "Müller" is found by "müller" and by "muller".
 *
 * The query string is never interpreted as syntax: quotes, parentheses, `*`, `OR`, `NEAR`, `:` are
 * separators or plain words, and all terms must match (AND).
 */

/** Highlight start inside a snippet. */
export const MARK_START = "\u0001";
/** Highlight end inside a snippet. */
export const MARK_END = "\u0002";
export const MIN_PREFIX = 3;
export const MAX_PREFIX = 8;
/** Text kept per message (UTF-16 units, cut at a code point boundary). */
export const MAX_INDEXED_CHARS = 4000;
/** Characters of context around the first match on each side of a snippet. */
export const SNIPPET_CONTEXT = 60;
/** Lookup keys per message at most. */
export const MAX_KEYS_PER_MESSAGE = 512;
/** Code points of a word at most (longer words are cut). */
export const MAX_WORD = 64;
/** Terms per query at most. */
export const MAX_QUERY_TERMS = 16;
/** Code points of a query at most (longer queries are truncated). */
export const MAX_QUERY_CHARS = 256;

/** One term of a parsed query. */
export interface QueryTerm {
  /** Lookup key of the posting list (`p:` prefix of at most 8 code points, or `x:` exact). */
  key: string;
  /** The full normalized term (verification of terms longer than 8 code points, highlighting). */
  word: string;
  /** Prefix term (matches words starting with `word`) or exact term (word or CJK gram equal to `word`). */
  prefix: boolean;
}

// A word starts with a letter or digit; combining marks (Indic vowel signs, unnormalized accents) stay
// part of it, variation selectors (emoji presentation) do not.
const RUN = /[\p{L}\p{N}](?:(?![\uFE00-\uFE0F])[\p{L}\p{N}\p{M}])*/gu;
const CJK = /\p{Script=Han}|\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Hangul}/u;
const MARKS = /\p{M}/gu;
const CONTROL_MARKS = /[\u0001\u0002]/g;

/** NFKC and lower case. */
export function normalize(s: string): string {
  return s.normalize("NFKC").toLowerCase();
}

/** Diacritics folded: NFD, combining marks dropped, `ß` → `ss`, NFC ("Müller" → "muller"). */
export function fold(s: string): string {
  return s.normalize("NFD").replace(MARKS, "").replace(/ß/g, "ss").normalize("NFC");
}

/** A piece of a letter/digit run: a (non-CJK) word or a run of CJK characters, with its UTF-16 offsets. */
interface Segment {
  text: string;
  cjk: boolean;
  start: number;
  end: number;
}

/** Splits `text` (already normalized or original) into words and CJK runs. */
function segments(text: string): Segment[] {
  const out: Segment[] = [];
  for (const m of text.matchAll(RUN)) {
    const run = m[0];
    const base = m.index;
    let cur = "";
    let curCjk = false;
    let curStart = 0;
    let pos = 0;
    for (const ch of run) {
      // A combining mark stays with the preceding character.
      const isCjk: boolean = /\p{M}/u.test(ch) && cur !== "" ? curCjk : CJK.test(ch);
      if (cur !== "" && isCjk !== curCjk) {
        out.push({ text: cur, cjk: curCjk, start: base + curStart, end: base + pos });
        cur = "";
      }
      if (cur === "") {
        curStart = pos;
        curCjk = isCjk;
      }
      cur += ch;
      pos += ch.length;
    }
    if (cur !== "") out.push({ text: cur, cjk: curCjk, start: base + curStart, end: base + pos });
  }
  return out;
}

function cutWord(w: string): string {
  if (w.length <= MAX_WORD) return w;
  const cps = Array.from(w);
  return cps.length <= MAX_WORD ? w : cps.slice(0, MAX_WORD).join("");
}

/** Unigrams and bigrams of a CJK run. */
function grams(run: string): string[] {
  const cps = Array.from(run);
  const out = [...cps];
  for (let i = 0; i + 1 < cps.length; i++) out.push(cps[i]! + cps[i + 1]!);
  return out;
}

interface Tokens {
  /** Normalized non-CJK words (cut to 64 code points), unique. */
  words: string[];
  /** CJK unigrams and bigrams, unique. */
  grams: string[];
}

function tokens(text: string): Tokens {
  const words = new Set<string>();
  const cjk = new Set<string>();
  for (const seg of segments(normalize(text))) {
    if (seg.cjk) for (const g of grams(seg.text)) cjk.add(g);
    else words.add(cutWord(seg.text));
  }
  return { words: [...words], grams: [...cjk] };
}

/** Unique normalized words of `text`; CJK runs contribute their unigrams and bigrams. */
export function words(text: string): string[] {
  const t = tokens(text);
  return [...t.words, ...t.grams];
}

function addWordKeys(out: Set<string>, w: string): void {
  const cps = Array.from(w);
  if (cps.length < MIN_PREFIX) {
    out.add("x:" + w);
    return;
  }
  const max = Math.min(cps.length, MAX_PREFIX);
  let prefix = cps.slice(0, MIN_PREFIX - 1).join("");
  for (let k = MIN_PREFIX; k <= max; k++) {
    prefix += cps[k - 1];
    out.add("p:" + prefix);
  }
}

/** The unique lookup keys of a text (at most {@link MAX_KEYS_PER_MESSAGE}, earlier words first). */
export function indexKeys(text: string): string[] {
  const out = new Set<string>();
  const t = tokens(text);
  for (const w of t.words) {
    addWordKeys(out, w);
    const f = fold(w);
    if (f !== w && f !== "") addWordKeys(out, cutWord(f));
    if (out.size >= MAX_KEYS_PER_MESSAGE) break;
  }
  for (const g of t.grams) {
    if (out.size >= MAX_KEYS_PER_MESSAGE) break;
    out.add("x:" + g);
  }
  return [...out].slice(0, MAX_KEYS_PER_MESSAGE);
}

/** Parses a user query into terms; never throws and never interprets syntax. */
export function queryTerms(query: string): QueryTerm[] {
  let q = typeof query === "string" ? query : "";
  if (q.length > MAX_QUERY_CHARS) q = Array.from(q).slice(0, MAX_QUERY_CHARS).join("");
  const out: QueryTerm[] = [];
  const seen = new Set<string>();
  const push = (t: QueryTerm) => {
    if (out.length >= MAX_QUERY_TERMS || seen.has(t.key)) return;
    seen.add(t.key);
    out.push(t);
  };
  for (const seg of segments(normalize(q))) {
    if (seg.cjk) {
      const cps = Array.from(seg.text);
      if (cps.length === 1) push({ key: "x:" + cps[0], word: cps[0]!, prefix: false });
      else for (let i = 0; i + 1 < cps.length; i++) {
        const g = cps[i]! + cps[i + 1]!;
        push({ key: "x:" + g, word: g, prefix: false });
      }
    } else {
      const w = cutWord(seg.text);
      const cps = Array.from(w);
      if (cps.length < MIN_PREFIX) push({ key: "x:" + w, word: w, prefix: false });
      else push({ key: "p:" + cps.slice(0, MAX_PREFIX).join(""), word: w, prefix: true });
    }
  }
  return out;
}

function wordMatches(w: string, term: QueryTerm): boolean {
  if (term.prefix) return w.startsWith(term.word) || fold(w).startsWith(fold(term.word));
  return w === term.word || fold(w) === fold(term.word);
}

/** True if every term matches `text` (prefix terms: a word starts with it; exact terms: equal word or CJK gram). */
export function matches(text: string, terms: QueryTerm[]): boolean {
  if (terms.length === 0) return true;
  const t = tokens(text);
  let gramSet: Set<string> | null = null;
  for (const term of terms) {
    if (CJK.test(term.word)) {
      gramSet ??= new Set(t.grams);
      if (!gramSet.has(term.word)) return false;
    } else if (!t.words.some((w) => wordMatches(w, term))) return false;
  }
  return true;
}

/** Highlight ranges [start, end) of every term match in `text` (UTF-16 offsets), sorted and merged. */
function matchRanges(text: string, terms: QueryTerm[]): [number, number][] {
  const ranges: [number, number][] = [];
  const cjkTerms = terms.filter((t) => CJK.test(t.word));
  const wordTerms = terms.filter((t) => !CJK.test(t.word));
  for (const seg of segments(text)) {
    if (seg.cjk) {
      if (cjkTerms.length === 0) continue;
      const cps = Array.from(seg.text);
      let off = seg.start;
      for (let i = 0; i < cps.length; i++) {
        for (const term of cjkTerms) {
          const len = Array.from(term.word).length;
          const piece = cps.slice(i, i + len).join("");
          if (normalize(piece) === term.word) ranges.push([off, off + piece.length]);
        }
        off += cps[i]!.length;
      }
      continue;
    }
    const w = cutWord(normalize(seg.text));
    for (const term of wordTerms) {
      if (!wordMatches(w, term)) continue;
      // The whole matching word is marked (like the node's snippets), not only the typed prefix.
      ranges.push([seg.start, seg.start + seg.text.length]);
    }
  }
  ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const merged: [number, number][] = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  }
  return merged;
}

/** Moves `i` off the low half of a surrogate pair (never cuts a code point). */
function cpBoundary(text: string, i: number, forward: boolean): number {
  if (i <= 0 || i >= text.length) return Math.max(0, Math.min(i, text.length));
  const c = text.charCodeAt(i);
  if (c >= 0xdc00 && c <= 0xdfff) return forward ? i + 1 : i - 1;
  return i;
}

/** Cuts `text` to at most `max` UTF-16 units at a code point boundary. */
export function cutText(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, cpBoundary(text, max, false));
}

/**
 * A plain-text snippet: ±{@link SNIPPET_CONTEXT} characters around the first match, `…` at cut ends,
 * every match wrapped in {@link MARK_START}/{@link MARK_END} (the control characters are removed from
 * the text first). Without a match, the first 2×{@link SNIPPET_CONTEXT} characters without markers.
 * Never contains HTML; the caller renders the markers.
 */
export function snippet(text: string, terms: QueryTerm[]): string {
  const clean = text.replace(CONTROL_MARKS, "");
  const ranges = terms.length ? matchRanges(clean, terms) : [];
  const first = ranges[0];
  if (!first) {
    const cut = cutText(clean, 2 * SNIPPET_CONTEXT);
    return cut.length < clean.length ? cut + "…" : cut;
  }
  const start = cpBoundary(clean, Math.max(0, first[0] - SNIPPET_CONTEXT), true);
  const end = cpBoundary(clean, Math.min(clean.length, first[1] + SNIPPET_CONTEXT), false);
  let out = start > 0 ? "…" : "";
  let pos = start;
  for (const [a, b] of ranges) {
    if (a >= end) break;
    const s = Math.max(a, start);
    const e = Math.min(b, end);
    if (e <= s) continue;
    out += clean.slice(pos, s) + MARK_START + clean.slice(s, e) + MARK_END;
    pos = e;
  }
  out += clean.slice(pos, end);
  if (end < clean.length) out += "…";
  return out;
}
