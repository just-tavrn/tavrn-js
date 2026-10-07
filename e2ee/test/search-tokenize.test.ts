// SPDX-License-Identifier: MPL-2.0
import { describe, expect, it } from "vitest";
import {
  MARK_END,
  MARK_START,
  MAX_KEYS_PER_MESSAGE,
  SNIPPET_CONTEXT,
  fold,
  indexKeys,
  matches,
  normalize,
  queryTerms,
  snippet,
  words,
} from "../src/search";

/** Whether `query` would find `text` by keys alone (every query key is among the text's keys) and by verification. */
function finds(text: string, query: string): boolean {
  const keys = new Set(indexKeys(text));
  const terms = queryTerms(query);
  return terms.length > 0 && terms.every((t) => keys.has(t.key)) && matches(text, terms);
}

describe("normalize / fold", () => {
  it("lower-cases and applies NFKC", () => {
    expect(normalize("ＡＢＣ Hello")).toBe("abc hello");
    expect(normalize("ﬁle")).toBe("file");
  });

  it("folds diacritics and ß", () => {
    expect(fold("müller")).toBe("muller");
    expect(fold("straße")).toBe("strasse");
    expect(fold("crème brûlée")).toBe("creme brulee");
  });
});

describe("words", () => {
  it("splits on everything that is not a letter or digit and dedups", () => {
    expect(words("Hello, hello WORLD! 42-x")).toEqual(["hello", "world", "42", "x"]);
  });

  it("ignores emoji (also with variation selectors and ZWJ sequences)", () => {
    expect(words("ok 🎉 ❤️ 👩‍💻 👍🏽 fine")).toEqual(["ok", "fine"]);
  });

  it("keeps Cyrillic and Greek words", () => {
    expect(words("Привет мир, Καλημέρα κόσμε")).toEqual(["привет", "мир", "καλημέρα", "κόσμε"]);
  });

  it("splits CJK runs into unigrams and bigrams", () => {
    expect(words("東京")).toEqual(["東", "京", "東京"]);
    expect(words("猫")).toEqual(["猫"]);
    // Mixed runs: the Latin part stays one word.
    expect(words("abc東京")).toEqual(["abc", "東", "京", "東京"]);
  });

  it("cuts words longer than 64 code points", () => {
    const w = words("a".repeat(100));
    expect(w).toEqual(["a".repeat(64)]);
  });
});

describe("indexKeys", () => {
  it("gives prefixes of 3..8 code points and exact keys for short words", () => {
    expect(indexKeys("Hello ab")).toEqual(["p:hel", "p:hell", "p:hello", "x:ab"]);
    expect(indexKeys("abcdefghijk")).toEqual(["p:abc", "p:abcd", "p:abcde", "p:abcdef", "p:abcdefg", "p:abcdefgh"]);
  });

  it("counts code points, not UTF-16 units", () => {
    // Deseret letters are surrogate pairs; "𐐨𐐩𐐪" has 3 code points (6 UTF-16 units).
    expect(indexKeys("𐐨𐐩𐐪")).toEqual(["p:𐐨𐐩𐐪"]);
    expect(indexKeys("𐐨𐐩")).toEqual(["x:𐐨𐐩"]);
    expect(indexKeys("𐐨𐐩𐐪𐐫𐐬𐐭𐐮𐐯𐐰𐐱")).toHaveLength(6);
  });

  it("adds the folded variant", () => {
    const keys = indexKeys("Müller");
    expect(keys).toContain("p:mül");
    expect(keys).toContain("p:mul");
    expect(keys).toContain("p:muller");
  });

  it("gives CJK grams exact keys", () => {
    expect(indexKeys("東京都")).toEqual(["x:東", "x:京", "x:都", "x:東京", "x:京都"]);
  });

  it("caps the keys per message", () => {
    const text = Array.from({ length: 400 }, (_, i) => `wort${i}abcdefgh`).join(" ");
    expect(indexKeys(text).length).toBe(MAX_KEYS_PER_MESSAGE);
  });
});

describe("queryTerms", () => {
  it("never interprets syntax", () => {
    const terms = queryTerms(`"foo" (bar) * OR NEAR a:b -x`);
    expect(terms).toEqual([
      { key: "p:foo", word: "foo", prefix: true },
      { key: "p:bar", word: "bar", prefix: true },
      { key: "x:or", word: "or", prefix: false },
      { key: "p:near", word: "near", prefix: true },
      { key: "x:a", word: "a", prefix: false },
      { key: "x:b", word: "b", prefix: false },
      { key: "x:x", word: "x", prefix: false },
    ]);
  });

  it("does not throw on odd input", () => {
    for (const q of ['"', "(", ")", "*", "OR", "NEAR(", ":", "\\", "'", "", "!?.,;", "x".repeat(10_000), "\u0000\u0001\u0002"]) {
      expect(() => queryTerms(q)).not.toThrow();
    }
    expect(queryTerms("")).toEqual([]);
    expect(queryTerms("!?.,; -- ***")).toEqual([]);
    expect(queryTerms(undefined as unknown as string)).toEqual([]);
  });

  it("truncates long queries and caps the terms", () => {
    const many = Array.from({ length: 40 }, (_, i) => `term${i}`).join(" ");
    expect(queryTerms(many)).toHaveLength(16);
    const long = queryTerms("y".repeat(10_000));
    expect(long).toHaveLength(1);
    expect(long[0]!.word.length).toBe(64);
    expect(long[0]!.key).toBe("p:" + "y".repeat(8));
  });

  it("drops duplicate keys", () => {
    expect(queryTerms("hello Hello HELLO")).toHaveLength(1);
  });

  it("splits CJK queries into bigrams, a single character into a unigram", () => {
    expect(queryTerms("東京都").map((t) => t.key)).toEqual(["x:東京", "x:京都"]);
    expect(queryTerms("猫")).toEqual([{ key: "x:猫", word: "猫", prefix: false }]);
  });

  it("uses the 8 code point prefix as key and keeps the full word", () => {
    expect(queryTerms("Verschlüsselung")).toEqual([{ key: "p:verschlü", word: "verschlüsselung", prefix: true }]);
  });
});

describe("finding by keys and verification", () => {
  it("lower case and NFKC", () => {
    expect(finds("Hello World", "hello")).toBe(true);
    expect(finds("ＡＢＣ Ｄｅｆ", "abc def")).toBe(true);
    expect(finds("abc def", "ＡＢＣ")).toBe(true);
  });

  it("umlauts both ways", () => {
    expect(finds("Herr Müller kommt", "müller")).toBe(true);
    expect(finds("Herr Müller kommt", "muller")).toBe(true);
    expect(finds("Herr Müller kommt", "MÜLL")).toBe(true);
    expect(finds("Die Straße ist nass", "strasse")).toBe(true);
    expect(finds("Die Straße ist nass", "straße")).toBe(true);
  });

  it("CJK", () => {
    const text = "東京都に住んでいます";
    expect(finds(text, "東京")).toBe(true);
    expect(finds(text, "住ん")).toBe(true);
    expect(finds(text, "住")).toBe(true);
    expect(finds(text, "大阪")).toBe(false);
  });

  it("Cyrillic and Greek", () => {
    expect(finds("Привет, мир", "привет")).toBe(true);
    expect(finds("Привет, мир", "ПРИВ")).toBe(true);
    expect(finds("Καλημέρα κόσμε", "καλημ")).toBe(true);
  });

  it("emoji are not terms", () => {
    expect(queryTerms("🎉")).toEqual([]);
  });

  it("terms shorter than 3 are exact", () => {
    expect(finds("an ab abc", "ab")).toBe(true);
    expect(finds("abc", "ab")).toBe(false);
  });

  it("long words: a query prefix longer than 8 is verified", () => {
    const text = "Die Verschlüsselung funktioniert";
    expect(finds(text, "verschlüsse")).toBe(true);
    expect(finds(text, "verschlüssx")).toBe(false);
    expect(finds(text, "verschluesselung")).toBe(false);
    expect(finds(text, "verschlusselung")).toBe(true);
  });

  it("AND of all terms", () => {
    expect(finds("hello world", "hello world")).toBe(true);
    expect(finds("hello there", "hello world")).toBe(false);
  });
});

describe("snippet", () => {
  it("marks every match in the original text", () => {
    const s = snippet("Hello World, hello again", queryTerms("hel"));
    expect(s).toBe(`${MARK_START}Hello${MARK_END} World, ${MARK_START}hello${MARK_END} again`);
  });

  it("marks diacritic-insensitive prefixes and whole short words", () => {
    expect(snippet("Herr Müller", queryTerms("mull"))).toBe(`Herr ${MARK_START}Müller${MARK_END}`);
    expect(snippet("Die Straße", queryTerms("strass"))).toBe(`Die ${MARK_START}Straße${MARK_END}`);
    expect(snippet("an ab abc", queryTerms("ab"))).toBe(`an ${MARK_START}ab${MARK_END} abc`);
  });

  it("marks CJK grams", () => {
    expect(snippet("東京都に住んでいます", queryTerms("東京"))).toBe(`${MARK_START}東京${MARK_END}都に住んでいます`);
  });

  it("cuts around the first match with ellipses", () => {
    const text = `${"a ".repeat(100)}needle${" b".repeat(100)}`;
    const s = snippet(text, queryTerms("needle"));
    expect(s.startsWith("…")).toBe(true);
    expect(s.endsWith("…")).toBe(true);
    expect(s).toContain(`${MARK_START}needle${MARK_END}`);
    expect(s.length).toBeLessThanOrEqual(2 * SNIPPET_CONTEXT + "needle".length + 4);
  });

  it("removes control markers from the text and never adds HTML", () => {
    const s = snippet("x\u0001<b>evil</b>\u0002 needle", queryTerms("needle"));
    expect(s).toBe(`x<b>evil</b> ${MARK_START}needle${MARK_END}`);
  });

  it("without a match: the beginning without markers", () => {
    const text = "z".repeat(500);
    const s = snippet(text, queryTerms("needle"));
    expect(s).toBe("z".repeat(2 * SNIPPET_CONTEXT) + "…");
    expect(snippet("short", [])).toBe("short");
  });

  it("never cuts a surrogate pair", () => {
    const text = `${"😀".repeat(80)}needle${"😀".repeat(80)}`;
    const s = snippet(text, queryTerms("needle"));
    expect(s).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/);
  });
});
