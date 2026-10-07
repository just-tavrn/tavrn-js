// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { JcsError, jcs } from "../src/jcs";

interface JcsVector {
  input: string;
  canonical: string;
}

const vectors = JSON.parse(readFileSync(new URL("../../protocol/testvectors/federation.json", import.meta.url), "utf8")) as {
  jcs: JcsVector[];
  plaintext_signature: { content_input: string; content_jcs: string };
};

describe("jcs (RFC 8785)", () => {
  it.each(vectors.jcs.map((v) => [v.input, v] as const))("protocol vector %s", (_, v) => {
    expect(jcs(JSON.parse(v.input))).toBe(v.canonical);
    // Canonical text is a fixed point.
    expect(jcs(JSON.parse(v.canonical))).toBe(v.canonical);
  });

  it("matches the content of the plaintext signature vector", () => {
    const p = vectors.plaintext_signature;
    expect(jcs(JSON.parse(p.content_input))).toBe(p.content_jcs);
  });

  it("sorts by UTF-16 code units, not by code points", () => {
    // U+1F600 (surrogates D83D DE00) sorts before U+FB33 in UTF-16, after it by code point.
    const emoji = String.fromCodePoint(0x1f600);
    const dalet = String.fromCodePoint(0xfb33);
    expect(jcs({ [dalet]: 1, [emoji]: 2 })).toBe(`{"${emoji}":2,"${dalet}":1}`);
  });

  it("serializes numbers like ECMAScript", () => {
    expect(jcs([0, -0, 1.5, 1e21, 1e-7, 4.5, 2e-3, 333333333.33333329])).toBe("[0,0,1.5,1e+21,1e-7,4.5,0.002,333333333.3333333]");
  });

  it("refuses values without a JSON form", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, () => 1, Symbol("x"), 1n, undefined, new Date(0), new Map()]) {
      expect(() => jcs(bad)).toThrow(JcsError);
    }
    expect(() => jcs({ s: `a${String.fromCharCode(0xd800)}b` })).toThrow(JcsError);
    expect(() => jcs(String.fromCharCode(0xdc00))).toThrow(JcsError);
    // A well-formed surrogate pair is fine.
    expect(jcs(String.fromCodePoint(0x1f600))).toBe(`"${String.fromCodePoint(0x1f600)}"`);
  });

  it("omits undefined members like JSON.stringify and escapes control characters", () => {
    expect(jcs({ b: undefined, a: "x\n\u0001" })).toBe('{"a":"x\\n\\u0001"}');
    expect(jcs(Object.create(null) as object)).toBe("{}");
  });
});
