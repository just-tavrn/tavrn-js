// SPDX-License-Identifier: MPL-2.0
import { describe, expect, it } from "vitest";
import { EmbedsInvalidError, assertEmbeds, embedsProblem, readEmbeds, validEmbedUrl, withValidEmbeds } from "../src/embeds";

const example = {
  title: "Build #128",
  description: "All **42** tests passed",
  url: "https://ci.example/b/128",
  color: 3066993,
  fields: [{ name: "Branch", value: "main", inline: true }],
  footer: "ci.example",
  timestamp: "2026-10-05T12:00:00Z",
};

describe("embeds (APPLICATIONS.md §6.4)", () => {
  it("accepts the example of the spec and unknown fields", () => {
    expect(embedsProblem([example])).toBeNull();
    expect(embedsProblem([])).toBeNull();
    expect(embedsProblem([{ title: "t", future: 1 }])).toBeNull();
  });

  it("enforces the same limits as the node", () => {
    const bad = (v: unknown) => embedsProblem(v) !== null;
    expect(bad({ title: "x" })).toBe(true);
    expect(bad([{}])).toBe(true);
    expect(bad(Array.from({ length: 11 }, () => ({ title: "x" })))).toBe(true);
    expect(bad([{ title: "a".repeat(256) }])).toBe(false);
    expect(bad([{ title: "a".repeat(257) }])).toBe(true);
    expect(bad([{ title: "ä".repeat(256) }])).toBe(false);
    expect(bad([{ title: "😀".repeat(256) }])).toBe(false);
    expect(bad([{ description: "d".repeat(4097) }])).toBe(true);
    expect(bad([{ footer: "f".repeat(2049) }])).toBe(true);
    for (const url of ["http://ci.example", "javascript:alert(1)", "https://u:p@ci.example/", "https://", "https://a b.example"]) {
      expect(validEmbedUrl(url), url).toBe(false);
      expect(bad([{ title: "x", url }]), url).toBe(true);
    }
    for (const color of [-1, 16_777_216, 1.5, "#fff"]) expect(bad([{ title: "x", color }])).toBe(true);
    expect(bad([{ title: "x", timestamp: "yesterday" }])).toBe(true);
    const field = { name: "n", value: "v" };
    expect(bad([{ fields: Array.from({ length: 25 }, () => field) }])).toBe(false);
    expect(bad([{ fields: Array.from({ length: 26 }, () => field) }])).toBe(true);
    expect(bad([{ fields: [{ name: "", value: "v" }] }])).toBe(true);
    expect(bad([{ fields: [{ name: "n", value: "v", inline: "yes" }] }])).toBe(true);
    const six = { title: "t".repeat(200), description: "d".repeat(800) };
    expect(bad(Array.from({ length: 6 }, () => six))).toBe(false);
    expect(bad([...Array.from({ length: 6 }, () => six), { title: "x" }])).toBe(true);
  });

  it("senders refuse invalid embeds, receivers drop them", () => {
    expect(() => assertEmbeds({ type: "text", body: "", embeds: [example] })).not.toThrow();
    expect(() => assertEmbeds({ type: "text", body: "x" })).not.toThrow();
    expect(() => assertEmbeds({ type: "text", body: "x", embeds: [{ title: "x", url: "http://x.example" }] })).toThrow(EmbedsInvalidError);
    expect(() => assertEmbeds({ type: "action", body: "x", embeds: [example] })).toThrow(EmbedsInvalidError);
    const dropped = withValidEmbeds({ type: "text", body: "x", embeds: [{ title: 5 }] });
    expect(dropped).toEqual({ type: "text", body: "x" });
    const kept = { type: "text", body: "x", embeds: [example] };
    expect(withValidEmbeds(kept)).toBe(kept);
  });

  it("readEmbeds keeps only the known, checked fields", () => {
    const embeds = readEmbeds({ type: "text", body: "", embeds: [{ ...example, image: "https://tracker.example/p.png" }] });
    expect(embeds).toEqual([example]);
    expect(embeds[0]).not.toHaveProperty("image");
    expect(readEmbeds({ type: "text", body: "", embeds: [{ title: "x", url: "http://insecure.example" }] })).toEqual([]);
    expect(readEmbeds({ type: "action", body: "x", embeds: [example] })).toEqual([]);
    expect(readEmbeds(null)).toEqual([]);
  });
});
