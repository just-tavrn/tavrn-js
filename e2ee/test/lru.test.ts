// SPDX-License-Identifier: MPL-2.0
import { describe, expect, it } from "vitest";
import { LruMap, NonceWindow, fingerprint } from "../src/lru";

describe("LruMap", () => {
  it("evicts the least recently used entry beyond its limit", () => {
    const m = new LruMap<string, number>(3);
    m.set("a", 1).set("b", 2).set("c", 3);
    expect(m.get("a")).toBe(1); // a is now the newest
    m.set("d", 4);
    expect(m.size).toBe(3);
    expect(m.has("b")).toBe(false);
    expect([m.peek("a"), m.peek("c"), m.peek("d")]).toEqual([1, 3, 4]);
    m.set("c", 30); // overwrite refreshes
    m.set("e", 5);
    expect(m.has("a")).toBe(false);
    expect(m.get("c")).toBe(30);
    m.deleteWhere((v) => v > 4);
    expect(m.has("c") || m.has("e")).toBe(false);
    expect(() => new LruMap(0)).toThrow(RangeError);
  });
});

describe("fingerprint", () => {
  it("tells different strings apart and is stable", () => {
    const a = "QWxsZSBtZWluZSBFbnRjaGVu".repeat(10);
    expect(fingerprint(a)).toBe(fingerprint(`${a}`));
    expect(fingerprint(a)).not.toBe(fingerprint(`${a.slice(0, -1)}x`));
    expect(fingerprint(a)).not.toBe(fingerprint(a.slice(1)));
    const seen = new Set(Array.from({ length: 20_000 }, (_, i) => fingerprint(`content-${i}`)));
    expect(seen.size).toBe(20_000);
  });
});

describe("NonceWindow", () => {
  it("remembers a nonce for exactly keepMs and sweeps from the oldest end", () => {
    const w = new NonceWindow(100);
    w.remember("a", 0);
    w.remember("b", 50);
    expect(w.has("a", 100)).toBe(true);
    expect(w.has("a", 101)).toBe(false);
    expect(w.size).toBe(1);
    expect(w.has("b", 150)).toBe(true);
    expect(w.has("b", 151)).toBe(false);
    expect(w.size).toBe(0);
  });

  it("checks in amortized constant time with a full window", () => {
    const w = new NonceWindow(10 * 60_000);
    for (let i = 0; i < 60_000; i++) w.remember(`n${i}`, i);
    const t = performance.now();
    for (let i = 0; i < 10_000; i++) w.has(`x${i}`, 60_000 + i);
    // A scan of the whole window per check takes seconds here; the sweep from the front stops at the first live one.
    expect(performance.now() - t).toBeLessThan(200);
    expect(w.size).toBe(60_000);
  });
});
