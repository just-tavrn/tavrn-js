// SPDX-License-Identifier: MPL-2.0
/**
 * The behaviour every {@link SearchBackend} must have, as a Vitest `describe` block. Exported from
 * `@tavrn/e2ee/search-contract` (not from the main entry, which must not import Vitest) and run against
 * every implementation: `backendContract("memory", () => new MemorySearchBackend())`.
 */
import { describe, expect, it } from "vitest";
import type { SearchBackend, SearchWrite } from "./backend";

const b = (...v: number[]) => new Uint8Array(v);

export function backendContract(name: string, make: () => SearchBackend | Promise<SearchBackend>): void {
  describe(`search backend contract: ${name}`, () => {
    it("puts, reads and deletes records through write()", async () => {
      const be = await make();
      expect(await be.get("docs", "a")).toBeNull();
      await be.write([{ store: "docs", key: "a", value: b(1, 2, 3) }]);
      expect(Array.from((await be.get("docs", "a"))!)).toEqual([1, 2, 3]);
      await be.write([{ store: "docs", key: "a", value: b(4) }]);
      expect(Array.from((await be.get("docs", "a"))!)).toEqual([4]);
      await be.write([{ store: "docs", key: "a", value: null }]);
      expect(await be.get("docs", "a")).toBeNull();
      // Deleting a missing record is not an error.
      await be.write([{ store: "docs", key: "missing", value: null }]);
    });

    it("keeps the stores apart", async () => {
      const be = await make();
      await be.write([
        { store: "docs", key: "k", value: b(1) },
        { store: "postings", key: "k", value: b(2) },
        { store: "meta", key: "k", value: b(3) },
      ]);
      expect(Array.from((await be.get("docs", "k"))!)).toEqual([1]);
      expect(Array.from((await be.get("postings", "k"))!)).toEqual([2]);
      expect(Array.from((await be.get("meta", "k"))!)).toEqual([3]);
      await be.write([{ store: "postings", key: "k", value: null }]);
      expect(await be.get("postings", "k")).toBeNull();
      expect(await be.get("docs", "k")).not.toBeNull();
    });

    it("getMany keeps the order of the keys and returns null for misses", async () => {
      const be = await make();
      await be.write([
        { store: "postings", key: "x", value: b(1) },
        { store: "postings", key: "z", value: b(3) },
      ]);
      const got = await be.getMany("postings", ["z", "nope", "x", "z"]);
      expect(got.map((v) => (v ? Array.from(v) : null))).toEqual([[3], null, [1], [3]]);
      expect(await be.getMany("postings", [])).toEqual([]);
    });

    it("lists the keys of a store", async () => {
      const be = await make();
      await be.write([
        { store: "meta", key: "m1", value: b(1) },
        { store: "meta", key: "m2", value: b(2) },
        { store: "docs", key: "d1", value: b(3) },
      ]);
      expect((await be.keys("meta")).sort()).toEqual(["m1", "m2"]);
      expect(await be.keys("docs")).toEqual(["d1"]);
      expect(await be.keys("postings")).toEqual([]);
    });

    it("size() sums the value lengths of all stores", async () => {
      const be = await make();
      expect(await be.size()).toBe(0);
      await be.write([
        { store: "docs", key: "a", value: new Uint8Array(100) },
        { store: "postings", key: "b", value: new Uint8Array(20) },
        { store: "meta", key: "c", value: new Uint8Array(3) },
      ]);
      expect(await be.size()).toBe(123);
      await be.write([{ store: "docs", key: "a", value: null }]);
      expect(await be.size()).toBe(23);
    });

    it("clear() empties every store", async () => {
      const be = await make();
      await be.write([
        { store: "docs", key: "a", value: b(1) },
        { store: "postings", key: "b", value: b(2) },
        { store: "meta", key: "c", value: b(3) },
      ]);
      await be.clear();
      for (const s of ["docs", "postings", "meta"] as const) expect(await be.keys(s)).toEqual([]);
      expect(await be.size()).toBe(0);
      expect(await be.get("docs", "a")).toBeNull();
    });

    it("applies a batch as a whole: every value is visible once write() resolves, the last write of a key wins", async () => {
      const be = await make();
      const batch: SearchWrite[] = Array.from({ length: 300 }, (_, i) => ({ store: "postings", key: `k${i}`, value: b(i % 256) }));
      batch.push({ store: "postings", key: "k0", value: b(9, 9) });
      batch.push({ store: "postings", key: "k1", value: null });
      await be.write(batch);
      const got = await be.getMany("postings", batch.slice(0, 300).map((w) => w.key));
      expect(got.filter((v) => v !== null)).toHaveLength(299);
      expect(Array.from(got[0]!)).toEqual([9, 9]);
      expect(got[1]).toBeNull();
      expect(Array.from(got[299]!)).toEqual([299 % 256]);
    });

    it("copies values: changing the input or a result afterwards does not change the stored value", async () => {
      const be = await make();
      const v = b(1, 2, 3);
      await be.write([{ store: "docs", key: "a", value: v }]);
      v[0] = 99;
      const got = (await be.get("docs", "a"))!;
      expect(Array.from(got)).toEqual([1, 2, 3]);
      got[1] = 77;
      expect(Array.from((await be.get("docs", "a"))!)).toEqual([1, 2, 3]);
      const [many] = await be.getMany("docs", ["a"]);
      many![2] = 55;
      expect(Array.from((await be.get("docs", "a"))!)).toEqual([1, 2, 3]);
    });

    it("handles arbitrary string keys", async () => {
      const be = await make();
      const keys = ["", "a:b", "ü/ß\u0000x", "0123456789abcdef0123456789abcdef"];
      await be.write(keys.map((key, i) => ({ store: "meta" as const, key, value: b(i) })));
      expect((await be.getMany("meta", keys)).map((v) => (v ? v[0] : null))).toEqual([0, 1, 2, 3]);
      expect((await be.keys("meta")).sort()).toEqual([...keys].sort());
    });
  });
}
