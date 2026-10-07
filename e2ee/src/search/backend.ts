// SPDX-License-Identifier: MPL-2.0
/**
 * Storage backend of the local search index: three key-value stores of opaque strings to opaque bytes.
 * The index seals every value and derives every key with HMAC before it reaches the backend, so a
 * backend never sees plaintext. Implementations: {@link MemorySearchBackend} (tests, tools), the
 * IndexedDB backend of the web client (tavrn-web `src/search/idbBackend.ts`) and, later (phase 6), a SQLite
 * backend of the Tauri app. Keep the interface minimal so that all of them stay simple; the shared
 * behaviour is pinned by `backendContract` (`@tavrn/e2ee/search-contract`).
 */

export type SearchStore = "docs" | "postings" | "meta";

export const SEARCH_STORES: readonly SearchStore[] = ["docs", "postings", "meta"];

export interface SearchWrite {
  store: SearchStore;
  key: string;
  /** null deletes the record. */
  value: Uint8Array | null;
}

export interface SearchBackend {
  get(store: SearchStore, key: string): Promise<Uint8Array | null>;
  /** One result per key, in the order of `keys`; null for a missing record. */
  getMany(store: SearchStore, keys: string[]): Promise<(Uint8Array | null)[]>;
  /** Applies all writes atomically where the backend can (one IndexedDB transaction); null deletes. */
  write(batch: SearchWrite[]): Promise<void>;
  /** Every key of a store (meta and maintenance only; never needed on the search path). */
  keys(store: SearchStore): Promise<string[]>;
  /** Sum of value byte lengths (stats). */
  size(): Promise<number>;
  clear(): Promise<void>;
}

/** A {@link SearchBackend} in process memory. Values are copied on write and on read. */
export class MemorySearchBackend implements SearchBackend {
  private readonly stores = new Map<SearchStore, Map<string, Uint8Array>>(SEARCH_STORES.map((s) => [s, new Map()]));

  private store(store: SearchStore): Map<string, Uint8Array> {
    const m = this.stores.get(store);
    if (!m) throw new Error(`unknown search store ${String(store)}`);
    return m;
  }

  async get(store: SearchStore, key: string): Promise<Uint8Array | null> {
    return this.store(store).get(key)?.slice() ?? null;
  }

  async getMany(store: SearchStore, keys: string[]): Promise<(Uint8Array | null)[]> {
    const m = this.store(store);
    return keys.map((k) => m.get(k)?.slice() ?? null);
  }

  async write(batch: SearchWrite[]): Promise<void> {
    const copies = batch.map((w) => ({ m: this.store(w.store), key: w.key, value: w.value?.slice() ?? null }));
    for (const w of copies) {
      if (w.value) w.m.set(w.key, w.value);
      else w.m.delete(w.key);
    }
  }

  async keys(store: SearchStore): Promise<string[]> {
    return [...this.store(store).keys()];
  }

  async size(): Promise<number> {
    let n = 0;
    for (const m of this.stores.values()) for (const v of m.values()) n += v.byteLength;
    return n;
  }

  async clear(): Promise<void> {
    for (const m of this.stores.values()) m.clear();
  }

  /** Every record (copies), for tests that inspect what is stored at rest. */
  dump(): { store: SearchStore; key: string; value: Uint8Array }[] {
    const out: { store: SearchStore; key: string; value: Uint8Array }[] = [];
    for (const [store, m] of this.stores) for (const [key, value] of m) out.push({ store, key, value: value.slice() });
    return out;
  }
}
