// SPDX-License-Identifier: MPL-2.0
/** Small bounded caches of the session manager (a session may run for weeks: a bot, a tab that stays open). */

/**
 * A `Map` with at most `limit` entries: a read moves its entry to the newest end, a write beyond the limit evicts the
 * least recently used entry (`Map` keeps insertion order).
 */
export class LruMap<K, V> {
  private readonly map = new Map<K, V>();

  constructor(readonly limit: number) {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError("LruMap: limit must be a positive integer");
  }

  get size(): number {
    return this.map.size;
  }

  /** The value of `key`, marked as recently used. */
  get(key: K): V | undefined {
    const value = this.map.get(key);
    if (value === undefined) return undefined;
    this.map.delete(key);
    this.map.set(key, value);
    return value;
  }

  /** The value of `key` without changing its age. */
  peek(key: K): V | undefined {
    return this.map.get(key);
  }

  has(key: K): boolean {
    return this.map.has(key);
  }

  set(key: K, value: V): this {
    this.map.delete(key);
    this.map.set(key, value);
    if (this.map.size > this.limit) {
      const oldest = this.map.keys().next();
      if (!oldest.done) this.map.delete(oldest.value);
    }
    return this;
  }

  delete(key: K): boolean {
    return this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  /** Deletes every entry `drop` selects. */
  deleteWhere(drop: (value: V, key: K) => boolean): void {
    for (const [k, v] of [...this.map]) if (drop(v, k)) this.map.delete(k);
  }
}

/**
 * A 53-bit hash of a string (cyrb53, public domain), as a fingerprint of a ciphertext in a cache entry: the cache keys
 * name the message, the fingerprint tells a changed ciphertext of the same message apart without keeping it. Not a
 * cryptographic hash; a collision can only make the cache answer with the earlier result of the same message.
 */
export function fingerprint(s: string, seed = 0): string {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761);
    h2 = Math.imul(h2 ^ c, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return `${s.length.toString(36)}.${(4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36)}`;
}

/**
 * Nonces seen in the last `keepMs` (replay windows of signed arguments and component values): each one counts until
 * `keepMs` after it was seen. Expired nonces are swept from the oldest end (insertion order follows the clock), so a
 * check costs O(1) amortized instead of a scan of the whole window.
 */
export class NonceWindow {
  private readonly seen = new Map<string, number>();

  constructor(private readonly keepMs: number) {}

  get size(): number {
    return this.seen.size;
  }

  /** Whether `nonce` was remembered within the window at `now`. */
  has(nonce: string, now: number): boolean {
    this.sweep(now);
    const at = this.seen.get(nonce);
    return at !== undefined && now - at <= this.keepMs;
  }

  remember(nonce: string, now: number): void {
    this.seen.delete(nonce);
    this.seen.set(nonce, now);
  }

  private sweep(now: number): void {
    for (const [nonce, at] of this.seen) {
      if (now - at <= this.keepMs) break;
      this.seen.delete(nonce);
    }
  }
}
