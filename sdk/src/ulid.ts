// SPDX-License-Identifier: Apache-2.0
/**
 * ULIDs made by the client (PROTOCOL.md §7e: the id of a new thread, so the device signature of its first message can
 * cover `thread_id`). 48 bits of milliseconds and 80 random bits in Crockford's base32, uppercase, 26 characters.
 */

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** A ULID of `now` (milliseconds since the epoch) with random bits from `crypto.getRandomValues`. */
export function newUlid(now: number = Date.now(), random: (bytes: Uint8Array<ArrayBuffer>) => void = (b) => crypto.getRandomValues(b)): string {
  if (!Number.isSafeInteger(now) || now < 0 || now > 2 ** 48 - 1) throw new RangeError("ULID time: 0 to 2^48 - 1 milliseconds");
  let time = "";
  let t = now;
  for (let i = 0; i < 10; i++) {
    time = ALPHABET[t % 32] + time;
    t = Math.floor(t / 32);
  }
  const bytes = new Uint8Array(10);
  random(bytes);
  // 80 bits in 16 characters of 5 bits each.
  let bits = 0n;
  for (const b of bytes) bits = (bits << 8n) | BigInt(b);
  let rest = "";
  for (let i = 0; i < 16; i++) {
    rest = ALPHABET[Number(bits & 31n)] + rest;
    bits >>= 5n;
  }
  return time + rest;
}

const CANONICAL = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

/** A ULID in canonical form: 26 characters of Crockford's base32, uppercase, at most 2^48 - 1 milliseconds. */
export function isUlid(id: unknown): id is string {
  return typeof id === "string" && CANONICAL.test(id);
}

/** The time of a ULID in milliseconds, or null for anything that is not a canonical ULID. */
export function ulidTime(id: string): number | null {
  if (!isUlid(id)) return null;
  let t = 0;
  for (const c of id.slice(0, 10)) t = t * 32 + ALPHABET.indexOf(c);
  return t;
}
