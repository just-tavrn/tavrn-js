// SPDX-License-Identifier: MPL-2.0
/**
 * Keys of the local search index. Two non-extractable WebCrypto keys are derived from the device's
 * local storage key (ENCRYPTION.md §2.1) with HKDF-SHA-256: an HMAC key that turns every record name
 * (message ids, conversation ids, lookup keys) into an opaque token, and an AES-256-GCM key that seals
 * every record value. A stolen index store reveals record counts and sizes, nothing else.
 */
import { localStorageKey, type KeyStore } from "../keystore";

export interface SearchKeys {
  /** HMAC-SHA-256 key of the token keys (record names). */
  mac: CryptoKey;
  /** AES-256-GCM key of the record values. */
  enc: CryptoKey;
}

/** Thrown while the key store (or the index, after `lock()`) is locked. */
export class SearchLockedError extends Error {
  override name = "search_locked";
  constructor() {
    super("The local search index is locked");
  }
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("WebCrypto is unavailable");
  return s;
}

function bytes(s: string): Uint8Array<ArrayBuffer> {
  return enc.encode(s);
}

/**
 * HKDF-SHA-256 (salt = 32 zero bytes) of the local key: info "tavrn search index v1 mac" → HMAC-SHA-256
 * key, info "tavrn search index v1 enc" → AES-GCM-256 key. Both non-extractable.
 */
export async function deriveSearchKeys(localKey: Uint8Array): Promise<SearchKeys> {
  const s = subtle();
  const ikm = await s.importKey("raw", localKey as Uint8Array<ArrayBuffer>, "HKDF", false, ["deriveKey"]);
  const salt = new Uint8Array(32);
  const [mac, aes] = await Promise.all([
    s.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: bytes("tavrn search index v1 mac") },
      ikm,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"],
    ),
    s.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: bytes("tavrn search index v1 enc") },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    ),
  ]);
  return { mac, enc: aes };
}

/** The search keys of the open account of `store`; throws {@link SearchLockedError} while it is locked. */
export async function searchKeysFromStore(store: KeyStore): Promise<SearchKeys> {
  if (!store.isUnlocked()) throw new SearchLockedError();
  const master = store.masterSecret();
  let local: Uint8Array | null = null;
  try {
    local = await localStorageKey(master, store.deviceId());
    return await deriveSearchKeys(local);
  } finally {
    master.fill(0);
    local?.fill(0);
  }
}

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

/** The token key of a record name: hex(HMAC(mac, parts joined by NUL)), first 32 hex digits (128 bits). */
export async function tokenKey(keys: SearchKeys, ...parts: string[]): Promise<string> {
  const sig = new Uint8Array(await subtle().sign("HMAC", keys.mac, bytes(parts.join("\u0000"))));
  let out = "";
  for (let i = 0; i < 16; i++) out += HEX[sig[i]!];
  return out;
}

/** iv (12 bytes) || AES-GCM(JSON of `value`), bound to `aad` (store name + NUL + record key). */
export async function seal(keys: SearchKeys, aad: string, value: unknown): Promise<Uint8Array> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle().encrypt({ name: "AES-GCM", iv, additionalData: bytes(aad) }, keys.enc, bytes(JSON.stringify(value)));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return out;
}

/** Opens a value of {@link seal}; throws if the key, the aad or the bytes do not match. */
export async function open<T>(keys: SearchKeys, aad: string, sealed: Uint8Array): Promise<T> {
  if (sealed.length < 12 + 16) throw new Error("sealed search record too short");
  const plain = await subtle().decrypt(
    { name: "AES-GCM", iv: sealed.slice(0, 12), additionalData: bytes(aad) },
    keys.enc,
    sealed.slice(12),
  );
  return JSON.parse(dec.decode(plain)) as T;
}
