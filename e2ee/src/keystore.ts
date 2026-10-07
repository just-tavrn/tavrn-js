// SPDX-License-Identifier: MPL-2.0
/**
 * Local key storage (ENCRYPTION.md §2.1 "local storage key"). A `KeyStore` keeps, per account, the
 * device id, the 32-byte master secret and named secrets (the exported MLS client state, pins, MLS
 * bookkeeping, verified contacts), everything encrypted at rest under
 * `local_key = MasterSecret.localStorageKey(deviceId)`.
 *
 * Implementations: the IndexedDB store of the web client (tavrn-web `src/crypto/store.ts`, with "lock on
 * close"), {@link MemoryKeyStore} (tests, short-lived tools) and the file store for Node.js
 * (`FileKeyStore` from `@tavrn/e2ee/node`, the state directory of a bot).
 *
 * At most one account is open ("unlocked") at a time; the secret accessors act on that account and
 * throw while the store is locked.
 */
import { MasterSecret } from "@tavrn/crypto";
import { ensureCrypto } from "./wasm";

export type CryptoStatus = "none" | "locked" | "unlocked";

export interface KeyStore {
  /** Whether this store holds the account's master secret, and whether it is readable right now. */
  status(account: string): Promise<CryptoStatus>;
  /** Device id the account's local data belongs to, or null if there is none. */
  deviceIdOf(account: string): Promise<string | null>;
  /**
   * Opens the store without user interaction (a persisted local key); false if that is not possible
   * (no data, "lock on close", or a store that always needs the master secret).
   */
  resume(account: string): Promise<boolean>;
  /**
   * Stores a master secret for this device and unlocks. Replaces earlier data of the account, including
   * its named secrets.
   */
  saveMaster(account: string, deviceId: string, master: Uint8Array): Promise<void>;
  /** Unlocks existing data with the master secret; throws {@link LocalKeyMismatchError} if it does not open it. */
  unlockWithMaster(account: string, master: Uint8Array): Promise<void>;
  isUnlocked(account?: string): boolean;
  /** Forgets the key and the master secret in memory (data stays stored). */
  lock(): void;
  /** Deletes all local data of the account and locks if it was open. */
  wipe(account: string): Promise<void>;
  /** Account address of the open store, or null. */
  account(): string | null;
  /** Device id of the open account. */
  deviceId(): string;
  /** A copy of the 32-byte master secret; the caller should `fill(0)` it after use. */
  masterSecret(): Uint8Array;
  putSecret(name: string, value: Uint8Array): Promise<void>;
  getSecret(name: string): Promise<Uint8Array | null>;
  deleteSecret(name: string): Promise<void>;
}

/** Thrown when a master secret does not open this device's local data (stale entry or reset elsewhere). */
export class LocalKeyMismatchError extends Error {
  constructor() {
    super("The master secret does not match the local data of this device");
    this.name = "local_key_mismatch";
  }
}

/** Additional data of every sealed value: binds it to the account and the entry name. */
export function localAad(account: string, name: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`tavrn local v1\u0000${account}\u0000${name}`);
}

/** The raw 32-byte local storage key of `deviceId` (ENCRYPTION.md §2.1); the caller zeroes it after use. */
export async function localStorageKey(master: Uint8Array, deviceId: string): Promise<Uint8Array> {
  await ensureCrypto();
  const ms = MasterSecret.fromBytes(master);
  try {
    return ms.localStorageKey(deviceId);
  } finally {
    ms.free();
  }
}

/** Runs `fn` with the store's master secret as a WASM object, freed afterwards. Requires an unlocked store. */
export function withMasterSecret<T>(store: KeyStore, fn: (m: MasterSecret) => T): T {
  const bytes = store.masterSecret();
  const master = MasterSecret.fromBytes(bytes);
  bytes.fill(0);
  try {
    return fn(master);
  } finally {
    master.free();
  }
}

/**
 * Runs `fn` with a fresh copy of the backup key (ENCRYPTION.md §2.1), zeroed afterwards; null while the
 * store is locked. Used for data the user keeps encrypted on the home node (whiteboard scenes).
 */
export function withBackupKey<T>(store: KeyStore, fn: (key: Uint8Array) => T): T | null {
  if (!store.isUnlocked()) return null;
  const key = withMasterSecret(store, (m) => m.backupKey());
  try {
    return fn(key);
  } finally {
    key.fill(0);
  }
}

/** Reads a named secret holding JSON; `fallback` if it is missing or unreadable. */
export async function readJsonSecret<T>(store: KeyStore, name: string, fallback: T): Promise<T> {
  const bytes = await store.getSecret(name);
  if (!bytes) return fallback;
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  } catch {
    return fallback;
  } finally {
    bytes.fill(0);
  }
}

/** Stores a value as a JSON secret; does nothing while the store is locked (e.g. after sign-out). */
export async function writeJsonSecret(store: KeyStore, name: string, value: unknown): Promise<void> {
  if (!store.isUnlocked()) return;
  await store.putSecret(name, new TextEncoder().encode(JSON.stringify(value)));
}
