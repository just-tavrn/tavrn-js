// SPDX-License-Identifier: MPL-2.0
/**
 * Wiring of the MLS session manager to a {@link KeyStore}: the client state, the pinned identity keys,
 * the MLS bookkeeping and the verified contacts are named secrets of the open account; the backup key is
 * derived from its master secret on demand, the own identity key (derived or rotated, ENCRYPTION.md §9a) is read
 * once when the manager opens (a rotation reopens it).
 */
import { loadClient, saveClient } from "./account";
import { ownIdentityPublicKey } from "./identity";
import { readJsonSecret, withMasterSecret, writeJsonSecret, type KeyStore } from "./keystore";
import { MlsManager, type MlsApi, type MlsDeps, type MlsMeta, type Pin, type VerifiedContact } from "./mls";

/** Names of the manager's secrets in the store. */
export const PINS = "pins";
export const META = "mls-meta";
/** Verified contacts (FEDERATION.md §10.2), stored encrypted next to the pins. */
export const VERIFIED = "verified-contacts";

export interface OpenMlsOptions {
  api: MlsApi;
  /** Own user address `name@domain`. */
  address: string;
  deviceId: string;
  /** Domain of this user's home node. */
  homeDomain: string;
  onEvent?: MlsDeps["onEvent"];
  backupDelayMs?: number;
}

/**
 * The session manager of the store's open account, or null if this device has no MLS client yet
 * (run `ensureDevice` first). Requires an unlocked store. The caller starts the background work it
 * wants (`restoreBackups`, `processWelcomes` per node, `flushBackups` if `hasPendingBackups()`).
 */
/** The store and the cached own identity key of every open manager (see {@link reloadOwnIdentity}). */
const ownKeys = new WeakMap<MlsManager, { store: KeyStore; own: { key: string } }>();

/**
 * After the account's identity key was rotated (here or on another device, ENCRYPTION.md §9a): the manager verifies
 * its own devices against the new key from now on. Nothing else changes (device key, groups, epoch keys).
 */
export async function reloadOwnIdentity(manager: MlsManager): Promise<void> {
  const entry = ownKeys.get(manager);
  if (!entry) return;
  entry.own.key = await ownIdentityPublicKey(entry.store);
  manager.forgetDevices(manager.address);
}

export async function openMlsManager(store: KeyStore, opts: OpenMlsOptions): Promise<MlsManager | null> {
  const client = await loadClient(store);
  if (!client) return null;
  const pins = await readJsonSecret<Record<string, Pin>>(store, PINS, {});
  const meta = await readJsonSecret<MlsMeta>(store, META, { convs: {} });
  const verified = await readJsonSecret<Record<string, VerifiedContact>>(store, VERIFIED, {});
  const own = { key: await ownIdentityPublicKey(store) };
  const manager = new MlsManager({
    api: opts.api,
    client,
    address: opts.address,
    deviceId: opts.deviceId,
    homeDomain: opts.homeDomain,
    persist: (c) => saveClient(store, c),
    backupKey: () => withMasterSecret(store, (ms) => ms.backupKey()),
    ownIdentityKey: () => own.key,
    pins,
    savePins: (p) => writeJsonSecret(store, PINS, p),
    meta,
    saveMeta: (v) => writeJsonSecret(store, META, v),
    verified,
    saveVerified: (v) => writeJsonSecret(store, VERIFIED, v),
    onEvent: opts.onEvent,
    backupDelayMs: opts.backupDelayMs,
  });
  ownKeys.set(manager, { store, own });
  return manager;
}
