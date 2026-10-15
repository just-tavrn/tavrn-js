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
import { MlsError, MlsManager, type MlsApi, type MlsDeps, type MlsEvent, type MlsMeta, type MlsTabLink, type Pin, type VerifiedContact } from "./mls";
import { TabCoordinator, type TabOptions } from "./tabs";

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
  /** Failed background writes of the bookkeeping (see {@link MlsDeps.onError}). */
  onError?: MlsDeps["onError"];
  backupDelayMs?: number;
  /**
   * Browsers: coordinate the MLS state with the other tabs of this browser profile that open the same account
   * (`tabs.ts`): one tab owns and writes the state, the others forward their state-changing calls to it. Without
   * Web Locks or BroadcastChannel the manager works alone. Omit it in a single process (bots).
   */
  tabs?: TabOptions;
}

/** Events the owning tab passes on to the other tabs (their views re-check rosters and messages). */
const SHARED_EVENTS = new Set<MlsEvent["type"]>(["epoch", "rejoined", "removed"]);

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
  // Tab coordination: the election comes first, so that an owner loads the newest state.
  let resolveManager: (m: MlsManager | null) => void = () => undefined;
  const ready = new Promise<MlsManager | null>((r) => (resolveManager = r));
  /** Only the owning tab (or a manager without coordination) writes the client state and the bookkeeping. */
  let writable = true;
  let stale = false;
  let reloading: Promise<void> = Promise.resolve();
  const loadState = async () => {
    const c = await loadClient(store);
    return c ? { client: c, meta: await readJsonSecret<MlsMeta>(store, META, { convs: {} }) } : null;
  };
  /** Follower: reloads the copy when the owner wrote the state since the last reload. */
  const refresh = async (): Promise<void> => {
    const m = await ready;
    if (stale && m) {
      stale = false;
      reloading = m.reloadState(loadState).catch(() => undefined);
    }
    return reloading;
  };
  const tabs = opts.tabs
    ? await TabCoordinator.open(opts.tabs, {
        serve: async (method, args) => {
          const m = await ready;
          if (!m) throw new MlsError("owner_unavailable");
          return m.serveForwarded(method, args);
        },
        takeOver: async () => {
          const m = await ready;
          if (!m) return;
          if (!store.isUnlocked(opts.address)) throw new MlsError("owner_unavailable");
          await m.reloadState(loadState, () => {
            writable = true;
            stale = false;
          });
        },
        stale: () => {
          stale = true;
        },
        event: (e) => {
          void refresh()
            .then(() => opts.onEvent?.(e as MlsEvent))
            .catch(() => undefined);
        },
      })
    : null;
  if (tabs) writable = tabs.ready;
  const client = await loadClient(store);
  if (!client) {
    tabs?.close();
    resolveManager(null);
    return null;
  }
  const pins = await readJsonSecret<Record<string, Pin>>(store, PINS, {});
  const meta = await readJsonSecret<MlsMeta>(store, META, { convs: {} });
  const verified = await readJsonSecret<Record<string, VerifiedContact>>(store, VERIFIED, {});
  const own = { key: await ownIdentityPublicKey(store) };
  const link: MlsTabLink | undefined = tabs
    ? {
        local: () => tabs.ready,
        forward: async (operation, args) => {
          const value = await tabs.call(operation, args);
          await refresh();
          return value;
        },
        close: () => tabs.close(),
      }
    : undefined;
  const manager = new MlsManager({
    api: opts.api,
    client,
    address: opts.address,
    deviceId: opts.deviceId,
    homeDomain: opts.homeDomain,
    persist: async (c) => {
      if (!writable) return;
      await saveClient(store, c);
      tabs?.notifyState();
    },
    backupKey: () => withMasterSecret(store, (ms) => ms.backupKey()),
    ownIdentityKey: () => own.key,
    pins,
    savePins: (p) => writeJsonSecret(store, PINS, p),
    meta,
    saveMeta: async (v) => {
      if (writable) await writeJsonSecret(store, META, v);
    },
    verified,
    saveVerified: (v) => writeJsonSecret(store, VERIFIED, v),
    onEvent: (e) => {
      opts.onEvent?.(e);
      if (SHARED_EVENTS.has(e.type)) tabs?.notifyEvent(e);
    },
    onError: opts.onError,
    backupDelayMs: opts.backupDelayMs,
    tabs: link,
  });
  ownKeys.set(manager, { store, own });
  resolveManager(manager);
  return manager;
}
