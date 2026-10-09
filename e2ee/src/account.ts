// SPDX-License-Identifier: MPL-2.0
/**
 * Account-level encryption flows (ENCRYPTION.md §2.4 client flows, §3, §8, §9): setting up a new account,
 * unlocking a device with the recovery key or a passkey PRF output, attesting the device and keeping
 * KeyPackages topped up, regenerating the recovery key and the identity reset. Every flow works on an
 * injected {@link KeyStore}; nothing here touches the DOM (the WebAuthn ceremony that yields a PRF output
 * stays in the web client). Secrets stay in memory as briefly as possible; WASM objects are freed after use.
 */
import { Client, MasterSecret, RecoveryKey, passkeyMethod, passkeyWrappingKey, unwrapIdentityKey, unwrapMasterSecret, wrapMasterSecret } from "@tavrn/crypto";
import { TavrnApiError, b64urlDecode, b64urlEncode, type TavrnApi } from "@tavrn/sdk";
import { E2eeError } from "./errors";
import { IDENTITY_SEED, chainReaches, ownIdentityPublicKey, resolveIdentity, syncIdentity, withIdentityKey } from "./identity";
import { LocalKeyMismatchError, withMasterSecret, type CryptoStatus, type KeyStore } from "./keystore";
import { ensureCrypto } from "./wasm";

/** Name of the exported MLS client state (device key + groups) in the key store. */
export const CLIENT_STATE = "mls-client";
/** KeyPackages uploaded at once, and the level below which the client tops up (ENCRYPTION.md §3.2). */
export const KEY_PACKAGE_BATCH = 20;
export const KEY_PACKAGE_MIN = 5;
const METHOD_RECOVERY = "recovery";

export interface E2eeContext {
  /** The routes used: `keys` (all flows) and `secretStorage` (recovery key and passkey flows). */
  api: Pick<TavrnApi, "keys" | "secretStorage">;
  /** Local username (path segment of `GET /users/{username}/keys`). */
  username: string;
  /** Full user address `username@domain`. */
  address: string;
  /** Device id of the current session (or bot token). */
  deviceId: string;
  /** Local storage of this device. */
  store: KeyStore;
  /** `client` in the params of secret storage entries (default `tavrn-web`). */
  clientName?: string;
  /**
   * `ensureDevice`: creates `count` KeyPackages (base64url) in the client state of the open session manager
   * (`MlsManager.createKeyPackages`, which also runs in the tab that owns the state), so that no second copy of the
   * state is written next to it. Omitted or null: they are created in the stored state.
   */
  keyPackages?: (count: number) => Promise<string[] | null>;
}

export { E2eeError, type E2eeErrorCode } from "./errors";

function code(e: unknown): string | undefined {
  return e instanceof TavrnApiError ? e.code : undefined;
}

function params(ctx: E2eeContext) {
  return { client: ctx.clientName ?? "tavrn-web", v: 1 };
}

/**
 * Status of this device for the account: resumes with a persisted local key if possible. Local data of
 * another device (a login that could not continue the stored device, PROTOCOL.md §5b) is discarded; that
 * old device is reported to `onStaleDevice` first, so the caller can have it removed (its keys are gone
 * with the local data, its MLS leaves would stay as ghosts otherwise, ENCRYPTION.md §4.7).
 */
export async function localStatus(
  store: KeyStore,
  address: string,
  deviceId: string | null,
  opts: { onStaleDevice?: (oldDeviceId: string) => void | Promise<void> } = {},
): Promise<CryptoStatus> {
  const owner = await store.deviceIdOf(address);
  if (owner && deviceId && owner !== deviceId) {
    try {
      await opts.onStaleDevice?.(owner);
    } catch {
      /* best effort: housekeeping deletes the device when it stays unused */
    }
    await store.wipe(address);
    return "none";
  }
  if (await store.resume(address)) return "unlocked";
  return store.status(address);
}

/** A device proof as login requests carry it (`device`, PROTOCOL.md §5b). */
export interface DeviceProof {
  id: string;
  nonce: string;
  proof: string;
}

/**
 * Proof that this store holds the key of the account's stored device, over a login nonce of the node
 * (`POST /auth/device-nonce`, ENCRYPTION.md §3.4). Null when the store has no device for `address` or
 * cannot open it without the user (lock on close): the login then creates a new device.
 */
export async function deviceLoginProof(store: KeyStore, address: string, nonce: () => Promise<string>): Promise<DeviceProof | null> {
  const deviceId = await store.deviceIdOf(address);
  if (!deviceId) return null;
  if (!store.isUnlocked(address) && !(await store.resume(address))) return null;
  const client = await loadClient(store);
  if (!client) return null;
  try {
    if (client.deviceId !== deviceId || client.userAddress !== address) return null;
    const n = await nonce();
    return { id: deviceId, nonce: n, proof: b64urlEncode(client.signDeviceLogin(n)) };
  } finally {
    client.free();
  }
}

/** The MLS client of this device from the store (null if none was created yet). Requires an unlocked store. */
export async function loadClient(store: KeyStore): Promise<Client | null> {
  await ensureCrypto();
  const state = await store.getSecret(CLIENT_STATE);
  if (!state) return null;
  try {
    return Client.importState(state);
  } finally {
    state.fill(0);
  }
}

/** Persists the client state; call after every mutating call on the client. */
export async function saveClient(store: KeyStore, client: Client): Promise<void> {
  const state = client.exportState();
  try {
    await store.putSecret(CLIENT_STATE, state);
  } finally {
    state.fill(0);
  }
}

function withMaster<T>(store: KeyStore, fn: (m: MasterSecret) => T): T {
  if (!store.isUnlocked()) throw new E2eeError("locked");
  return withMasterSecret(store, fn);
}

/** Devices (`address/device id`) whose share key this session published or asked the node for: asked once. */
const sharePublished = new Set<string>();

/**
 * Makes this device usable for encryption: follows a rotation of the identity key done on another device (§9a),
 * creates its MLS client (device key) if needed, attests it with the current identity key (§3.1) and keeps at least
 * {@link KEY_PACKAGE_MIN} KeyPackages uploaded (§3.2). Idempotent; requires an unlocked store.
 */
export async function ensureDevice(ctx: E2eeContext): Promise<void> {
  await ensureCrypto();
  const { store } = ctx;
  await syncIdentity(ctx.api, store, ctx.username, ctx.address);
  let client = await loadClient(store);
  if (!client) {
    client = Client.create(ctx.address, ctx.deviceId);
    await saveClient(store, client);
  }
  try {
    const devicePublicKey = client.devicePublicKey;
    if (!store.isUnlocked()) throw new E2eeError("locked");
    const signature = await withIdentityKey(store, (k) => k.attestDevice(ctx.address, ctx.deviceId, devicePublicKey));
    // The device's share key goes with the device key (ENCRYPTION.md §3.1); a device attested without one publishes it
    // once (best effort: nodes without `history.shares2` do not know the route, shares then stay format 1).
    const shareKey = client.shareKey();
    const share = { share_public_key: b64urlEncode(shareKey.publicKey), share_key_signature: b64urlEncode(shareKey.signature) };
    shareKey.free();
    try {
      await ctx.api.keys.putDeviceKey(ctx.deviceId, { device_public_key: b64urlEncode(devicePublicKey), identity_signature: b64urlEncode(signature), ...share });
    } catch (e) {
      if (code(e) !== "e2ee.device_key_exists") throw e;
      if (!sharePublished.has(`${ctx.address}/${ctx.deviceId}`)) {
        // Asked once per session, also when it fails (a node without the route); the next start asks again.
        sharePublished.add(`${ctx.address}/${ctx.deviceId}`);
        await Promise.resolve()
          .then(() => ctx.api.keys.putShareKey(ctx.deviceId, share))
          .catch(() => undefined);
      }
    }
    const { count } = await ctx.api.keys.countKeyPackages(ctx.deviceId);
    if (count < KEY_PACKAGE_MIN) {
      let packages = (await ctx.keyPackages?.(KEY_PACKAGE_BATCH - count)) ?? null;
      if (!packages) {
        packages = Array.from({ length: KEY_PACKAGE_BATCH - count }, () => b64urlEncode(client.createKeyPackage()));
        await saveClient(store, client);
      }
      await ctx.api.keys.uploadKeyPackages(ctx.deviceId, { key_packages: packages });
    }
  } finally {
    client.free();
  }
}

async function putRecovery(ctx: E2eeContext, recovery: RecoveryKey) {
  const key = recovery.wrappingKey();
  try {
    const wrapped = withMaster(ctx.store, (m) => wrapMasterSecret(m, key, ctx.address, METHOD_RECOVERY));
    await ctx.api.secretStorage.putRecovery({ wrapped: b64urlEncode(wrapped), params: params(ctx) });
  } finally {
    key.fill(0);
  }
}

/** Uploads the `passkey:<id>` entry for a PRF-capable credential (requires an unlocked store). */
export async function addPasskeySecret(ctx: E2eeContext, credentialId: string, prf: Uint8Array): Promise<void> {
  await ensureCrypto();
  const key = passkeyWrappingKey(prf);
  try {
    const method = passkeyMethod(credentialId);
    const wrapped = withMaster(ctx.store, (m) => wrapMasterSecret(m, key, ctx.address, method));
    await ctx.api.secretStorage.putPasskey(credentialId, { wrapped: b64urlEncode(wrapped), params: params(ctx) });
  } finally {
    key.fill(0);
  }
}

async function identityKeyOnNode(ctx: E2eeContext): Promise<string | null> {
  return (await ctx.api.keys.get(ctx.username)).identity_public_key ?? null;
}

/**
 * Registration (ENCRYPTION.md §2.4 flow 1), after the user confirmed `recovery`: master secret (kept
 * locally first, so a retry after an error reuses it), identity key, `recovery` entry, optional
 * passkey entry, device attestation and KeyPackages.
 */
export async function setupAccount(ctx: E2eeContext, recovery: RecoveryKey, passkey?: { credentialId: string; prf: Uint8Array } | null): Promise<void> {
  await ensureCrypto();
  if ((await localStatus(ctx.store, ctx.address, ctx.deviceId)) !== "unlocked") {
    const fresh = MasterSecret.generate();
    const bytes = fresh.toBytes();
    fresh.free();
    try {
      await ctx.store.saveMaster(ctx.address, ctx.deviceId, bytes);
    } finally {
      bytes.fill(0);
    }
  }
  const identity = b64urlEncode(withMaster(ctx.store, (m) => m.identityPublicKey()));
  try {
    await ctx.api.keys.putIdentity({ identity_public_key: identity });
  } catch (e) {
    if (code(e) !== "e2ee.identity_exists" || (await identityKeyOnNode(ctx)) !== identity) throw code(e) === "e2ee.identity_exists" ? new E2eeError("identity_mismatch") : e;
  }
  await putRecovery(ctx, recovery);
  if (passkey) await addPasskeySecret(ctx, passkey.credentialId, passkey.prf);
  await ensureDevice(ctx);
}

/**
 * Device key carried over an identity reset done on another device, per store: the local master secret
 * is stale, but the device keeps its key (ENCRYPTION.md §9 step 4) and re-attests it after unlocking.
 * Memory only; a restart before unlocking loses it and the device has to be signed in anew.
 */
const carried = new WeakMap<KeyStore, Uint8Array>();

/**
 * Own `identity.changed` from another device: deletes the local master secret and everything else of
 * the account in the store except the MLS client state, which is kept in memory until the user
 * unlocked with the new recovery key ({@link adoptMaster} stores it again).
 */
export async function forgetIdentityKeepDevice(store: KeyStore, address: string): Promise<void> {
  const state = store.isUnlocked(address) ? await store.getSecret(CLIENT_STATE) : null;
  carried.get(store)?.fill(0);
  if (state) carried.set(store, state);
  else carried.delete(store);
  await store.wipe(address);
}

/** Takes over an unwrapped master secret after checking it against the published identity key. */
async function adoptMaster(ctx: E2eeContext, master: MasterSecret): Promise<void> {
  const { store } = ctx;
  const derived = b64urlEncode(master.identityPublicKey());
  const bytes = master.toBytes();
  let seed: Uint8Array | null = null;
  try {
    // §2.4: a stale or forged entry must not be used. The published key is the derived one, or a rotated key the
    // continuity chain reaches from it and the blob holds (§9a).
    const doc = await ctx.api.keys.get(ctx.username);
    seed = await resolveIdentity(ctx.api, doc, derived, (blob) => unwrapIdentityKey(master, blob, ctx.address));
    const keepSeed = async () => {
      if (seed) await store.putSecret(IDENTITY_SEED, seed);
      else await store.deleteSecret(IDENTITY_SEED);
    };
    if ((await localStatus(store, ctx.address, ctx.deviceId)) === "locked") {
      try {
        await store.unlockWithMaster(ctx.address, bytes);
        // Forward only (§9a): local data that already follows a rotated key accepts the published key only when the
        // chain leads to it from that key, so the node cannot roll this device back to an older generation.
        const own = await ownIdentityPublicKey(store);
        const published = doc.identity_public_key ?? derived;
        if (own !== derived && own !== published && !chainReaches(doc.continuity, own, published)) {
          store.lock();
          throw new E2eeError("identity_mismatch");
        }
        await keepSeed();
        await ensureDevice(ctx);
        return;
      } catch (e) {
        // Local data under an older identity (reset on another device): start this device over.
        if (!(e instanceof LocalKeyMismatchError)) throw e;
      }
    }
    await store.saveMaster(ctx.address, ctx.deviceId, bytes);
    await keepSeed();
    const state = carried.get(store);
    if (state) {
      await store.putSecret(CLIENT_STATE, state);
      state.fill(0);
      carried.delete(store);
    }
  } finally {
    bytes.fill(0);
    seed?.fill(0);
    master.free();
  }
  await ensureDevice(ctx);
}

/**
 * The identity public key derived from the local master secret (generation 0, base64url), or null if locked: tells
 * whether this device holds the master secret behind the published key (an identity reset elsewhere replaces it).
 */
export function localIdentityKey(store: KeyStore): string | null {
  if (!store.isUnlocked()) return null;
  return withMasterSecret(store, (m) => b64urlEncode(m.identityPublicKey()));
}

async function entry(ctx: E2eeContext, method: string): Promise<Uint8Array | null> {
  const items = (await ctx.api.secretStorage.list()).items;
  const e = items.find((i) => i.method === method);
  return e ? b64urlDecode(e.wrapped) : null;
}

/** New device, cleared storage or lock on close: unlock with the 24 words, the compact string or the file. */
export async function unlockWithRecoveryKey(ctx: E2eeContext, text: string): Promise<void> {
  await ensureCrypto();
  let recovery: RecoveryKey;
  try {
    recovery = RecoveryKey.fromText(text);
  } catch {
    throw new E2eeError("recovery_key_invalid");
  }
  const key = recovery.wrappingKey();
  recovery.free();
  try {
    const wrapped = await entry(ctx, METHOD_RECOVERY);
    if (!wrapped) throw new E2eeError("no_recovery_entry");
    let master: MasterSecret;
    try {
      master = unwrapMasterSecret(wrapped, key, ctx.address, METHOD_RECOVERY);
    } catch {
      throw new E2eeError("recovery_key_wrong");
    }
    await adoptMaster(ctx, master);
  } finally {
    key.fill(0);
  }
}

/** Unlock with the PRF output of a passkey ceremony (login or the unlock screen). */
export async function unlockWithPasskeyPrf(ctx: E2eeContext, credentialId: string, prf: Uint8Array): Promise<void> {
  await ensureCrypto();
  const method = passkeyMethod(credentialId);
  const wrapped = await entry(ctx, method);
  if (!wrapped) throw new E2eeError("no_passkey_entry");
  const key = passkeyWrappingKey(prf);
  try {
    let master: MasterSecret;
    try {
      master = unwrapMasterSecret(wrapped, key, ctx.address, method);
    } catch {
      throw new E2eeError("passkey_wrong");
    }
    await adoptMaster(ctx, master);
  } finally {
    key.fill(0);
  }
}

/** Credential ids that have a passkey entry in the secret storage. */
export async function passkeyEntryIds(api: Pick<TavrnApi, "secretStorage">): Promise<string[]> {
  return (await api.secretStorage.list()).items.filter((i) => i.method.startsWith("passkey:")).map((i) => i.method.slice("passkey:".length));
}

/** Settings: a new recovery key re-wraps the same master secret (ENCRYPTION.md §2.4 flow 3). */
export async function regenerateRecoveryKey(ctx: E2eeContext, recovery: RecoveryKey): Promise<void> {
  await ensureCrypto();
  await putRecovery(ctx, recovery);
}

/**
 * Identity reset (ENCRYPTION.md §9) after the user confirmed the new recovery key: new master secret
 * and identity key, `recovery` entry, re-attestation of this device's existing key, KeyPackages.
 */
export async function resetIdentity(ctx: E2eeContext, password: string, recovery: RecoveryKey): Promise<void> {
  await ensureCrypto();
  const { store } = ctx;
  const master = MasterSecret.generate();
  const bytes = master.toBytes();
  try {
    await ctx.api.keys.resetIdentity({ identity_public_key: b64urlEncode(master.identityPublicKey()), password });
    const keepClient = store.isUnlocked(ctx.address) && (await store.deviceIdOf(ctx.address)) === ctx.deviceId ? await store.getSecret(CLIENT_STATE) : null;
    await store.saveMaster(ctx.address, ctx.deviceId, bytes);
    if (keepClient) {
      await store.putSecret(CLIENT_STATE, keepClient);
      keepClient.fill(0);
    }
  } finally {
    bytes.fill(0);
    master.free();
  }
  await putRecovery(ctx, recovery);
  await ensureDevice(ctx);
}

/** Logout: delete the account's local crypto data and lock. */
export async function wipeLocal(store: KeyStore, address: string): Promise<void> {
  try {
    await store.wipe(address);
  } catch {
    store.lock();
  }
}
