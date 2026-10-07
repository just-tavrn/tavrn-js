// SPDX-License-Identifier: MPL-2.0
/**
 * The account's current identity key and its rotation with continuity (ENCRYPTION.md §2.1, §9a). Generation 0 is
 * the key derived from the master secret; after a rotation the current key is a random one, kept in the key store
 * as {@link IDENTITY_SEED} and on the home node wrapped under the master secret (`identity_blob`). Every device of
 * the account follows the published key when the keys document's continuity chain leads to it from the derived key.
 */
import { IdentityKey, continuityReaches, signContinuity, unwrapIdentityKey, verifyDeviceAttestation, wrapIdentityKey } from "@tavrn/crypto";
import { TavrnApiError, b64urlDecode, b64urlEncode, type TavrnApi } from "@tavrn/sdk";
import { E2eeError } from "./errors";
import { withMasterSecret, type KeyStore } from "./keystore";
import { ensureCrypto } from "./wasm";

/** Name of the rotated identity key (32-byte seed) in the key store; absent at generation 0. */
export const IDENTITY_SEED = "identity-seed";

/** A continuity statement as the keys document carries it (base64url keys and signatures). */
export interface ContinuityStatement {
  old_key: string;
  new_key: string;
  at: string;
  sig_old: string;
  sig_new: string;
}

/** The parts of a keys document (`GET /users/{username}/keys`) the identity checks use. */
export interface IdentityDocument {
  identity_public_key?: string | null;
  continuity?: ContinuityStatement[] | null;
}

/** Is `to` reachable from `from` through valid, consecutive statements of `chain`? `true` for `from === to`. */
export function chainReaches(chain: readonly ContinuityStatement[] | null | undefined, from: string, to: string): boolean {
  if (from === to) return true;
  if (!chain?.length) return false;
  return continuityReaches(JSON.stringify(chain), from, to);
}

/**
 * The keys that lead to `current` through valid statements of `chain`, `current` included: attestations made under
 * them (retired devices, ENCRYPTION.md §3.3) stay trustworthy after a rotation.
 */
export function chainKeys(chain: readonly ContinuityStatement[] | null | undefined, current: string): Set<string> {
  const out = new Set([current]);
  for (const s of chain ?? []) if (!out.has(s.old_key) && chainReaches(chain, s.old_key, current)) out.add(s.old_key);
  return out;
}

/** RFC 3339 time without fractions (the form the node checks against its clock). */
export function rfc3339(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Runs `fn` with the store's current identity key (the rotated one if present, else the derived one), freed afterwards. */
export async function withIdentityKey<T>(store: KeyStore, fn: (key: IdentityKey) => T): Promise<T> {
  await ensureCrypto();
  const seed = await store.getSecret(IDENTITY_SEED);
  let key: IdentityKey;
  if (seed) {
    try {
      key = IdentityKey.fromBytes(seed);
    } finally {
      seed.fill(0);
    }
  } else {
    key = withMasterSecret(store, (m) => IdentityKey.fromMaster(m));
  }
  try {
    return fn(key);
  } finally {
    key.free();
  }
}

/** The current identity public key of the open account (base64url). */
export function ownIdentityPublicKey(store: KeyStore): Promise<string> {
  return withIdentityKey(store, (k) => b64urlEncode(k.publicKey()));
}

/** The identity public key derived from the master secret (generation 0, base64url). */
export function derivedIdentityKey(store: KeyStore): string {
  return withMasterSecret(store, (m) => b64urlEncode(m.identityPublicKey()));
}

/**
 * The rotated identity key (seed) that a master secret leads to for the published key, or null at generation 0
 * (ENCRYPTION.md §2.4 client rules): the derived key equals the published key, or the chain reaches the published key
 * from the derived one and the blob unwraps with the master secret to exactly that key. Anything else is
 * `identity_mismatch`. The caller zeroes the returned seed.
 */
export async function resolveIdentity(
  api: Pick<TavrnApi, "keys">,
  doc: IdentityDocument,
  derived: string,
  unwrap: (blob: Uint8Array) => IdentityKey,
): Promise<Uint8Array | null> {
  const published = doc.identity_public_key ?? null;
  if (!published || published === derived) return null;
  if (!chainReaches(doc.continuity, derived, published)) throw new E2eeError("identity_mismatch");
  let blob: string;
  try {
    blob = (await api.keys.identityBlob()).identity_blob;
  } catch (e) {
    if (e instanceof TavrnApiError && e.status === 404) throw new E2eeError("identity_mismatch");
    throw e;
  }
  let key: IdentityKey;
  try {
    key = unwrap(b64urlDecode(blob));
  } catch {
    throw new E2eeError("identity_mismatch");
  }
  try {
    if (b64urlEncode(key.publicKey()) !== published) throw new E2eeError("identity_mismatch");
    return key.toBytes();
  } finally {
    key.free();
  }
}

/**
 * Brings the open store's identity key in line with the published one (another device rotated, ENCRYPTION.md §9a):
 * `current` when nothing changed, `rotated` when the new key was taken over from the blob. Throws
 * {@link E2eeError} `identity_mismatch` when the published key is not reachable from this master secret.
 */
export async function syncIdentity(
  api: Pick<TavrnApi, "keys">,
  store: KeyStore,
  username: string,
  address: string,
  doc?: IdentityDocument,
): Promise<"current" | "rotated"> {
  await ensureCrypto();
  if (!store.isUnlocked()) throw new E2eeError("locked");
  const keys = doc ?? (await api.keys.get(username));
  const published = keys.identity_public_key ?? null;
  if (!published || published === (await ownIdentityPublicKey(store))) return "current";
  const seed = await resolveIdentity(api, keys, derivedIdentityKey(store), (blob) => withMasterSecret(store, (m) => unwrapIdentityKey(m, blob, address)));
  if (!seed) {
    await store.deleteSecret(IDENTITY_SEED);
    return "rotated";
  }
  try {
    await store.putSecret(IDENTITY_SEED, seed);
  } finally {
    seed.fill(0);
  }
  return "rotated";
}

/** What a rotation needs from the API. */
export interface RotationContext {
  api: Pick<TavrnApi, "keys">;
  username: string;
  address: string;
  store: KeyStore;
  /** Clock (tests). */
  now?: () => number;
}

/**
 * Rotates the identity key with continuity (ENCRYPTION.md §9a): new random key, statement signed by the current and
 * the new key, the new key wrapped under the master secret, every device of the keys document attested again. The
 * node asks for a reauth token (`auth.reauth_required`; the web client confirms and repeats). Refuses with
 * `rotation_devices` when a listed device does not verify under the current key (the document and the local state
 * disagree) and with `identity_mismatch` when this device is not on the published key.
 */
export async function rotateIdentity(ctx: RotationContext): Promise<{ identity_public_key: string; identity_generation: number }> {
  await ensureCrypto();
  const { store, address } = ctx;
  if (!store.isUnlocked()) throw new E2eeError("locked");
  const doc = await ctx.api.keys.get(ctx.username);
  const current = await ownIdentityPublicKey(store);
  if (doc.identity_public_key !== current) throw new E2eeError("identity_mismatch");
  const currentBytes = b64urlDecode(current);
  const devices = doc.devices.map((d) => {
    const key = b64urlDecode(d.device_public_key);
    if (!verifyDeviceAttestation(address, d.device_id, key, b64urlDecode(d.identity_signature), currentBytes)) throw new E2eeError("rotation_devices");
    return { id: d.device_id, key };
  });
  const fresh = IdentityKey.generate();
  try {
    const at = rfc3339(ctx.now?.() ?? Date.now());
    const continuity = JSON.parse(await withIdentityKey(store, (old) => signContinuity(old, fresh, at))) as ContinuityStatement;
    const blob = withMasterSecret(store, (m) => wrapIdentityKey(m, fresh, address));
    const attestations = devices.map((d) => ({ device_id: d.id, identity_signature: b64urlEncode(fresh.attestDevice(address, d.id, d.key)) }));
    const res = await ctx.api.keys.rotateIdentity({
      new_identity_public_key: b64urlEncode(fresh.publicKey()),
      continuity,
      identity_blob: b64urlEncode(blob),
      attestations,
    });
    // If this fails, the next start takes the key from the blob (syncIdentity).
    const seed = fresh.toBytes();
    try {
      await store.putSecret(IDENTITY_SEED, seed);
    } finally {
      seed.fill(0);
    }
    return res;
  } finally {
    fresh.free();
  }
}
