// SPDX-License-Identifier: MPL-2.0
/**
 * The trust record of an account (ENCRYPTION.md §7 "Trust record"): the pinned identity keys of other users (§3.3),
 * the verified contacts (FEDERATION.md §10.2) and the account's own devices this account attested (device id → device
 * key, §4.7). It is kept in the local store and, encrypted under the backup key, as a backup blob on the home node, so
 * that it survives a sign-out and reaches every device of the account: a contact's key that changed while the user
 * was signed out still raises the "security key changed" warning, and only a device key the account attested itself
 * is ever attested again as retired.
 *
 * ```text
 * blob      = 0x01 || nonce(12) || AES-256-GCM(backup_key, nonce, aad, plaintext)
 * aad       = "tavrn trust v1" || 0x00 || account address
 * plaintext = {"v":1,"pins":{…},"verified":{…},"devices":{"<device id>":"<base64url device key>"}}
 * ```
 *
 * Path: `PUT /users/me/backups/<home domain>/00000000000000000000000000` (the ULID of time 0, never a conversation).
 * The node cannot read or forge it; at worst it serves an older blob or none (entries merge, nothing is replaced).
 */
import { b64urlDecode } from "@tavrn/sdk";
import type { Pin, VerifiedContact } from "./mls";

/** The conversation ULID under which the trust record is stored as a backup (time 0, no conversation has it). */
export const TRUST_BACKUP_ULID = "00000000000000000000000000";

export interface TrustRecord {
  pins: Record<string, Pin>;
  verified: Record<string, VerifiedContact>;
  /** Own devices attested by this account: device id → base64url device key. */
  devices: Record<string, string>;
}

function aad(account: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`tavrn trust v1\u0000${account}`);
}

async function aesKey(backupKey: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey("raw", backupKey as Uint8Array<ArrayBuffer>, { name: "AES-GCM" }, false, [usage]);
}

/** Encrypts a trust record of `account` under the backup key. */
export async function sealTrust(backupKey: Uint8Array, account: string, record: TrustRecord): Promise<Uint8Array> {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify({ v: 1, pins: record.pins, verified: record.verified, devices: record.devices }));
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad(account) }, await aesKey(backupKey, "encrypt"), plain));
  const out = new Uint8Array(1 + 12 + ct.length);
  out[0] = 1;
  out.set(nonce, 1);
  out.set(ct, 13);
  return out;
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** Decrypts and checks a trust record of `account`; null when it does not open or is malformed. */
export async function openTrust(backupKey: Uint8Array, account: string, blob: Uint8Array): Promise<TrustRecord | null> {
  if (blob.length < 1 + 12 + 16 || blob[0] !== 1) return null;
  let plain: ArrayBuffer;
  try {
    plain = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: blob.slice(1, 13), additionalData: aad(account) },
      await aesKey(backupKey, "decrypt"),
      blob.slice(13),
    );
  } catch {
    return null;
  }
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder().decode(plain));
  } catch {
    return null;
  }
  if (!isObject(v) || v.v !== 1 || !isObject(v.pins) || !isObject(v.verified) || !isObject(v.devices)) return null;
  const pins: Record<string, Pin> = {};
  for (const [a, p] of Object.entries(v.pins)) {
    if (!isObject(p) || typeof p.key !== "string") continue;
    pins[a] = { key: p.key, ...(p.changed === true ? { changed: true } : {}), ...(p.rotated === true ? { rotated: true } : {}) };
  }
  const verified: Record<string, VerifiedContact> = {};
  for (const [a, c] of Object.entries(v.verified)) {
    if (!isObject(c) || c.address !== a || typeof c.identity_public_key !== "string" || typeof c.verified_at !== "string") continue;
    if (c.method !== "qr" && c.method !== "numeric") continue;
    verified[a] = {
      address: a,
      identity_public_key: c.identity_public_key,
      verified_at: c.verified_at,
      method: c.method,
      ...(typeof c.rotated_to === "string" ? { rotated_to: c.rotated_to } : {}),
      ...(c.refresh_dismissed === true ? { refresh_dismissed: true } : {}),
    };
  }
  const devices: Record<string, string> = {};
  for (const [d, k] of Object.entries(v.devices)) {
    if (typeof k !== "string") continue;
    try {
      if (b64urlDecode(k).length === 32) devices[d] = k;
    } catch {
      /* malformed entry */
    }
  }
  return { pins, verified, devices };
}

/**
 * Adds what `from` has and `into` lacks (in place); entries `into` has stay as they are. Verified contacts named in
 * `removed` (removed on this device, not uploaded yet) are not taken over. True when `into` changed.
 */
export function mergeTrust(into: TrustRecord, from: TrustRecord, removed: ReadonlySet<string> = new Set()): boolean {
  let changed = false;
  for (const [a, p] of Object.entries(from.pins)) {
    if (!into.pins[a]) {
      into.pins[a] = p;
      changed = true;
    }
  }
  for (const [a, c] of Object.entries(from.verified)) {
    if (!into.verified[a] && !removed.has(a)) {
      into.verified[a] = c;
      changed = true;
    }
  }
  for (const [d, k] of Object.entries(from.devices)) {
    if (!into.devices[d]) {
      into.devices[d] = k;
      changed = true;
    }
  }
  return changed;
}
