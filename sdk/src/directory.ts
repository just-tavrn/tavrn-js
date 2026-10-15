// SPDX-License-Identifier: Apache-2.0
/**
 * Peer directory helpers (FEDERATION.md §7.3): verification of signed room listings.
 *
 * Every room in `GET /directory/rooms` carries a listing JWT that its hosting node signed with one of
 * the keys of its own discovery document (`typ = listing`, `aud = tavrn-directory`, `sub` = room id,
 * 48 hours). A client that verifies it knows the hosting node vouches for the name, description and
 * member count, whichever node relayed the entry. Clients prefer the signed values.
 */
import type { DirectoryRoom, PublicKeyInfo } from "./generated/types.gen";
import { decodeJsonPart as decodeJson } from "./jwt";
import { b64urlDecode } from "./webauthn";

export const LISTING_AUDIENCE = "tavrn-directory";
export const LISTING_TYPE = "listing";
/** Longest validity a listing may claim (48 hours plus a little clock slack). */
export const LISTING_MAX_TTL_SECS = 48 * 3600 + 600;
/** Clock skew tolerated for `iat` (as between nodes, §2.1). */
export const LISTING_SKEW_SECS = 300;

export interface ListingClaims {
  iss: string;
  sub: string;
  aud: string;
  typ: string;
  iat: number;
  exp: number;
  jti?: string;
  name: string;
  description: string;
  icon_sha256?: string | null;
  member_count: number;
}

export type ListingCheck =
  | { status: "valid"; claims: ListingClaims }
  | { status: "invalid"; reason: string }
  /** This runtime cannot verify Ed25519 signatures (no WebCrypto Ed25519). */
  | { status: "unsupported" };

export interface VerifyOptions {
  /** Current time in seconds (tests). */
  now?: number;
  /** WebCrypto implementation (tests); defaults to `globalThis.crypto.subtle`. */
  subtle?: SubtleCrypto;
}


function decodeBytes(part: string): Uint8Array<ArrayBuffer> | null {
  try {
    return b64urlDecode(part);
  } catch {
    return null;
  }
}

/**
 * Verifies the listing of room `roomId` on node `node` against `keys` (the `keys` of that node's own
 * discovery document): signature (Ed25519 via WebCrypto), signer, room, audience, type and lifetime.
 */
export async function verifyListing(listing: string, expected: { node: string; roomId: string }, keys: PublicKeyInfo[], opts: VerifyOptions = {}): Promise<ListingCheck> {
  const invalid = (reason: string): ListingCheck => ({ status: "invalid", reason });
  if (typeof listing !== "string" || listing.length > 4096) return invalid("format");
  const parts = listing.split(".");
  if (parts.length !== 3) return invalid("format");
  const [h, p, s] = parts as [string, string, string];
  const header = decodeJson(h);
  const claims = decodeJson(p) as Partial<ListingClaims> | null;
  const signature = decodeBytes(s);
  if (!header || !claims || !signature || signature.length !== 64) return invalid("format");
  if (header.alg !== "EdDSA" || header.typ !== "JWT" || typeof header.kid !== "string") return invalid("header");
  const key = keys.find((k) => k.kid === header.kid && k.alg === "EdDSA" && k.crv === "Ed25519");
  const raw = key ? decodeBytes(key.x) : null;
  if (!raw || raw.length !== 32) return invalid("unknown key");

  const subtle = opts.subtle ?? globalThis.crypto?.subtle;
  if (!subtle) return { status: "unsupported" };
  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return { status: "unsupported" };
  }
  let ok = false;
  try {
    ok = await subtle.verify({ name: "Ed25519" }, cryptoKey, signature, new TextEncoder().encode(`${h}.${p}`));
  } catch {
    ok = false;
  }
  if (!ok) return invalid("signature");

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (claims.iss !== expected.node) return invalid("signer");
  if (claims.sub !== expected.roomId) return invalid("room");
  if (claims.aud !== LISTING_AUDIENCE || claims.typ !== LISTING_TYPE) return invalid("audience");
  if (typeof claims.iat !== "number" || typeof claims.exp !== "number") return invalid("lifetime");
  if (claims.exp <= now) return invalid("expired");
  if (claims.iat > now + LISTING_SKEW_SECS || claims.exp - claims.iat > LISTING_MAX_TTL_SECS) return invalid("lifetime");
  if (typeof claims.name !== "string" || typeof claims.description !== "string" || typeof claims.member_count !== "number") return invalid("claims");
  return { status: "valid", claims: claims as ListingClaims };
}

/** A directory room after verification: the signed values replace the relayed ones. */
export interface VerifiedRoom extends DirectoryRoom {
  /** `valid`, or `unsupported` when this runtime cannot check Ed25519 (the entry is then shown as is). */
  verification: "valid" | "unsupported";
}

/**
 * Verifies every room of a directory page. Rooms whose listing fails (or whose node's keys cannot be
 * loaded) are dropped; `keysOf` loads the keys of a hosting node from that node's own discovery
 * document and is called once per node.
 */
export async function verifyDirectoryRooms(rooms: DirectoryRoom[], keysOf: (node: string) => Promise<PublicKeyInfo[]>, opts: VerifyOptions = {}): Promise<VerifiedRoom[]> {
  const keys = new Map<string, Promise<PublicKeyInfo[] | null>>();
  const keysFor = (node: string) => {
    let hit = keys.get(node);
    if (!hit) {
      hit = keysOf(node).catch(() => null);
      keys.set(node, hit);
    }
    return hit;
  };
  const checked = await Promise.all(
    rooms.map(async (room): Promise<VerifiedRoom | null> => {
      const nodeKeys = await keysFor(room.node);
      if (!nodeKeys) return null;
      const check = await verifyListing(room.listing, { node: room.node, roomId: room.room_id }, nodeKeys, opts);
      if (check.status === "invalid") return null;
      if (check.status === "unsupported") return { ...room, verification: "unsupported" };
      const c = check.claims;
      return { ...room, name: c.name, description: c.description, member_count: c.member_count, verification: "valid" };
    }),
  );
  return checked.filter((r): r is VerifiedRoom => r !== null);
}
