// SPDX-License-Identifier: Apache-2.0
/**
 * Verification of hook requests (protocol/APPLICATIONS.md §6.3): every request a node sends to an application's URL
 * (event subscriptions, the interactions URL) carries `Tavrn-Signature: <hook token>`, an EdDSA JWT signed with one
 * of the keys of the node's `/.well-known/tavrn`. An application MUST verify it before trusting the body:
 *
 * - the signature with a key of the node's discovery document (cached at most one hour, refetched once when the
 *   token names an unknown `kid`);
 * - `typ = "hook"`, `aud = "app:<application id>"`, `iss = sub` = the node's domain;
 * - `iat` within ±5 minutes, `exp` in the future, `exp − iat ≤ 300`;
 * - `htu` equal to the configured URL and `body_sha256` equal to the SHA-256 of the exact body bytes, checked
 *   **before** the body is parsed;
 * - `jti` unseen until `exp + 5 minutes` (replays are refused).
 *
 * ```ts
 * const verifier = new HookVerifier({ node: "node.example", applicationId: "01J…", url: "https://bot.example/hook" });
 * const result = await verifier.verify({ headers: req.headers, body: rawBody });
 * if (!result.ok) return new Response(null, { status: 401 });
 * if (result.event.type === "ping") return Response.json({ challenge: result.event.challenge });
 * ```
 */
import { DISCOVERY_TIMEOUT_MS, MAX_DISCOVERY_BYTES } from "./federation";
import type { PublicKeyInfo } from "./generated/types.gen";
import { deadline, discard, readText } from "./http";
import { b64urlDecode, b64urlEncode } from "./webauthn";

export const HOOK_TYPE = "hook";
/** Tolerated clock skew for `iat` (seconds). */
export const HOOK_SKEW_SECS = 300;
/** Longest lifetime of a hook token (seconds). */
export const HOOK_MAX_TTL_SECS = 300;
/** Spent `jti`s are remembered until `exp` plus this grace (seconds). */
export const HOOK_REPLAY_GRACE_SECS = 300;
/** Keys of the node are cached at most this long (seconds). */
export const HOOK_KEY_CACHE_SECS = 3600;
/** At most one refetch of the keys for an unknown `kid` per this many seconds. */
export const HOOK_KEY_REFETCH_SECS = 10;

export type HookFailure =
  | "missing_signature"
  | "format"
  | "header"
  | "keys_unavailable"
  | "unknown_key"
  | "signature"
  | "type"
  | "audience"
  | "issuer"
  | "time"
  | "expired"
  | "url"
  | "body"
  | "replay"
  | "body_invalid"
  | "unsupported";

/** The body of a hook request: an event (§6.2), a ping (§6.3) or an invocation (§5.6). */
export interface HookEvent {
  id?: string;
  type: string;
  at?: string;
  application_id?: string;
  room_id?: string;
  data?: unknown;
  challenge?: string;
  [key: string]: unknown;
}

export interface HookClaims {
  iss: string;
  sub: string;
  aud: string;
  typ: string;
  iat: number;
  exp: number;
  jti: string;
  htu: string;
  body_sha256: string;
}

export type HookVerification = { ok: true; event: HookEvent; claims: HookClaims } | { ok: false; reason: HookFailure };

/** The parts of an incoming HTTP request the verifier needs. */
export interface HookRequest {
  /** `Headers`, or a plain object as Node.js frameworks give it (names in any case). */
  headers: Headers | Record<string, string | string[] | undefined>;
  /** The exact body bytes as received (a string is taken as UTF-8). */
  body: Uint8Array | ArrayBuffer | string;
}

export interface HookVerifierOptions {
  /** The node: its domain (`node.example`, fetched over https) or an origin (`http://127.0.0.1:8080`, development). */
  node: string;
  /** The application's id (the token's audience is `app:<id>`). */
  applicationId: string;
  /** The URL configured at the node, exactly as configured (compared with `htu`). */
  url: string;
  /** Key cache lifetime in seconds (at most and by default one hour). */
  keyCacheSecs?: number;
  /** `fetch` implementation (tests). */
  fetch?: typeof fetch;
  /** Deadline of the key fetch in milliseconds (default 15 s). */
  timeoutMs?: number;
  /** Current time in seconds (tests). */
  now?: () => number;
  /** WebCrypto implementation (tests); defaults to `globalThis.crypto.subtle`. */
  subtle?: SubtleCrypto;
}

interface KeySet {
  domain: string;
  keys: PublicKeyInfo[];
  fetchedAt: number;
}

function header(headers: HookRequest["headers"], name: string): string | null {
  if (typeof (headers as Headers).get === "function") return (headers as Headers).get(name);
  const record = headers as Record<string, string | string[] | undefined>;
  const key = Object.keys(record).find((k) => k.toLowerCase() === name);
  const value = key === undefined ? undefined : record[key];
  return Array.isArray(value) ? (value[0] ?? null) : (value ?? null);
}

function bytesOf(body: HookRequest["body"]): Uint8Array<ArrayBuffer> {
  if (typeof body === "string") return new TextEncoder().encode(body) as Uint8Array<ArrayBuffer>;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  return new Uint8Array(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer);
}


/** UTF-8 bytes → string, without TextDecoder (whose typed-array realm checks differ between runtimes). */
function utf8(bytes: Uint8Array): string {
  let escaped = "";
  for (const b of bytes) escaped += `%${b.toString(16).padStart(2, "0")}`;
  return decodeURIComponent(escaped);
}

function decodeJson(part: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(utf8(b64urlDecode(part)));
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * Verifies hook requests of one node for one application. Keep one instance per application: it caches the node's
 * keys and remembers spent token ids.
 */
export class HookVerifier {
  private keySet: KeySet | null = null;
  private lastRefetch = -Infinity;
  private readonly seen = new Map<string, number>();
  private readonly origin: string;

  constructor(private readonly opts: HookVerifierOptions) {
    this.origin = opts.node.includes("://") ? opts.node.replace(/\/+$/, "") : `https://${opts.node}`;
  }

  private now(): number {
    return this.opts.now ? this.opts.now() : Math.floor(Date.now() / 1000);
  }

  private async fetchKeys(): Promise<KeySet | null> {
    const doFetch = this.opts.fetch ?? fetch;
    const d = deadline(this.opts.timeoutMs ?? DISCOVERY_TIMEOUT_MS);
    try {
      const resp = await doFetch(`${this.origin}/.well-known/tavrn`, { headers: { Accept: "application/json" }, redirect: "error", signal: d.signal });
      if (!resp.ok) {
        discard(resp);
        return null;
      }
      const doc = JSON.parse(await readText(resp, MAX_DISCOVERY_BYTES)) as { domain?: unknown; keys?: unknown };
      if (typeof doc.domain !== "string" || !Array.isArray(doc.keys)) return null;
      const keys = (doc.keys as PublicKeyInfo[]).filter((k) => k && typeof k.kid === "string" && typeof k.x === "string");
      return { domain: doc.domain, keys, fetchedAt: this.now() };
    } catch {
      return null;
    } finally {
      d.done();
    }
  }

  /** The node's keys from the cache (at most `keyCacheSecs` old) or freshly fetched. */
  private async keys(forceRefetch: boolean): Promise<KeySet | null> {
    const ttl = Math.min(this.opts.keyCacheSecs ?? HOOK_KEY_CACHE_SECS, HOOK_KEY_CACHE_SECS);
    const now = this.now();
    const fresh = this.keySet && now - this.keySet.fetchedAt < ttl;
    if (fresh && !forceRefetch) return this.keySet;
    if (forceRefetch && now - this.lastRefetch < HOOK_KEY_REFETCH_SECS) return this.keySet;
    if (forceRefetch) this.lastRefetch = now;
    const next = await this.fetchKeys();
    if (next) this.keySet = next;
    else if (!fresh) this.keySet = null;
    return this.keySet;
  }

  private forgetSpent(now: number) {
    for (const [jti, until] of this.seen) if (until <= now) this.seen.delete(jti);
  }

  /** Verifies a request; the event is returned only when every check passed. */
  async verify(request: HookRequest): Promise<HookVerification> {
    const fail = (reason: HookFailure): HookVerification => ({ ok: false, reason });
    const token = header(request.headers, "tavrn-signature");
    if (!token) return fail("missing_signature");
    if (token.length > 8192) return fail("format");
    const parts = token.split(".");
    if (parts.length !== 3) return fail("format");
    const [h, p, s] = parts as [string, string, string];
    const head = decodeJson(h);
    const claims = decodeJson(p) as Partial<HookClaims> | null;
    let signature: Uint8Array<ArrayBuffer>;
    try {
      signature = b64urlDecode(s);
    } catch {
      return fail("format");
    }
    if (!head || !claims || signature.length !== 64) return fail("format");
    if (head.alg !== "EdDSA" || head.typ !== "JWT" || typeof head.kid !== "string") return fail("header");

    const subtle = this.opts.subtle ?? globalThis.crypto?.subtle;
    if (!subtle) return fail("unsupported");
    let keySet = await this.keys(false);
    let key = keySet?.keys.find((k) => k.kid === head.kid);
    if (!key) {
      // One refetch: the node may have rotated its key since the cache was filled.
      keySet = await this.keys(true);
      key = keySet?.keys.find((k) => k.kid === head.kid);
    }
    if (!keySet) return fail("keys_unavailable");
    if (!key || key.alg !== "EdDSA" || key.crv !== "Ed25519") return fail("unknown_key");
    let ok = false;
    try {
      const raw = b64urlDecode(key.x);
      if (raw.length !== 32) return fail("unknown_key");
      const cryptoKey = await subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
      ok = await subtle.verify({ name: "Ed25519" }, cryptoKey, signature, new TextEncoder().encode(`${h}.${p}`));
    } catch {
      return fail("unsupported");
    }
    if (!ok) return fail("signature");

    const now = this.now();
    if (claims.typ !== HOOK_TYPE) return fail("type");
    if (claims.aud !== `app:${this.opts.applicationId}`) return fail("audience");
    if (claims.iss !== keySet.domain || claims.sub !== keySet.domain) return fail("issuer");
    if (typeof claims.iat !== "number" || typeof claims.exp !== "number") return fail("time");
    if (Math.abs(now - claims.iat) > HOOK_SKEW_SECS || claims.exp - claims.iat > HOOK_MAX_TTL_SECS) return fail("time");
    if (claims.exp <= now) return fail("expired");
    if (claims.htu !== this.opts.url) return fail("url");
    // The body hash is checked before the body is parsed.
    const body = bytesOf(request.body);
    const digest = b64urlEncode(await subtle.digest("SHA-256", body));
    if (typeof claims.body_sha256 !== "string" || claims.body_sha256 !== digest) return fail("body");
    if (typeof claims.jti !== "string" || !claims.jti) return fail("format");
    this.forgetSpent(now);
    if (this.seen.has(claims.jti)) return fail("replay");
    this.seen.set(claims.jti, claims.exp + HOOK_REPLAY_GRACE_SECS);

    let event: unknown;
    try {
      event = JSON.parse(utf8(body));
    } catch {
      return fail("body_invalid");
    }
    if (!event || typeof event !== "object" || Array.isArray(event) || typeof (event as HookEvent).type !== "string") return fail("body_invalid");
    return { ok: true, event: event as HookEvent, claims: claims as HookClaims };
  }
}

const verifiers = new Map<string, HookVerifier>();

/**
 * Verifies one hook request with a verifier shared per node, application and URL (so the key cache and the replay
 * window persist between calls). See {@link HookVerifier} for the checks.
 */
export function verifyHookRequest(request: HookRequest, opts: HookVerifierOptions): Promise<HookVerification> {
  const key = `${opts.node}\n${opts.applicationId}\n${opts.url}`;
  let verifier = verifiers.get(key);
  if (!verifier) {
    verifier = new HookVerifier(opts);
    verifiers.set(key, verifier);
  }
  return verifier.verify(request);
}
