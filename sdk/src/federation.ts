// SPDX-License-Identifier: Apache-2.0
/**
 * Client helpers for federation (FEDERATION.md): user addresses, node discovery for clients (§1.4,
 * §8), the base URLs of a node and PKCE for the connect flow (§8, RFC 7636).
 */
import { TavrnApiError } from "./errors";
import { deadline, readText } from "./http";
import type { PeerResolution, WellKnown } from "./generated/types.gen";
import { b64urlEncode } from "./webauthn";

/** Capability every federating node announces (§12). */
export const FEDERATION_CAPABILITY = "federation.v1";
/** Largest discovery document a client accepts (§1.3). */
export const MAX_DISCOVERY_BYTES = 64 * 1024;
/** Default deadline of a discovery request (the document of another domain). */
export const DISCOVERY_TIMEOUT_MS = 15_000;

const USERNAME = /^[a-z0-9][a-z0-9_.-]{1,31}$/;
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** A node domain (§1.3 rule 1): lowercase labels, at least one dot, no port, no IP literal. */
export function isNodeDomain(s: string): boolean {
  if (!s || s.length > 253 || !s.includes(".")) return false;
  const labels = s.split(".");
  if (!labels.every((l) => LABEL.test(l))) return false;
  return !/^[0-9]+$/.test(labels[labels.length - 1]!);
}

/** `alice@home.example` → `{ username, domain }` (trimmed, lowercased), or null. */
export function parseAddress(input: string): { username: string; domain: string } | null {
  const s = input.trim().toLowerCase();
  const at = s.lastIndexOf("@");
  if (at <= 0) return null;
  const username = s.slice(0, at);
  const domain = s.slice(at + 1);
  if (!USERNAME.test(username) || !isNodeDomain(domain)) return null;
  return { username, domain };
}

/**
 * What a user types to sign in with an account of another node: an address (`alice@tavrn.org`) or just the
 * identity domain (`tavrn.org`, the username follows later). Null for anything else.
 */
export function parseAccountInput(input: string): { username: string | null; domain: string } | null {
  const address = parseAddress(input);
  if (address) return address;
  const domain = input.trim().toLowerCase().replace(/^@/, "");
  return isNodeDomain(domain) ? { username: null, domain } : null;
}

/** The URLs a client needs to talk to a node, taken from its discovery document. */
export interface NodeEndpoints {
  domain: string;
  /** Base URL for {@link TavrnApi} (the document's `api` without `/api/v1`). */
  base: string;
  /** WebSocket URL. */
  ws: string;
  /** Origin of the node's web client (`/connect` lives there). */
  web: string;
}

function parsedUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/**
 * Checks a discovery document fetched for `domain` the way §1.4 and §8 ask clients to: protocol `1`,
 * `domain` equal to the requested one, `federation.v1` announced, and absolute API, WebSocket and web client
 * URLs without credentials. The URLs may point to another host than `domain`: the identity domain may
 * delegate to the host that serves the node (design note 4.2c, `tavrn.org` → `app.tavrn.org`), the document is
 * the domain's own statement. `http:`/`ws:` URLs are only accepted with `allowInsecure` (development).
 */
export function nodeEndpoints(doc: WellKnown, domain: string, opts: { allowInsecure?: boolean } = {}): NodeEndpoints {
  if (!doc || typeof doc !== "object") throw invalidNode("no discovery document");
  if (doc.tavrn !== 1) throw invalidNode("unknown protocol version");
  if (doc.domain !== domain) throw invalidNode("domain mismatch");
  if (!Array.isArray(doc.capabilities) || !doc.capabilities.includes(FEDERATION_CAPABILITY)) throw invalidNode("node does not federate");
  return checkedEndpoints(doc, domain, opts);
}

/**
 * Endpoints from the resolution of the node this client was loaded from (`GET /federation/resolve/{domain}`,
 * which also follows `_tavrn._tcp` SRV records), checked like a discovery document: the resolved domain must
 * be `domain`, the URLs absolute without credentials, `http:`/`ws:` only with `allowInsecure`.
 */
export function resolutionEndpoints(res: PeerResolution, domain: string, opts: { allowInsecure?: boolean } = {}): NodeEndpoints {
  if (!res || typeof res !== "object") throw invalidNode("no resolution");
  if (res.domain !== domain) throw invalidNode("domain mismatch");
  return checkedEndpoints(res, domain, opts);
}

function invalidNode(detail: string): TavrnApiError {
  return new TavrnApiError({ type: "about:blank", title: "Invalid node", status: 0, detail, code: "federation.peer_invalid" });
}

function checkedEndpoints(doc: { api?: unknown; ws?: unknown; web?: unknown }, domain: string, opts: { allowInsecure?: boolean }): NodeEndpoints {
  if (typeof doc.api !== "string" || !doc.api.endsWith("/api/v1")) throw invalidNode("api missing");
  if (typeof doc.ws !== "string") throw invalidNode("ws missing");
  const web = typeof doc.web === "string" && doc.web ? doc.web : `https://${domain}`;
  const http = opts.allowInsecure ? ["https:", "http:"] : ["https:"];
  const ws = opts.allowInsecure ? ["wss:", "ws:"] : ["wss:"];
  for (const [url, schemes] of [[doc.api, http], [web, http], [doc.ws, ws]] as const) {
    const u = parsedUrl(url);
    if (!u || !u.hostname) throw invalidNode("invalid URL");
    if (!schemes.includes(u.protocol)) throw invalidNode("insecure URL");
    if (u.username || u.password || u.search || u.hash) throw invalidNode("invalid URL");
  }
  return { domain, base: doc.api.slice(0, -"/api/v1".length), ws: doc.ws, web: web.replace(/\/+$/, "") };
}

/** Endpoints of a node that has no discovery document (404): everything on `https://<domain>`. */
export function fallbackEndpoints(domain: string): NodeEndpoints {
  return { domain, base: `https://${domain}`, ws: `wss://${domain}/api/v1/ws`, web: `https://${domain}` };
}

type WellKnownFetch = { kind: "doc"; doc: WellKnown } | { kind: "missing" } | { kind: "status"; status: number } | { kind: "unreachable" };

/** Deadline and abort signal of discovery requests. */
export interface DiscoveryTimeouts {
  /** Deadline of the request in milliseconds (default {@link DISCOVERY_TIMEOUT_MS}; 0 = none). */
  timeoutMs?: number;
  signal?: AbortSignal;
}

/**
 * `https://<domain>/.well-known/tavrn` straight from the browser (CORS-open), classified. The body is read up to
 * {@link MAX_DISCOVERY_BYTES} (a larger one counts as unreadable) within the deadline.
 */
async function fetchWellKnown(domain: string, doFetch: typeof fetch, opts: DiscoveryTimeouts = {}): Promise<WellKnownFetch> {
  const d = deadline(opts.timeoutMs ?? DISCOVERY_TIMEOUT_MS, opts.signal);
  try {
    let resp: Response;
    try {
      resp = await doFetch(`https://${domain}/.well-known/tavrn`, { headers: { Accept: "application/json" }, credentials: "omit", redirect: "error", signal: d.signal });
    } catch {
      // CORS, TLS, DNS, a timeout or a development peer: the browser cannot tell which.
      return { kind: "unreachable" };
    }
    if (resp.status === 404 || !resp.ok) {
      void resp.body?.cancel().catch(() => undefined);
      return resp.status === 404 ? { kind: "missing" } : { kind: "status", status: resp.status };
    }
    try {
      return { kind: "doc", doc: JSON.parse(await readText(resp, MAX_DISCOVERY_BYTES)) as WellKnown };
    } catch {
      /* unreadable, too large or too slow: like unreachable */
    }
    return { kind: "unreachable" };
  } finally {
    d.done();
  }
}

function unreachable(domain: string): TavrnApiError {
  return new TavrnApiError({ type: "about:blank", title: "Node unreachable", status: 0, detail: domain, code: "federation.peer_unreachable" });
}

/**
 * Discovery document of `domain`: first straight from `https://<domain>/.well-known/tavrn` (CORS-open),
 * otherwise through `proxy` (the node the client was loaded from, `GET /federation/peer/{domain}`).
 */
export async function discoverNode(domain: string, opts: DiscoveryTimeouts & { fetchImpl?: typeof fetch; proxy?: (domain: string) => Promise<WellKnown> } = {}): Promise<WellKnown> {
  const fetched = await fetchWellKnown(domain, opts.fetchImpl ?? fetch, opts);
  if (fetched.kind === "doc") return fetched.doc;
  if (!opts.proxy) throw unreachable(domain);
  return opts.proxy(domain);
}

/** How {@link resolveNode} asks for help: the node this client was loaded from. */
export interface ResolveNodeOptions extends DiscoveryTimeouts {
  fetchImpl?: typeof fetch;
  /**
   * The resolution of the own node (`GET /federation/resolve/{domain}`): well-known, `_tavrn._tcp` SRV record,
   * `https://<domain>`, the same order nodes use among themselves. Preferred over `proxy`.
   */
  resolve?: (domain: string) => Promise<PeerResolution>;
  /** Older nodes: the discovery document through the own node (`GET /federation/peer/{domain}`). */
  proxy?: (domain: string) => Promise<WellKnown>;
  allowInsecure?: boolean;
}

/**
 * Where to talk to the node of `domain` (FEDERATION.md §1.4, design note 4.2c), in this order:
 *
 * 1. its discovery document `https://<domain>/.well-known/tavrn`; the endpoints may live on another host
 *    (delegation: `tavrn.org` → `https://app.tavrn.org/api/v1`);
 * 2. no document there (404), or the browser cannot fetch it at all (CORS, TLS, DNS, development peers): the
 *    node this client was loaded from resolves the domain (`resolve`), which includes the `_tavrn._tcp` SRV
 *    record browsers cannot read, and the direct `https://<domain>` as its last step. Without `resolve` a 404
 *    means everything is on `https://<domain>`, an unreachable document goes through `proxy`;
 * 3. any other answer is an error.
 *
 * After a 404 the own node's answer wins; when the own node cannot help (federation off, rate limited,
 * unreachable) the direct `https://<domain>` is used, but a resolution it refused as invalid (an SRV target
 * claiming another domain) stays an error.
 */
export async function resolveNode(domain: string, opts: ResolveNodeOptions = {}): Promise<NodeEndpoints> {
  const fetched = await fetchWellKnown(domain, opts.fetchImpl ?? fetch, opts);
  switch (fetched.kind) {
    case "doc":
      return nodeEndpoints(fetched.doc, domain, opts);
    case "missing":
      if (!opts.resolve) return fallbackEndpoints(domain);
      try {
        return resolutionEndpoints(await opts.resolve(domain), domain, opts);
      } catch (e) {
        if (e instanceof TavrnApiError && e.code === "federation.peer_invalid") throw e;
        return fallbackEndpoints(domain);
      }
    case "status":
      throw new TavrnApiError({ type: "about:blank", title: "Node unreachable", status: 0, detail: `${domain}: HTTP ${fetched.status}`, code: "federation.peer_unreachable" });
    case "unreachable":
      if (opts.resolve) return resolutionEndpoints(await opts.resolve(domain), domain, opts);
      if (!opts.proxy) throw unreachable(domain);
      return nodeEndpoints(await opts.proxy(domain), domain, opts);
  }
}

/**
 * The identity domain of the node whose web client or API lives on `host` (an invite link
 * `https://app.tavrn.org/invite/…` of the node `tavrn.org`): the node serves its discovery document on its
 * own host too. `host` itself when it is the identity domain, the document's `domain` when its `web` or
 * `api` is on `host`, otherwise null. The caller then resolves that domain through its own well-known, so
 * the host can only name a domain that delegates to it.
 */
export async function identityOfHost(host: string, opts: DiscoveryTimeouts & { fetchImpl?: typeof fetch } = {}): Promise<string | null> {
  const fetched = await fetchWellKnown(host, opts.fetchImpl ?? fetch, opts);
  if (fetched.kind !== "doc") return null;
  const doc = fetched.doc;
  if (typeof doc?.domain !== "string" || !isNodeDomain(doc.domain)) return null;
  if (doc.domain === host) return host;
  const onHost = [doc.web, doc.api].some((u) => typeof u === "string" && parsedUrl(u)?.origin === `https://${host}`);
  return onHost ? doc.domain : null;
}

// ---- PKCE (RFC 7636, S256) -------------------------------------------------------------------

function random(bytes: number): Uint8Array {
  const out = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Random URL-safe value (32 bytes → 43 characters), e.g. the `state` of the connect flow. */
export function randomUrlSafe(bytes = 32): string {
  return b64urlEncode(random(bytes));
}

/** `BASE64URL(SHA-256(verifier))`. */
export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64urlEncode(new Uint8Array(digest));
}

/** A fresh verifier (43 characters) and its S256 challenge. */
export async function createPkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = randomUrlSafe(32);
  return { verifier, challenge: await pkceChallenge(verifier) };
}
