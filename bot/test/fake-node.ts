// SPDX-License-Identifier: Apache-2.0
/**
 * A fake node for unit tests of the bot runtime: just enough of the HTTP API (`fetchImpl`) and the WebSocket
 * (`WebSocketImpl`) for `createBot().start()` (identity, device attestation, KeyPackages, rooms), plus recorded
 * requests and canned answers for the routes a test exercises. Conversations here are plaintext; encrypted paths
 * are covered by the integration tests against a real node (`test/node/`).
 */
import { b64urlEncode, type Message } from "@tavrn/sdk";

export const DOMAIN = "h.test";
export const BASE = `http://${DOMAIN}`;
export const BOT_ID = "01J9ZK3G5M8Q2W4E6R8T0Y2B01";
export const DEVICE = "01J9ZK3G5M8Q2W4E6R8T0Y2D01";
export const APP_ID = "01J9ZK3G5M8Q2W4E6R8T0Y2A01";
export const ROOM = "01J9ZK3G5M8Q2W4E6R8T0Y2R01";
export const CHANNEL = "01J9ZK3G5M8Q2W4E6R8T0Y2C01";
export const VOICE = "01J9ZK3G5M8Q2W4E6R8T0Y2C02";
export const FORUM = "01J9ZK3G5M8Q2W4E6R8T0Y2C03";
export const ALICE = "alice@h.test";
export const ALICE_ID = "01J9ZK3G5M8Q2W4E6R8T0Y2S01";
export const BOT_ADDRESS = `bot@${DOMAIN}`;

const enc = (v: unknown) => b64urlEncode(new TextEncoder().encode(JSON.stringify(v)));
/** An app token the runtime can read (the fake node does not verify signatures). */
export const TOKEN = `${enc({ alg: "EdDSA", typ: "JWT" })}.${enc({ typ: "app", iss: DOMAIN, aud: DOMAIN, sub: BOT_ID, dev: DEVICE, app: APP_ID, exp: Math.floor(Date.now() / 1000) + 86400, scp: [] })}.c2ln`;

export interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Record<string, string>;
  body: unknown;
}

const ANSWER = Symbol("answer");
type Answer = { [ANSWER]: true; status?: number; body?: unknown; headers?: Record<string, string> };

/** An answer with a status (and headers) other than `200` with the returned JSON. */
export function respond(status: number, body?: unknown, headers?: Record<string, string>): Answer {
  return { [ANSWER]: true, status, body, headers };
}
type Handler = (call: Call, match: RegExpMatchArray) => Answer | unknown | Promise<Answer | unknown>;

function reply(a: Omit<Answer, typeof ANSWER>): Response {
  if (a.status === 204 || a.body === undefined) return new Response(null, { status: a.status ?? 204, headers: a.headers });
  return new Response(JSON.stringify(a.body), { status: a.status ?? 200, headers: { "Content-Type": "application/json", ...a.headers } });
}

/** A message envelope of the fake node (plaintext). */
export function message(over: Partial<Message> = {}): Message {
  return {
    id: "01J9ZK3G5M8Q2W4E6R8T0Y2M01",
    conversation_id: CHANNEL,
    author: ALICE,
    author_id: ALICE_ID,
    author_kind: "user",
    device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2D99",
    created_at: new Date().toISOString(),
    edited_at: null,
    encrypted: false,
    format: 1,
    reply_to_id: null,
    thread_id: null,
    mentions: [],
    mentions_everyone: false,
    attachments: [],
    reactions: [],
    pinned: false,
    content: { type: "text", body: "hello" },
    signature: null,
    ...over,
  } as Message;
}

export class FakeNode {
  readonly calls: Call[] = [];
  readonly unrouted: Call[] = [];
  readonly sockets: FakeSocket[] = [];
  private readonly routes: { method: string; re: RegExp; handler: Handler }[] = [];
  private identity: string | null = null;
  private readonly devices = new Map<string, Record<string, unknown>>();
  private keyPackages = 0;
  capabilities = ["content.v1", "threads", "threads.client_ids"];

  constructor() {
    const R = this.route.bind(this);
    R("GET", /^\/\.well-known\/tavrn$/, () => ({ domain: DOMAIN, web: BASE }));
    R("GET", /^\/api\/v1\/node$/, () => ({ domain: DOMAIN, capabilities: this.capabilities }));
    R("GET", /^\/api\/v1\/users\/me$/, () => ({ id: BOT_ID, username: "bot", address: BOT_ADDRESS, display_name: "Bot", kind: "bot", has_identity_key: this.identity !== null }));
    R("PUT", /^\/api\/v1\/users\/me\/identity$/, (c) => {
      this.identity = (c.body as { identity_public_key: string }).identity_public_key;
      return respond(204);
    });
    R("GET", /^\/api\/v1\/users\/([^/]+)\/keys$/, (_c, m) => {
      if (m[1] !== "bot") return { user: `${m[1]}@${DOMAIN}`, identity_public_key: null, devices: [], kind: "user" };
      return { user: BOT_ADDRESS, identity_public_key: this.identity, devices: [...this.devices.entries()].map(([device_id, d]) => ({ device_id, ...d })), kind: "bot" };
    });
    R("PUT", /^\/api\/v1\/users\/me\/devices\/([^/]+)\/key$/, (c, m) => {
      this.devices.set(m[1]!, { ...(this.devices.get(m[1]!) ?? {}), ...(c.body as Record<string, unknown>) });
      return respond(204);
    });
    R("PUT", /^\/api\/v1\/users\/me\/devices\/([^/]+)\/share-key$/, (c, m) => {
      this.devices.set(m[1]!, { ...(this.devices.get(m[1]!) ?? {}), ...(c.body as Record<string, unknown>) });
      return respond(204);
    });
    R("GET", /^\/api\/v1\/users\/me\/devices\/[^/]+\/key-packages$/, () => ({ count: this.keyPackages }));
    R("POST", /^\/api\/v1\/users\/me\/devices\/[^/]+\/key-packages$/, (c) => {
      this.keyPackages += (c.body as { key_packages: string[] }).key_packages.length;
      return { count: this.keyPackages };
    });
    R("GET", /^\/api\/v1\/mls\/welcomes$/, () => ({ items: [] }));
    R("GET", /^\/api\/v1\/applications\/me\/installations$/, () => []);
    R("GET", /^\/api\/v1\/rooms$/, () => [{ id: ROOM, name: "Room" }]);
    R("GET", /^\/api\/v1\/rooms\/([^/]+)$/, (_c, m) => ({
      id: m[1],
      name: "Room",
      channels: [
        { id: CHANNEL, room_id: ROOM, kind: "text", name: "general", encrypted: false, no_bots_effective: false },
        { id: VOICE, room_id: ROOM, kind: "voice", name: "Voice", encrypted: false, no_bots_effective: false },
        { id: FORUM, room_id: ROOM, kind: "forum", name: "Forum", encrypted: false, no_bots_effective: false },
      ],
    }));
  }

  /** Answers `method` requests whose path (without query) matches `re`; later routes win. */
  route(method: string, re: RegExp, handler: Handler): this {
    this.routes.unshift({ method, re, handler });
    return this;
  }

  /** Requests to a path (method optional), oldest first. */
  requests(re: RegExp, method?: string): Call[] {
    return this.calls.filter((c) => re.test(c.path) && (!method || c.method === method));
  }

  readonly fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = v;
    let body: unknown = init?.body;
    if (typeof body === "string" && headers["content-type"]?.includes("json")) body = JSON.parse(body);
    const call: Call = { method: init?.method ?? "GET", path: url.pathname, query: url.searchParams, headers, body };
    this.calls.push(call);
    for (const r of this.routes) {
      if (r.method !== call.method) continue;
      const m = call.path.match(r.re);
      if (!m) continue;
      const out = await r.handler(call, m);
      if (out instanceof Response) return out;
      if (out && typeof out === "object" && ANSWER in out) return reply(out as Answer);
      return reply({ body: out });
    }
    this.unrouted.push(call);
    return reply({ status: 404, body: { type: "about:blank", title: "Not found", status: 404, code: "test.unrouted", detail: `${call.method} ${call.path}` } });
  }) as typeof fetch;

  /** Sends an event to every open socket. */
  emit(type: string, data: unknown): void {
    for (const s of this.sockets) if (s.readyState === 1) s.deliver({ op: "event", id: `01J9ZK3G5M8Q2W4E6R8T0Y${String(Math.floor(Math.random() * 9999)).padStart(4, "0")}`, type, data });
  }

  /** Client operations (other than hello/pong) the sockets received. */
  operations(): Record<string, unknown>[] {
    return this.sockets.flatMap((s) => s.sent).filter((o) => o.op !== "hello" && o.op !== "pong");
  }

  get WebSocket(): typeof WebSocket {
    const node = this;
    return class extends FakeSocket {
      constructor(url: string) {
        super(url);
        node.sockets.push(this);
      }
    } as unknown as typeof WebSocket;
  }
}

export class FakeSocket {
  readyState = 0;
  readonly sent: Record<string, unknown>[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((m: { data: string }) => void) | null = null;
  onclose: ((ev: { code: number; reason?: string }) => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(readonly url: string) {
    setTimeout(() => {
      this.readyState = 1;
      this.onopen?.();
    }, 0);
  }

  send(raw: string) {
    const op = JSON.parse(raw) as Record<string, unknown>;
    this.sent.push(op);
    if (op.op === "hello") setTimeout(() => this.deliver({ op: "ready", session_id: "s1", capabilities: [], application_id: APP_ID }), 0);
  }

  deliver(frame: unknown) {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.onclose?.({ code: 1000 });
  }
}

/** Lets pending timers and promise chains run (socket delivery, async listeners). */
export async function settle(rounds = 5): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setTimeout(r, 0));
}
