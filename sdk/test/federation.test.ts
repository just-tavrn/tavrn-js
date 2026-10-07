// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi, TavrnApiError, createPkce, discoverNode, fallbackEndpoints, identityOfHost, isNodeDomain, nodeEndpoints, parseAccountInput, parseAddress, pkceChallenge, randomUrlSafe, resolutionEndpoints, resolveNode, type PeerResolution, type WellKnown } from "../src";

function doc(over: Partial<WellKnown> = {}): WellKnown {
  return {
    tavrn: 1,
    domain: "home.example",
    name: "Home",
    description: "",
    api: "https://home.example/api/v1",
    ws: "wss://home.example/api/v1/ws",
    web: "https://home.example",
    software: { name: "tavrn-node", version: "0" },
    capabilities: ["content.v1", "federation", "federation.v1"],
    keys: [],
    registration: "open",
    email: "none",
    policies: { uploads_enabled: true, upload_max_bytes: 1, voice_enabled: false, voice_max_bitrate_kbps: 1, screenshare: { enabled: false, max_resolution: "720p", max_fps: 1 } },
    directory_listing: true,
    ...over,
  } as WellKnown;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

describe("addresses and domains", () => {
  it("parses user addresses of other nodes", () => {
    expect(parseAddress(" Alice@Home.Example ")).toEqual({ username: "alice", domain: "home.example" });
    expect(parseAddress("alice@localhost")).toBeNull();
    expect(parseAddress("alice")).toBeNull();
    expect(parseAddress("@home.example")).toBeNull();
    expect(parseAddress("al ice@home.example")).toBeNull();
    expect(parseAddress("alice@home.example:443")).toBeNull();
    expect(parseAddress("alice@10.0.0.1")).toBeNull();
  });

  it("accepts an address or just the identity domain to sign in", () => {
    expect(parseAccountInput("alice@tavrn.org")).toEqual({ username: "alice", domain: "tavrn.org" });
    expect(parseAccountInput(" Tavrn.org ")).toEqual({ username: null, domain: "tavrn.org" });
    expect(parseAccountInput("@tavrn.org")).toEqual({ username: null, domain: "tavrn.org" });
    expect(parseAccountInput("https://tavrn.org")).toBeNull();
    expect(parseAccountInput("tavrn.org:443")).toBeNull();
    expect(parseAccountInput("alice")).toBeNull();
    expect(parseAccountInput("127.0.0.1")).toBeNull();
  });

  it("knows node domains", () => {
    expect(isNodeDomain("a.test")).toBe(true);
    expect(isNodeDomain("xn--bcher-kva.example")).toBe(true);
    expect(isNodeDomain("-a.test")).toBe(false);
    expect(isNodeDomain("a..test")).toBe(false);
    expect(isNodeDomain("A.test")).toBe(false);
  });
});

describe("node endpoints from the discovery document", () => {
  it("derives base, ws and web", () => {
    expect(nodeEndpoints(doc(), "home.example")).toEqual({ domain: "home.example", base: "https://home.example", ws: "wss://home.example/api/v1/ws", web: "https://home.example" });
    const sub = nodeEndpoints(doc({ api: "https://api.home.example/api/v1", web: "https://chat.home.example/" }), "home.example");
    expect(sub.base).toBe("https://api.home.example");
    expect(sub.web).toBe("https://chat.home.example");
    expect(nodeEndpoints(doc({ web: undefined as unknown as string }), "home.example").web).toBe("https://home.example");
  });

  it("refuses documents that do not belong to the domain or do not federate", () => {
    const code = (d: WellKnown, opts?: { allowInsecure?: boolean }) => {
      try {
        nodeEndpoints(d, "home.example", opts);
        return "ok";
      } catch (e) {
        return (e as TavrnApiError).code;
      }
    };
    expect(code(doc({ domain: "evil.example" }))).toBe("federation.peer_invalid");
    expect(code(doc({ tavrn: 2 }))).toBe("federation.peer_invalid");
    expect(code(doc({ capabilities: ["content.v1"] }))).toBe("federation.peer_invalid");
    expect(code(doc({ api: "https://home.example/api" }))).toBe("federation.peer_invalid");
    expect(code(doc({ api: "https://user:pw@app.example/api/v1" }))).toBe("federation.peer_invalid");
    expect(code(doc({ api: "javascript:alert(1)//api/v1" }))).toBe("federation.peer_invalid");
    expect(code(doc({ web: "javascript:alert(1)" }))).toBe("federation.peer_invalid");
    expect(code(doc({ web: "https://chat.example/?next=x" }))).toBe("federation.peer_invalid");
    expect(code(doc({ ws: "https://home.example/api/v1/ws" }))).toBe("federation.peer_invalid");
    expect(code(doc({ ws: "wss://home.example/api/v1/ws#x" }))).toBe("federation.peer_invalid");
    // Plain HTTP only for development clients.
    const dev = doc({ api: "http://home.example:8183/api/v1", ws: "ws://home.example:8183/api/v1/ws", web: "http://home.example:5275" });
    expect(code(dev)).toBe("federation.peer_invalid");
    expect(code(dev, { allowInsecure: true })).toBe("ok");
    expect(nodeEndpoints(dev, "home.example", { allowInsecure: true }).base).toBe("http://home.example:8183");
  });
});

describe("delegation (design note 4.2c)", () => {
  const tavrn = doc({ domain: "tavrn.org", api: "https://app.tavrn.org/api/v1", ws: "wss://app.tavrn.org/api/v1/ws", web: "https://app.tavrn.org" });

  it("follows endpoints on another host", () => {
    expect(nodeEndpoints(tavrn, "tavrn.org")).toEqual({ domain: "tavrn.org", base: "https://app.tavrn.org", ws: "wss://app.tavrn.org/api/v1/ws", web: "https://app.tavrn.org" });
    // Even an unrelated host: the document is the identity domain's own statement.
    const other = nodeEndpoints(doc({ domain: "tavrn.org", api: "https://chat.example.net/api/v1", ws: "wss://chat.example.net/api/v1/ws", web: "https://chat.example.net" }), "tavrn.org");
    expect(other.base).toBe("https://chat.example.net");
    expect(other.domain).toBe("tavrn.org");
  });

  it("resolves the well-known of the identity domain first", async () => {
    const fetchImpl = vi.fn(async () => json(200, tavrn)) as unknown as typeof fetch;
    const proxy = vi.fn();
    expect(await resolveNode("tavrn.org", { fetchImpl, proxy })).toEqual({ domain: "tavrn.org", base: "https://app.tavrn.org", ws: "wss://app.tavrn.org/api/v1/ws", web: "https://app.tavrn.org" });
    expect((fetchImpl as unknown as { mock: { calls: unknown[][] } }).mock.calls[0]![0]).toBe("https://tavrn.org/.well-known/tavrn");
    expect(proxy).not.toHaveBeenCalled();
  });

  it("refuses a document of another domain", async () => {
    const fetchImpl = (async () => json(200, { ...tavrn, domain: "evil.example" })) as unknown as typeof fetch;
    const err = await resolveNode("tavrn.org", { fetchImpl }).catch((e: unknown) => e as TavrnApiError);
    expect(err.code).toBe("federation.peer_invalid");
    const viaProxy = await resolveNode("tavrn.org", { fetchImpl: (async () => Promise.reject(new TypeError("cors"))) as unknown as typeof fetch, proxy: async () => ({ ...tavrn, domain: "evil.example" }) }).catch((e: unknown) => e as TavrnApiError);
    expect(viaProxy.code).toBe("federation.peer_invalid");
  });

  it("falls back to the domain only when the document is missing", async () => {
    const proxy = vi.fn(async () => tavrn);
    const missing = (async () => json(404, { error: "not found" })) as unknown as typeof fetch;
    expect(await resolveNode("tavrn.org", { fetchImpl: missing, proxy })).toEqual(fallbackEndpoints("tavrn.org"));
    expect(fallbackEndpoints("tavrn.org")).toEqual({ domain: "tavrn.org", base: "https://tavrn.org", ws: "wss://tavrn.org/api/v1/ws", web: "https://tavrn.org" });
    const broken = (async () => json(500, {})) as unknown as typeof fetch;
    const err = await resolveNode("tavrn.org", { fetchImpl: broken, proxy }).catch((e: unknown) => e as TavrnApiError);
    expect(err.code).toBe("federation.peer_unreachable");
    expect(proxy).not.toHaveBeenCalled();
  });

  it("asks the own node when the browser cannot fetch the document", async () => {
    const fetchImpl = (async () => Promise.reject(new TypeError("Failed to fetch"))) as unknown as typeof fetch;
    const proxy = vi.fn(async () => tavrn);
    expect((await resolveNode("tavrn.org", { fetchImpl, proxy })).base).toBe("https://app.tavrn.org");
    expect(proxy).toHaveBeenCalledWith("tavrn.org");
    expect((await resolveNode("tavrn.org", { fetchImpl }).catch((e: unknown) => e as TavrnApiError)).code).toBe("federation.peer_unreachable");
    // Development peers on plain HTTP only with allowInsecure.
    const dev = doc({ domain: "a.test", api: "http://127.0.0.1:8402/api/v1", ws: "ws://127.0.0.1:8402/api/v1/ws", web: "http://a.test:5402" });
    const devErr = await resolveNode("a.test", { fetchImpl, proxy: async () => dev }).catch((e: unknown) => e as TavrnApiError);
    expect(devErr.code).toBe("federation.peer_invalid");
    expect((await resolveNode("a.test", { fetchImpl, proxy: async () => dev, allowInsecure: true })).base).toBe("http://127.0.0.1:8402");
  });
});

describe("resolution through the own node (well-known → SRV → domain)", () => {
  const viaSrv: PeerResolution = { domain: "tavrn.org", api: "https://node.example.net/api/v1", ws: "wss://node.example.net/api/v1/ws", web: "https://node.example.net", source: "srv" };
  const failing = (async () => Promise.reject(new TypeError("Failed to fetch"))) as unknown as typeof fetch;
  const missing = (async () => json(404, { error: "not found" })) as unknown as typeof fetch;
  const problem = (code: string) => new TavrnApiError({ type: "about:blank", title: "x", status: 502, detail: "x", code });

  it("asks the own node when the website has no document (SRV-only setups)", async () => {
    const resolve = vi.fn(async () => viaSrv);
    const proxy = vi.fn();
    expect(await resolveNode("tavrn.org", { fetchImpl: missing, resolve, proxy })).toEqual({ domain: "tavrn.org", base: "https://node.example.net", ws: "wss://node.example.net/api/v1/ws", web: "https://node.example.net" });
    expect(resolve).toHaveBeenCalledWith("tavrn.org");
    expect(proxy).not.toHaveBeenCalled();
  });

  it("prefers the node's resolution over the document proxy when the browser cannot fetch", async () => {
    const resolve = vi.fn(async () => viaSrv);
    const proxy = vi.fn();
    expect((await resolveNode("tavrn.org", { fetchImpl: failing, resolve, proxy })).base).toBe("https://node.example.net");
    expect(proxy).not.toHaveBeenCalled();
    // A failing node resolution is the answer here (nothing else can be tried).
    const err = await resolveNode("tavrn.org", { fetchImpl: failing, resolve: async () => Promise.reject(problem("federation.peer_unreachable")) }).catch((e: unknown) => e as TavrnApiError);
    expect(err.code).toBe("federation.peer_unreachable");
  });

  it("never asks the node when the domain serves a document", async () => {
    const resolve = vi.fn(async () => viaSrv);
    const fetchImpl = (async () => json(200, doc({ domain: "tavrn.org", api: "https://app.tavrn.org/api/v1", ws: "wss://app.tavrn.org/api/v1/ws" }))) as unknown as typeof fetch;
    expect((await resolveNode("tavrn.org", { fetchImpl, resolve })).base).toBe("https://app.tavrn.org");
    expect(resolve).not.toHaveBeenCalled();
    // Other status codes stay errors, without asking.
    const broken = (async () => json(503, {})) as unknown as typeof fetch;
    expect((await resolveNode("tavrn.org", { fetchImpl: broken, resolve }).catch((e: unknown) => e as TavrnApiError)).code).toBe("federation.peer_unreachable");
    expect(resolve).not.toHaveBeenCalled();
  });

  it("falls back to the domain after a 404 when the own node cannot help, but not after a refusal", async () => {
    for (const code of ["federation.disabled", "rate_limited", "federation.peer_unreachable"]) {
      expect(await resolveNode("tavrn.org", { fetchImpl: missing, resolve: async () => Promise.reject(problem(code)) })).toEqual(fallbackEndpoints("tavrn.org"));
    }
    expect(await resolveNode("tavrn.org", { fetchImpl: missing, resolve: async () => Promise.reject(new TypeError("offline")) })).toEqual(fallbackEndpoints("tavrn.org"));
    const refused = await resolveNode("tavrn.org", { fetchImpl: missing, resolve: async () => Promise.reject(problem("federation.peer_invalid")) }).catch((e: unknown) => e as TavrnApiError);
    expect(refused.code).toBe("federation.peer_invalid");
  });

  it("checks the node's answer like a discovery document", () => {
    expect(resolutionEndpoints(viaSrv, "tavrn.org").base).toBe("https://node.example.net");
    expect(resolutionEndpoints({ ...viaSrv, web: "" }, "tavrn.org").web).toBe("https://tavrn.org");
    const code = (res: PeerResolution, opts = {}) => {
      try {
        resolutionEndpoints(res, "tavrn.org", opts);
        return "ok";
      } catch (e) {
        return (e as TavrnApiError).code;
      }
    };
    // A compromised or buggy node cannot hand out another domain's endpoints or unsafe URLs.
    expect(code({ ...viaSrv, domain: "evil.example" })).toBe("federation.peer_invalid");
    expect(code({ ...viaSrv, api: "https://node.example.net/v2" })).toBe("federation.peer_invalid");
    expect(code({ ...viaSrv, api: "javascript:alert(1)//api/v1" })).toBe("federation.peer_invalid");
    expect(code({ ...viaSrv, api: "https://user:pw@node.example.net/api/v1" })).toBe("federation.peer_invalid");
    expect(code({ ...viaSrv, ws: "ws://node.example.net/api/v1/ws" })).toBe("federation.peer_invalid");
    expect(code({ ...viaSrv, web: "https://node.example.net/?x=1" })).toBe("federation.peer_invalid");
    expect(code(null as unknown as PeerResolution)).toBe("federation.peer_invalid");
    // Development nodes on plain HTTP only with allowInsecure.
    const dev: PeerResolution = { domain: "tavrn.org", api: "http://127.0.0.1:8601/api/v1", ws: "ws://127.0.0.1:8601/api/v1/ws", web: "http://127.0.0.1:5601", source: "well_known" };
    expect(code(dev)).toBe("federation.peer_invalid");
    expect(code(dev, { allowInsecure: true })).toBe("ok");
  });
});

describe("identity domain of an app host", () => {
  const tavrn = doc({ domain: "tavrn.org", api: "https://app.tavrn.org/api/v1", ws: "wss://app.tavrn.org/api/v1/ws", web: "https://app.tavrn.org" });
  const serve = (body: unknown, status = 200) => (async () => json(status, body)) as unknown as typeof fetch;

  it("maps the host of a delegated node to its identity domain", async () => {
    expect(await identityOfHost("app.tavrn.org", { fetchImpl: serve(tavrn) })).toBe("tavrn.org");
    expect(await identityOfHost("home.example", { fetchImpl: serve(doc()) })).toBe("home.example");
  });

  it("names nobody when the document does not point to the host", async () => {
    expect(await identityOfHost("evil.example", { fetchImpl: serve(tavrn) })).toBeNull();
    expect(await identityOfHost("app.tavrn.org", { fetchImpl: serve({ ...tavrn, domain: "127.0.0.1" }) })).toBeNull();
    expect(await identityOfHost("app.tavrn.org", { fetchImpl: serve({}, 404) })).toBeNull();
    expect(await identityOfHost("app.tavrn.org", { fetchImpl: (async () => Promise.reject(new TypeError("x"))) as unknown as typeof fetch })).toBeNull();
  });
});

describe("discovery", () => {
  it("fetches the document straight from the domain", async () => {
    const fetchImpl = vi.fn(async () => json(200, doc())) as unknown as typeof fetch;
    const proxy = vi.fn();
    const d = await discoverNode("home.example", { fetchImpl, proxy });
    expect(d.domain).toBe("home.example");
    expect((fetchImpl as unknown as { mock: { calls: unknown[][] } }).mock.calls[0]![0]).toBe("https://home.example/.well-known/tavrn");
    expect(proxy).not.toHaveBeenCalled();
  });

  it("falls back to the proxy when the browser cannot fetch it", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;
    const proxy = vi.fn(async () => doc());
    expect((await discoverNode("home.example", { fetchImpl, proxy })).domain).toBe("home.example");
    expect(proxy).toHaveBeenCalledWith("home.example");
    const err = await discoverNode("home.example", { fetchImpl }).catch((e: unknown) => e as TavrnApiError);
    expect(err.code).toBe("federation.peer_unreachable");
  });

  it("ignores oversized documents", async () => {
    const fetchImpl = (async () => new Response("x".repeat(70 * 1024), { status: 200 })) as unknown as typeof fetch;
    const proxy = vi.fn(async () => doc());
    await discoverNode("home.example", { fetchImpl, proxy });
    expect(proxy).toHaveBeenCalled();
  });
});

describe("PKCE", () => {
  it("computes the S256 challenge of RFC 7636 appendix B", async () => {
    expect(await pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("creates fresh verifiers and states", async () => {
    const a = await createPkce();
    const b = await createPkce();
    expect(a.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.challenge).toBe(await pkceChallenge(a.verifier));
    expect(randomUrlSafe()).toHaveLength(43);
  });
});

describe("multi-node TavrnApi", () => {
  it("reads a dynamic base URL on every request", async () => {
    const urls: string[] = [];
    let base = "https://a.example";
    const api = new TavrnApi({ baseUrl: () => base, fetchImpl: (async (url: string) => (urls.push(url), json(200, {}))) as unknown as typeof fetch });
    await api.users.me();
    base = "https://b.example/";
    await api.users.me();
    expect(urls).toEqual(["https://a.example/api/v1/users/me", "https://b.example/api/v1/users/me"]);
    expect(api.baseUrl).toBe("https://b.example");
  });

  it("federation token, federated login and the connect flow", async () => {
    const calls: Array<{ url: string; body: unknown; auth?: string }> = [];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      calls.push({ url, body: JSON.parse(String(init.body ?? "null")), auth: (init.headers as Record<string, string>).Authorization });
      return json(200, { ok: true });
    }) as unknown as typeof fetch;
    const home = new TavrnApi({ baseUrl: "https://home.example", getToken: () => "home-token", fetchImpl });
    const target = new TavrnApi({ baseUrl: "https://t.example", fetchImpl });
    await home.federation.token("t.example");
    await target.auth.federated("jwt", "Browser");
    await home.auth.connectCode({ origin: "https://t.example", code_challenge: "c" });
    await new TavrnApi({ baseUrl: "https://home.example", fetchImpl }).auth.connectToken({ code: "x", code_verifier: "v" });
    await target.federation.peer("home.example");
    await target.federation.resolve("home.example");
    expect(calls.map((c) => c.url)).toEqual([
      "https://home.example/api/v1/federation/token",
      "https://t.example/api/v1/auth/federated",
      "https://home.example/api/v1/auth/connect/code",
      "https://home.example/api/v1/auth/connect/token",
      "https://t.example/api/v1/federation/peer/home.example",
      "https://t.example/api/v1/federation/resolve/home.example",
    ]);
    expect(calls[0]!.body).toEqual({ target: "t.example" });
    expect(calls[0]!.auth).toBe("Bearer home-token");
    expect(calls[1]!.body).toEqual({ token: "jwt", device_name: "Browser" });
    expect(calls[3]!.auth).toBeUndefined();
  });

  it("reads and writes the conversation index with If-Match", async () => {
    const seen: Array<{ method: string; ifMatch?: string; body: unknown }> = [];
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      const headers = init.headers as Record<string, string>;
      seen.push({ method: String(init.method), ifMatch: headers["If-Match"], body: JSON.parse(String(init.body ?? "null")) });
      if (init.method === "GET") return json(200, { version: 3, items: [] }, { ETag: '"3"' });
      if (headers["If-Match"] === '"3"') return json(412, { type: "x", title: "", status: 412, detail: "", code: "index.version_conflict", meta: { version: 4 } });
      return json(200, { version: 5, items: [{ node: "a.example" }] });
    }) as unknown as typeof fetch;
    const api = new TavrnApi({ baseUrl: "https://home.example", fetchImpl });
    expect(await api.conversationIndex.get()).toEqual({ version: 3, items: [] });
    const conflict = await api.conversationIndex.put([], 3).catch((e: unknown) => e as TavrnApiError);
    expect(conflict.code).toBe("index.version_conflict");
    expect(conflict.problem.meta).toEqual({ version: 4 });
    const written = await api.conversationIndex.put([], null);
    expect(written.version).toBe(5);
    expect(seen[1]!.ifMatch).toBe('"3"');
    expect(seen[2]!.ifMatch).toBeUndefined();
    expect(seen[2]!.body).toEqual({ items: [] });
  });
});
