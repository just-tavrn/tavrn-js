// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi, TavrnApiError } from "../src";

type Call = { url: string; init: RequestInit };

/** A fetch whose answers are produced per call; records every call. */
function scripted(answer: (call: Call, n: number) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const impl = vi.fn(async (url: string, init: RequestInit) => {
    const call = { url: String(url), init };
    calls.push(call);
    return answer(call, calls.length - 1);
  });
  return { impl: impl as unknown as typeof fetch, calls };
}

/** A fetch that never answers until its signal aborts (then rejects like fetch does). */
function hanging() {
  const calls: Call[] = [];
  const impl = ((url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Promise<Response>((_, reject) => {
      const signal = init.signal;
      if (!signal) return;
      signal.addEventListener("abort", () => reject(signal.reason ?? new DOMException("aborted", "AbortError")), { once: true });
    });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const problem = (status: number, code: string) => new Response(JSON.stringify({ type: "about:blank", title: "", status, detail: "", code }), { status, headers: { "Content-Type": "application/json" } });
const headerOf = (c: Call, name: string) => (c.init.headers as Record<string, string>)[name];

describe("request timeouts and abort signals", () => {
  it("gives up after the timeout with network.timeout", async () => {
    const { impl } = hanging();
    const api = new TavrnApi({ fetchImpl: impl, timeoutMs: 30 });
    const started = Date.now();
    const err = await api.rooms.list().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TavrnApiError);
    expect((err as TavrnApiError).code).toBe("network.timeout");
    expect((err as TavrnApiError).status).toBe(0);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("applies the timeout to binary requests and discovery of the node as well", async () => {
    const { impl } = hanging();
    const api = new TavrnApi({ fetchImpl: impl, timeoutMs: 30 });
    await expect(api.whiteboards.get("S1")).rejects.toMatchObject({ code: "network.timeout" });
    await expect(api.node.wellKnown()).rejects.toMatchObject({ code: "network.timeout" });
  });

  it("uses the longer transfer timeout for uploads and downloads", async () => {
    const { impl } = hanging();
    const api = new TavrnApi({ fetchImpl: impl, timeoutMs: 10, transferTimeoutMs: 80 });
    const started = Date.now();
    await expect(api.attachments.download("B1")).rejects.toMatchObject({ code: "network.timeout" });
    expect(Date.now() - started).toBeGreaterThanOrEqual(60);
  });

  it("honours the caller's signal on every call (withSignal)", async () => {
    const { impl, calls } = hanging();
    const api = new TavrnApi({ fetchImpl: impl, timeoutMs: 0 });
    const ctrl = new AbortController();
    const scoped = api.withSignal(ctrl.signal);
    const pending = Promise.allSettled([scoped.rooms.list(), scoped.attachments.download("B1"), scoped.emojis.image("R1", "E1")]);
    await new Promise((r) => setTimeout(r, 5));
    expect(calls).toHaveLength(3);
    ctrl.abort();
    const results = await pending;
    for (const r of results) {
      expect(r.status).toBe("rejected");
      expect((r as PromiseRejectedResult).reason).toMatchObject({ code: "request.aborted" });
    }
    // An already aborted signal fails at once, without a request.
    await expect(scoped.rooms.list()).rejects.toMatchObject({ code: "request.aborted" });
    expect(calls).toHaveLength(3);
  });

  it("clears the timer once the request finished", async () => {
    vi.useFakeTimers();
    try {
      const { impl } = scripted(() => new Response("[]", { status: 200 }));
      const api = new TavrnApi({ fetchImpl: impl });
      await api.rooms.list();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("binary routes share the request layer", () => {
  it("refreshes the token on 401 for downloads, emoji, whiteboards and uploads", async () => {
    let token = "old";
    const { impl, calls } = scripted((c) => (headerOf(c, "Authorization") === "Bearer old" ? problem(401, "auth.token_expired") : new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { "Content-Type": "application/json" } })));
    const api = new TavrnApi({ fetchImpl: impl, getToken: () => token, refreshToken: async () => (token = "new") });
    const blob = await api.attachments.download("B1");
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    expect(calls.map((c) => headerOf(c, "Authorization"))).toEqual(["Bearer old", "Bearer new"]);
    token = "old";
    await api.emojis.image("R1", "E1");
    token = "old";
    expect(await api.whiteboards.get("S1")).toEqual(new Uint8Array([1, 2, 3]));
    expect(calls).toHaveLength(6);
  });

  it("repeats an upload once with a fresh token (the file is sent again unchanged)", async () => {
    let token = "old";
    const { impl, calls } = scripted((c) => (headerOf(c, "Authorization") === "Bearer old" ? problem(401, "auth.token_expired") : new Response(JSON.stringify({ id: "A1" }), { status: 201 })));
    const api = new TavrnApi({ fetchImpl: impl, getToken: () => token, refreshToken: async () => (token = "new") });
    const file = new Blob(["hello"], { type: "text/plain" });
    const att = await api.attachments.uploadToConversation("C1", file, "a.txt");
    expect(att).toEqual({ id: "A1" });
    expect(calls).toHaveLength(2);
    expect(calls[1]!.init.body).toBe(file);
  });

  it("reports network failures of every binary route as TavrnApiError", async () => {
    const impl = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    const api = new TavrnApi({ fetchImpl: impl });
    const file = new Blob(["x"], { type: "image/png" });
    for (const call of [() => api.emojis.create("R1", "x", file), () => api.emojis.image("R1", "E1"), () => api.attachments.download("B1"), () => api.attachments.uploadToConversation("C1", file, "x.png"), () => api.files.upload("R1", "C1", file, "x.png"), () => api.profile.uploadAvatar(file), () => api.node.wellKnown()]) {
      const err = await call().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(TavrnApiError);
      expect((err as TavrnApiError).code).toBe("network.error");
    }
  });

  it("sends the client header on every binary route and passes Blobs through unchanged", async () => {
    const { impl, calls } = scripted(() => new Response(JSON.stringify({ id: "x" }), { status: 200 }));
    const api = new TavrnApi({ fetchImpl: impl, getToken: () => "tok", clientHeader: "web/1" });
    const file = new Blob(["abc"], { type: "audio/ogg" });
    await api.attachments.download("B1");
    await api.emojis.create("R1", "party", file);
    await api.emojis.image("R1", "E1");
    await api.soundboard.create("R1", "boom", file, 1200);
    await api.emojis.personal.create("wave", file);
    for (const c of calls) {
      expect(headerOf(c, "Tavrn-Client")).toBe("web/1");
      expect(headerOf(c, "Authorization")).toBe("Bearer tok");
    }
    expect(calls[1]!.init.body).toBe(file);
    expect(calls[3]!.init.body).toBe(file);
    expect(calls[4]!.init.body).toBe(file);
  });

  it("keeps the problem details of refused binary requests", async () => {
    const { impl } = scripted(() => problem(403, "upload.type_forbidden"));
    const api = new TavrnApi({ fetchImpl: impl });
    await expect(api.attachments.uploadToConversation("C1", new Blob(["x"]), "x.exe")).rejects.toMatchObject({ code: "upload.type_forbidden", status: 403 });
    await expect(api.attachments.download("B1")).rejects.toMatchObject({ code: "upload.type_forbidden" });
  });
});

describe("response size", () => {
  it("refuses a JSON answer whose Content-Length is above the cap without reading it", async () => {
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        pulled += 1;
        c.enqueue(new Uint8Array(1024));
      },
    });
    const { impl } = scripted(() => new Response(body, { status: 200, headers: { "Content-Length": String(10 * 1024 * 1024) } }));
    const api = new TavrnApi({ fetchImpl: impl, maxResponseBytes: 4096 });
    await expect(api.rooms.list()).rejects.toMatchObject({ code: "response.too_large" });
    expect(pulled).toBeLessThanOrEqual(2);
  });

  it("stops reading a streamed JSON answer at the cap", async () => {
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        pulled += 1;
        c.enqueue(new Uint8Array(1024).fill(0x20));
      },
    });
    const { impl } = scripted(() => new Response(body, { status: 200 }));
    const api = new TavrnApi({ fetchImpl: impl, maxResponseBytes: 4096 });
    await expect(api.rooms.list()).rejects.toMatchObject({ code: "response.too_large" });
    expect(pulled).toBeLessThan(10);
  });
});
