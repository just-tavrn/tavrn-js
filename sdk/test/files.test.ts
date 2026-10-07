// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi } from "../src";

function fetchMock(body: unknown, status = 200) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  });
  return { impl: impl as unknown as typeof fetch, calls };
}

describe("files channels (FILES.md)", () => {
  it("lists folders and searches with the right query", async () => {
    const { impl, calls } = fetchMock({ entries: [], next_after: null, path: [] });
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    await api.files.list("R", "C", { parent: "F1", limit: 50, after: "E9" });
    expect(calls[0]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/files?parent=F1&limit=50&after=E9");
    await api.files.list("R", "C", { parent: null, q: "report" });
    expect(calls[1]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/files?q=report");
  });

  it("uploads raw with name, folder and conflict headers", async () => {
    const { impl, calls } = fetchMock({ id: "E1", name: "a b.txt" }, 201);
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    const entry = await api.files.upload("R", "C", new Blob(["hi"], { type: "text/plain" }), "a b.txt", { parentId: "F1", rename: true });
    expect(entry.id).toBe("E1");
    expect(calls[0]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/files/upload");
    const h = calls[0]!.init.headers as Record<string, string>;
    expect(h["Tavrn-File-Name"]).toBe("a%20b.txt");
    expect(h["Tavrn-Parent"]).toBe("F1");
    expect(h["Tavrn-Conflict"]).toBe("rename");
    expect(h["Content-Type"]).toBe("text/plain");
    expect(h.Authorization).toBe("Bearer tok");
  });

  it("moves to the top level with an explicit null and tests a backend", async () => {
    const { impl, calls } = fetchMock({ ok: true, kind: "webdav" });
    const api = new TavrnApi({ fetchImpl: impl });
    await api.files.update("R", "C", "E1", { parent_id: null });
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ parent_id: null });
    await api.files.testBackend("R", "C", { kind: "webdav", url: "https://dav.example/" });
    expect(calls[1]!.url).toMatch(/\/api\/v1\/rooms\/R\/channels\/C\/files\/backend\/test$/);
    expect(calls[1]!.init.method).toBe("POST");
  });
});
