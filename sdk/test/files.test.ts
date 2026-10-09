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

  it("sends encrypted uploads with id, record, epoch and category, never a name", async () => {
    const { impl, calls } = fetchMock({ id: "E1", name: "" }, 201);
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    await api.files.uploadEncrypted("R", "C", new Blob([new Uint8Array(32)]), { id: "E1", record: "AQ", recordEpoch: 3, category: "images", parentId: "F1" });
    const h = calls[0]!.init.headers as Record<string, string>;
    expect(h["Tavrn-Entry-Id"]).toBe("E1");
    expect(h["Tavrn-Record"]).toBe("AQ");
    expect(h["Tavrn-Record-Epoch"]).toBe("3");
    expect(h["Tavrn-Upload-Category"]).toBe("images");
    expect(h["Tavrn-Parent"]).toBe("F1");
    expect(h["Tavrn-File-Name"]).toBeUndefined();
    expect(h["Content-Type"]).toBe("application/octet-stream");
    await api.files.createFolderEncrypted("R", "C", { id: "F2", record: "AQ", record_epoch: 3, parent_id: null });
    expect(JSON.parse(String(calls[1]!.init.body))).toEqual({ id: "F2", record: "AQ", record_epoch: 3, parent_id: null });
  });

  it("lists own entries and records, and keeps external objects only on request", async () => {
    const { impl, calls } = fetchMock({ entries: [], next_after: null, files: 0, folders: 0, bytes: 0 });
    const api = new TavrnApi({ baseUrl: "https://n.example", fetchImpl: impl });
    await api.files.mine("R", "C", { after: "E1", limit: 10 });
    expect(calls[0]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/files/mine?limit=10&after=E1");
    await api.files.records("R", "C", { epoch: 4, since: "2026-10-09T00:00:00.000Z" });
    expect(calls[1]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/files/records?epoch=4&since=2026-10-09T00%3A00%3A00.000Z");
    await api.channels.delete("R", "C", { keepExternal: true });
    expect(calls[2]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C?keep_external=true");
    await api.rooms.delete("R");
    expect(calls[3]!.url).toBe("https://n.example/api/v1/rooms/R");
  });

  it("fetches a ciphertext range and the thumbnail (null without one)", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const impl = vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return url.endsWith("/thumbnail") ? new Response(JSON.stringify({ code: "files.no_thumbnail" }), { status: 404 }) : new Response(new Uint8Array([1, 2, 3]), { status: 206 });
    }) as unknown as typeof fetch;
    const api = new TavrnApi({ baseUrl: "https://n.example", fetchImpl: impl });
    const resp = await api.files.downloadResponse("R", "C", "E1", { start: 0, end: 2 });
    expect(resp.status).toBe(206);
    expect((calls[0]!.init.headers as Record<string, string>).Range).toBe("bytes=0-2");
    expect(await api.files.thumbnail("R", "C", "E1")).toBeNull();
  });
});
