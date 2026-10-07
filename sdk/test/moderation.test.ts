// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi } from "../src";
import type { AutomodRule } from "../src";

function fetchMock(body: unknown = {}, status = 200) {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  const impl = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(String(init.body)) : undefined });
    return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  });
  return { api: new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl as unknown as typeof fetch }), calls };
}

describe("moderation (MODERATION.md)", () => {
  it("sends reports with evidence and reads the inbox", async () => {
    const { api, calls } = fetchMock({ id: "R1", status: "open", merged: false });
    const evidence = [{ message_id: "M1", author: "a@n.example", device_id: "D", created_at: "2026-10-01T10:00:00Z", text: "hi", attachments: [] }];
    const created = await api.reports.create({ kind: "message", conversation_id: "C1", message_id: "M1", category: "harassment", detail: "", evidence });
    expect(created.id).toBe("R1");
    expect(calls[0]).toMatchObject({ url: "https://n.example/api/v1/reports", method: "POST", body: { kind: "message", evidence } });
    await api.reports.room("ROOM", { status: "open", limit: 20 });
    expect(calls[1]!.url).toBe("https://n.example/api/v1/rooms/ROOM/reports?status=open&limit=20");
    await api.reports.admin({ scope: "node", before: "R9" });
    expect(calls[2]!.url).toBe("https://n.example/api/v1/admin/reports?scope=node&before=R9");
    await api.reports.get("R1");
    expect(calls[3]).toMatchObject({ url: "https://n.example/api/v1/reports/R1", method: "GET" });
    await api.reports.update("R1", { status: "resolved", assignee_id: null, note: "done" });
    expect(calls[4]).toMatchObject({ method: "PATCH", body: { status: "resolved", assignee_id: null, note: "done" } });
    await api.reports.act("R1", { action: "timeout", minutes: 60, reason: "", resolve: true });
    expect(calls[5]).toMatchObject({ url: "https://n.example/api/v1/reports/R1/actions", method: "POST", body: { action: "timeout", minutes: 60 } });
  });

  it("deletes reports", async () => {
    const { api, calls } = fetchMock(undefined, 204);
    await expect(api.reports.delete("R/1")).resolves.toBeUndefined();
    expect(calls[0]).toMatchObject({ url: "https://n.example/api/v1/reports/R%2F1", method: "DELETE" });
  });

  it("reads and replaces the room's content rules", async () => {
    const { api, calls } = fetchMock({ rules: [], burst: { limit: 10, window_secs: 5, timeout_minutes: 10 }, node: { words: false, links: false } });
    const settings = await api.automod.get("ROOM");
    expect(settings.burst.window_secs).toBe(5);
    const rules: AutomodRule[] = [{ name: "Slurs", terms: ["bad*"], whole_word: true, links: "off", domains: [], exempt_roles: [], exempt_channels: [], action: "block", enabled: true }];
    await api.automod.set("ROOM", rules);
    expect(calls[1]).toMatchObject({ url: "https://n.example/api/v1/rooms/ROOM/automod", method: "PUT", body: { rules } });
  });

  it("transfers a room and lists the node's rooms for admins", async () => {
    const { api, calls } = fetchMock([]);
    await api.rooms.transfer("ROOM", "U2");
    expect(calls[0]).toMatchObject({ url: "https://n.example/api/v1/rooms/ROOM/transfer", method: "POST", body: { user_id: "U2" } });
    await api.admin.rooms({ q: "gui", limit: 10 });
    expect(calls[1]!.url).toBe("https://n.example/api/v1/admin/rooms?q=gui&limit=10");
  });
});
