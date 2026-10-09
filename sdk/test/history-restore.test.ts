// SPDX-License-Identifier: Apache-2.0
// History restore after a key reset (ENCRYPTION.md §7b): request routes and the permission bit.
import { describe, expect, it, vi } from "vitest";
import { ALL_PERMISSIONS, EVERYONE_RESTRICTED, PERMISSION_LABELS, Permission, SCOPES, TavrnApi, isEveryoneRestricted, scopeMask } from "../src";

function fetchMock(body: unknown = {}, status = 200) {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  const impl = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(String(init.body)) : undefined });
    return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  });
  return { api: new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl as unknown as typeof fetch }), calls };
}

describe("history restore requests", () => {
  it("asks, reads the own state, lists, decides and cancels", async () => {
    const { api, calls } = fetchMock({ id: "H1", status: "open", items: [] });
    await api.historyRequests.create("ROOM", "It is me");
    expect(calls[0]).toMatchObject({ url: "https://n.example/api/v1/rooms/ROOM/history-requests", method: "POST", body: { message: "It is me" } });
    await api.historyRequests.mine("ROOM");
    expect(calls[1]).toMatchObject({ url: "https://n.example/api/v1/rooms/ROOM/history-requests/mine", method: "GET" });
    await api.historyRequests.list("ROOM");
    expect(calls[2]).toMatchObject({ url: "https://n.example/api/v1/rooms/ROOM/history-requests", method: "GET" });
    await api.historyRequests.approve("ROOM", "H1", { partial: true });
    expect(calls[3]).toMatchObject({ url: "https://n.example/api/v1/rooms/ROOM/history-requests/H1/approve", method: "POST", body: { partial: true } });
    await api.historyRequests.deny("ROOM", "H/1", "Call me first");
    expect(calls[4]).toMatchObject({ url: "https://n.example/api/v1/rooms/ROOM/history-requests/H%2F1/deny", method: "POST", body: { reason: "Call me first" } });
  });

  it("cancels with a DELETE", async () => {
    const { api, calls } = fetchMock(undefined, 204);
    await expect(api.historyRequests.cancel("ROOM", "H1")).resolves.toBeUndefined();
    expect(calls[0]).toMatchObject({ url: "https://n.example/api/v1/rooms/ROOM/history-requests/H1", method: "DELETE" });
  });
});

describe("restore_history (bit 37)", () => {
  it("is management-class, never a bot scope, and labelled", () => {
    expect(Permission.RESTORE_HISTORY).toBe(1n << 37n);
    expect(isEveryoneRestricted("RESTORE_HISTORY")).toBe(true);
    expect(EVERYONE_RESTRICTED).toBe(4611686268363406212n);
    expect(ALL_PERMISSIONS & Permission.RESTORE_HISTORY).toBe(Permission.RESTORE_HISTORY);
    expect(scopeMask(SCOPES.map(([s]) => s)) & Permission.RESTORE_HISTORY).toBe(0n);
    expect(PERMISSION_LABELS.find((l) => l.name === "RESTORE_HISTORY")?.label).toBe("Restore history after a key reset");
  });
});
