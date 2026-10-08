// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { EVERYONE_RESTRICTED, Permission, TavrnApi, isEveryoneRestricted, scopeMask } from "../src";

function fetchMock(body: unknown = {}) {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  const impl = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, method: String(init.method), body: init.body === undefined ? undefined : JSON.parse(String(init.body)) });
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  return { api: new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl as unknown as typeof fetch }), calls };
}

describe("threads (PROTOCOL.md §7e)", () => {
  it("creates, lists, reads and changes threads", async () => {
    const { api, calls } = fetchMock();
    await api.threads.create("R", "C", { id: "01ARYZ6S41TSV4RRFFQ69G5FAV", title: "Plan", root_message_id: "M", message: { content: { type: "text", body: "hi" } } });
    await api.threads.list("R", "C", { archived: "all", sort: "created", tag: "T", before: "X", limit: 10 });
    await api.threads.get("TH");
    await api.threads.update("TH", { archived: true, locked: false });
    await api.threads.delete("TH");
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "POST https://n.example/api/v1/rooms/R/channels/C/threads",
      "GET https://n.example/api/v1/rooms/R/channels/C/threads?archived=all&sort=created&tag=T&before=X&limit=10",
      "GET https://n.example/api/v1/threads/TH",
      "PATCH https://n.example/api/v1/threads/TH",
      "DELETE https://n.example/api/v1/threads/TH",
    ]);
    expect(calls[0]!.body).toEqual({ id: "01ARYZ6S41TSV4RRFFQ69G5FAV", title: "Plan", root_message_id: "M", message: { content: { type: "text", body: "hi" } } });
    expect(calls[3]!.body).toEqual({ archived: true, locked: false });
  });

  it("follows, moves the read marker and pages thread messages", async () => {
    const { api, calls } = fetchMock();
    await api.threads.follow("TH");
    await api.threads.unfollow("TH");
    await api.threads.markRead("TH", "M2");
    await api.threads.followed("R");
    await api.threads.messages("C", "TH", { before: "M9", limit: 20 });
    await api.conversations.messages("C", { thread: "TH", around: "M5" });
    await api.messages.list("R", "C", { thread: "TH" });
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "POST https://n.example/api/v1/threads/TH/follow",
      "DELETE https://n.example/api/v1/threads/TH/follow",
      "PUT https://n.example/api/v1/threads/TH/read",
      "GET https://n.example/api/v1/rooms/R/followed-threads",
      "GET https://n.example/api/v1/conversations/C/messages?before=M9&limit=20&thread=TH",
      "GET https://n.example/api/v1/conversations/C/messages?thread=TH&around=M5",
      "GET https://n.example/api/v1/rooms/R/channels/C/messages?thread=TH",
    ]);
    expect(calls[2]!.body).toEqual({ last_read_message_id: "M2" });
  });

  it("escapes thread ids in paths", async () => {
    const { api, calls } = fetchMock();
    await api.threads.get("../rooms");
    expect(calls[0]!.url).toBe("https://n.example/api/v1/threads/..%2Frooms");
  });

  it("manage_threads (bit 36) is restricted for @everyone and covered by the moderation scope; create_threads (bit 6) is not", () => {
    expect(Permission.MANAGE_THREADS).toBe(1n << 36n);
    expect(Permission.CREATE_THREADS).toBe(1n << 6n);
    expect(isEveryoneRestricted(Permission.MANAGE_THREADS)).toBe(true);
    expect(isEveryoneRestricted(Permission.CREATE_THREADS)).toBe(false);
    expect(EVERYONE_RESTRICTED & Permission.CREATE_THREADS).toBe(0n);
    expect(scopeMask(["moderation"]) & Permission.MANAGE_THREADS).toBe(Permission.MANAGE_THREADS);
    expect(scopeMask(["messages:write"]) & Permission.MANAGE_THREADS).toBe(0n);
    expect(scopeMask(["messages:write"]) & Permission.CREATE_THREADS).toBe(Permission.CREATE_THREADS);
  });
});
