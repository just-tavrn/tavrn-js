// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi } from "../src";

describe("conformance API (FEDERATION.md §9)", () => {
  it("calls the peer state and the admin peer routes", async () => {
    const calls: Array<{ url: string; method: string; body: unknown }> = [];
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : undefined });
      return new Response(JSON.stringify({}), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    const api = new TavrnApi({ baseUrl: "https://a.test", fetchImpl: fetchImpl as unknown as typeof fetch });
    await api.federation.peerState("b.test");
    await api.admin.federationPeers({ after: "a.example", limit: 50 });
    await api.admin.checkPeer("b.test");
    await api.admin.blockPeer("b.test", "spam");
    await api.admin.blockPeer("c.test");
    await api.admin.unblockPeer("b.test");
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "GET https://a.test/api/v1/federation/peers/b.test/state",
      "GET https://a.test/api/v1/admin/federation/peers?after=a.example&limit=50",
      "POST https://a.test/api/v1/admin/federation/peers/b.test/check",
      "POST https://a.test/api/v1/admin/federation/peers/b.test/block",
      "POST https://a.test/api/v1/admin/federation/peers/c.test/block",
      "POST https://a.test/api/v1/admin/federation/peers/b.test/unblock",
    ]);
    expect(calls[3]!.body).toEqual({ reason: "spam" });
    expect(calls[4]!.body).toEqual({ reason: "" });
  });
});
