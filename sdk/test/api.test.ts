// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi, TavrnApiError } from "../src";

function fetchMock(responses: Array<{ status: number; body?: unknown }>) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let i = 0;
  const impl = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const r = responses[Math.min(i++, responses.length - 1)]!;
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status, headers: { "Content-Type": "application/json" } });
  });
  return { impl: impl as unknown as typeof fetch, calls };
}

describe("TavrnApi", () => {
  it("sets the token, client header and query parameters", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: [] }]);
    const api = new TavrnApi({ baseUrl: "https://n.example/", getToken: () => "tok", clientHeader: "web/0.1", fetchImpl: impl });
    await api.messages.list("r1", "c1", { limit: 20, before: "m9" });
    expect(calls[0]!.url).toBe("https://n.example/api/v1/rooms/r1/channels/c1/messages?limit=20&before=m9");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer tok");
    expect(headers["Tavrn-Client"]).toBe("web/0.1");
  });

  it("throws TavrnApiError with Problem Details and handles 204", async () => {
    const { impl } = fetchMock([
      { status: 403, body: { type: "x", title: "Forbidden", status: 403, detail: "missing", code: "room.not_member" } },
      { status: 204 },
    ]);
    const api = new TavrnApi({ fetchImpl: impl });
    const err = await api.rooms.get("r1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TavrnApiError);
    expect((err as TavrnApiError).code).toBe("room.not_member");
    await expect(api.rooms.leave("r1")).resolves.toBeUndefined();
  });

  it("retries once with a fresh token after 401", async () => {
    const { impl, calls } = fetchMock([{ status: 401, body: { code: "auth.token_expired", status: 401, title: "", detail: "", type: "" } }, { status: 200, body: { id: "u1" } }]);
    let token = "alt";
    const api = new TavrnApi({ getToken: () => token, refreshToken: async () => (token = "neu"), fetchImpl: impl });
    const me = await api.users.me();
    expect(me).toEqual({ id: "u1" });
    expect(calls).toHaveLength(2);
    expect((calls[1]!.init.headers as Record<string, string>).Authorization).toBe("Bearer neu");
  });

  it("asks for a re-authentication on auth.reauth_required and repeats the request once with the reauth token", async () => {
    const required = { status: 403, body: { code: "auth.reauth_required", status: 403, title: "", detail: "", type: "", meta: { methods: ["password", "webauthn"] } } };
    const { impl, calls } = fetchMock([required, { status: 204 }, required, required]);
    let reauth: string | null = null;
    const onReauthRequired = vi.fn(async (methods: string[]) => {
      expect(methods).toEqual(["password", "webauthn"]);
      reauth = "rt";
      return true;
    });
    const api = new TavrnApi({ getToken: () => "tok", reauthToken: () => reauth, onReauthRequired, fetchImpl: impl });
    await api.users.deleteDevice("D1");
    expect(calls).toHaveLength(2);
    expect((calls[0]!.init.headers as Record<string, string>)["Tavrn-Reauth"]).toBeUndefined();
    expect((calls[1]!.init.headers as Record<string, string>)["Tavrn-Reauth"]).toBe("rt");
    // Refused again after the confirmation: the error surfaces, no loop.
    await expect(api.users.deleteDevice("D2")).rejects.toMatchObject({ code: "auth.reauth_required" });
    expect(onReauthRequired).toHaveBeenCalledTimes(2);
    expect(calls).toHaveLength(4);
    // A cancelled dialog surfaces the error right away.
    const cancel = new TavrnApi({ getToken: () => "tok", onReauthRequired: async () => false, fetchImpl: fetchMock([required]).impl });
    await expect(cancel.users.deleteDevice("D3")).rejects.toMatchObject({ code: "auth.reauth_required" });
  });

  it("sends a direct invite for a user of any node and claims KeyPackages by address", async () => {
    const { impl, calls } = fetchMock([{ status: 202, body: { invite: { code: "abc" } } }, { status: 200, body: { key_packages: [] } }]);
    const api = new TavrnApi({ baseUrl: "https://b.example", getToken: () => "tok", fetchImpl: impl });
    expect((await api.invites.direct("R1", "alice@a.example")).invite.code).toBe("abc");
    expect(calls[0]!.url).toBe("https://b.example/api/v1/rooms/R1/invites/direct");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ user: "alice@a.example" });
    await api.keys.claim("alice@a.example");
    expect(calls[1]!.url).toBe("https://b.example/api/v1/users/alice%40a.example/key-packages/claim");
  });

  it("manages applications and their tokens (APPLICATIONS.md §1.6, §2.2)", async () => {
    const { impl, calls } = fetchMock([
      { status: 201, body: { id: "A1", name: "Bot" } },
      { status: 201, body: { token: { id: "T1" }, secret: "eyJ.x.y" } },
      { status: 200, body: { token: { id: "T1" }, secret: "eyJ.new.y" } },
      { status: 204 },
      { status: 204 },
      { status: 202 },
      { status: 200, body: { secret: "s", expires_at: "x" } },
      { status: 200, body: { id: "C1", no_bots: true } },
    ]);
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    await api.applications.create({ name: "Bot", scopes: ["messages:read"] });
    expect(calls[0]!.url).toBe("https://n.example/api/v1/applications");
    expect((await api.applications.createToken("A1", { name: "main", expires_in_days: 30 })).secret).toBe("eyJ.x.y");
    expect(calls[1]!.url).toBe("https://n.example/api/v1/applications/A1/tokens");
    expect((await api.applications.resetToken("A1", "T1")).secret).toBe("eyJ.new.y");
    expect(calls[2]!.url).toBe("https://n.example/api/v1/applications/A1/tokens/T1/reset");
    await api.applications.revokeToken("A1", "T1");
    expect(calls[3]!.init.method).toBe("DELETE");
    await api.applications.delete("A1", "Bot");
    expect([calls[4]!.init.method, JSON.parse(String(calls[4]!.init.body))]).toEqual(["DELETE", { name: "Bot" }]);
    await api.applications.transfer("A1", "bob");
    expect(calls[5]!.url).toBe("https://n.example/api/v1/applications/A1/transfer");
    await api.applications.rotate();
    expect(calls[6]!.url).toBe("https://n.example/api/v1/applications/me/tokens/rotate");
    await api.channels.updateCategory("R1", "C1", { no_bots: true });
    expect([calls[7]!.url, calls[7]!.init.method]).toEqual(["https://n.example/api/v1/rooms/R1/categories/C1", "PATCH"]);
  });

  it("clears a channel's own overrides one by one (\"Reset to category\", layered overrides)", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: [] }]);
    const api = new TavrnApi({ baseUrl: "https://n.example", fetchImpl: impl });
    await api.channels.clearOverrides("R1", [
      { target_type: "channel", target_id: "C1", subject_type: "role", subject_id: "r0" },
      { target_type: "channel", target_id: "C1", subject_type: "member", subject_id: "u1" },
    ]);
    expect(calls.map((c) => [c.init.method, c.url])).toEqual([
      ["PUT", "https://n.example/api/v1/rooms/R1/overrides"],
      ["PUT", "https://n.example/api/v1/rooms/R1/overrides"],
    ]);
    expect(JSON.parse(calls[1]!.init.body as string)).toEqual({ target_type: "channel", target_id: "C1", subject_type: "member", subject_id: "u1", allow: "0", deny: "0", upload_allow: [], upload_deny: [] });
  });

  it("sends ephemeral events and reads the whiteboard session", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: { session: null } }, { status: 200, body: { session: { owner: "a@n" } } }]);
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    await api.ephemeral.send("C1", { type: "whiteboard.open", content: "AQ", session: { open_for_all: true, grants: [] } });
    expect(calls[0]!.url).toBe("https://n.example/api/v1/conversations/C1/ephemeral");
    expect(calls[0]!.init.method).toBe("POST");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ type: "whiteboard.open", content: "AQ", session: { open_for_all: true, grants: [] } });
    expect((await api.ephemeral.session("C1")).session?.owner).toBe("a@n");
    expect(calls[1]!.url).toBe("https://n.example/api/v1/conversations/C1/whiteboard");
  });

  it("stores scenes as binary blobs with a percent-encoded name", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const impl = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      if (init.method === "GET") return new Response(new Uint8Array([1, 2, 3]), { status: 200 });
      return new Response(JSON.stringify({ id: "S1", name: "Raid ä" }), { status: 201 });
    }) as unknown as typeof fetch;
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    const info = await api.whiteboards.put("S1", new Uint8Array([1, 9]), "Raid ä");
    expect(info.name).toBe("Raid ä");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["Tavrn-Scene-Name"]).toBe("Raid%20%C3%A4");
    expect(headers.Authorization).toBe("Bearer tok");
    expect(calls[0]!.url).toBe("https://n.example/api/v1/users/me/whiteboards/S1");
    expect(Array.from((await api.whiteboards.get("S1"))!)).toEqual([1, 2, 3]);
    await api.whiteboards.put("S1", new Uint8Array([1]));
    expect((calls[2]!.init.headers as Record<string, string>)["Tavrn-Scene-Name"]).toBeUndefined();
  });

  it("lists the reactors of an emoji with a percent-encoded emoji and the paging cursor", async () => {
    const page = { items: [{ user: "alice@n.example", user_id: "U1", created_at: "2026-10-15T10:00:00.000Z" }], next: "c1" };
    const { impl, calls } = fetchMock([{ status: 200, body: page }, { status: 200, body: { items: [], next: null } }]);
    const api = new TavrnApi({ baseUrl: "https://n.example", fetchImpl: impl });
    await expect(api.reactions.list("C", "M", "👍", { limit: 1 })).resolves.toEqual(page);
    expect(calls[0]!.url).toBe("https://n.example/api/v1/conversations/C/messages/M/reactions/%F0%9F%91%8D?limit=1");
    expect(calls[0]!.init.method).toBe("GET");
    await api.reactions.list("C", "M", "<:party:01J00000000000000000000000>", { after: "c1" });
    expect(calls[1]!.url).toBe("https://n.example/api/v1/conversations/C/messages/M/reactions/%3C%3Aparty%3A01J00000000000000000000000%3E?after=c1");
  });

  it("reports network errors as network.error", async () => {
    const api = new TavrnApi({ fetchImpl: (async () => { throw new Error("offline"); }) as unknown as typeof fetch });
    const err = await api.node.info().catch((e: unknown) => e as TavrnApiError);
    expect(err.code).toBe("network.error");
    expect(err.status).toBe(0);
  });

  it("reads and writes backups as binary with ETag/If-Match and reports 404 as null", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const impl = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      if (init.method === "GET" && calls.length === 1) return new Response(JSON.stringify({ code: "backup.not_found", status: 404, title: "", detail: "", type: "" }), { status: 404 });
      if (init.method === "GET") return new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { ETag: '"abc"' } });
      return new Response(JSON.stringify({ conversation: "n.example/C", size: 3, etag: '"def"', updated_at: "" }), { status: 200 });
    }) as unknown as typeof fetch;
    const api = new TavrnApi({ getToken: () => "tok", fetchImpl: impl });
    expect(await api.backups.get("n.example", "C")).toBeNull();
    const got = await api.backups.get("n.example", "C");
    expect(Array.from(got!.blob)).toEqual([1, 2, 3]);
    expect(got!.etag).toBe('"abc"');
    await api.backups.put("n.example", "C", new Uint8Array([9]), got!.etag);
    const put = calls[2]!;
    // Same origin (no base URL): binary routes resolve like the JSON routes.
    expect(new URL(put.url).pathname).toBe("/api/v1/users/me/backups/n.example/C");
    expect((put.init.headers as Record<string, string>)["If-Match"]).toBe('"abc"');
    expect((put.init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
    await api.backups.put("n.example", "D", new Uint8Array([9]), null);
    expect((calls[3]!.init.headers as Record<string, string>)["If-Match"]).toBeUndefined();
  });

  it("calls the MLS delivery service and the conversation routes", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: { items: [], next: null } }]);
    const api = new TavrnApi({ baseUrl: "https://n.example", fetchImpl: impl });
    await api.mls.log("C", 7);
    await api.mls.postCommit("C", { epoch: 7, commit: "x", group_info: "y", welcome: null });
    await api.keys.claim("bob");
    await api.conversations.send("C", { content: "abc", epoch: 7, attachments: ["B"] });
    await api.friends.request("bob@n.example");
    await api.conversations.markRead("C", "M9");
    expect(JSON.parse(String(calls.at(-1)!.init.body))).toEqual({ last_read_message_id: "M9" });
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      "GET https://n.example/api/v1/conversations/C/mls/messages?since_epoch=7&limit=100",
      "POST https://n.example/api/v1/conversations/C/mls/commits",
      "POST https://n.example/api/v1/users/bob/key-packages/claim",
      "POST https://n.example/api/v1/conversations/C/messages",
      "POST https://n.example/api/v1/users/me/friends/requests",
      "PUT https://n.example/api/v1/conversations/C/read",
    ]);
  });
});


describe("notification settings", () => {
  it("reads and writes the settings of the home node", async () => {
    const settings = { global: { mode: "mentions" as const, sound: true, browser: false }, rooms: { r1: { muted_until: "9999-12-31T00:00:00Z" } }, channels: { c1: { mode: "all" as const } } };
    const { impl, calls } = fetchMock([{ status: 200, body: settings }, { status: 200, body: settings }]);
    const api = new TavrnApi({ baseUrl: "https://n.example", fetchImpl: impl });
    expect(await api.users.notificationSettings()).toEqual(settings);
    await api.users.putNotificationSettings(settings);
    expect(calls[0]!.url).toBe("https://n.example/api/v1/users/me/notification-settings");
    expect(calls[1]!.init.method).toBe("PUT");
    expect(JSON.parse(calls[1]!.init.body as string)).toEqual(settings);
  });

  it("the report push switch and the mail language travel with the settings and the account", async () => {
    const settings = { global: { mode: "all" as const, sound: true, browser: false, reports: false }, rooms: {}, channels: {} };
    const me = { id: "u1", username: "a", locale: "de" };
    const { impl, calls } = fetchMock([{ status: 200, body: settings }, { status: 200, body: me }]);
    const api = new TavrnApi({ baseUrl: "https://n.example", fetchImpl: impl });
    await api.users.putNotificationSettings(settings);
    expect(JSON.parse(calls[0]!.init.body as string).global.reports).toBe(false);
    const updated = await api.users.updateMe({ locale: "de" });
    expect(calls[1]!.init.method).toBe("PATCH");
    expect(JSON.parse(calls[1]!.init.body as string)).toEqual({ locale: "de" });
    expect(updated.locale).toBe("de");
  });

  it("web push: VAPID key, subscribe, list, unsubscribe and the test push", async () => {
    const registration = { id: "s1", device_id: "d1", push_service: "https://push.example", current_device: true, created_at: "2026-10-07T00:00:00.000Z", failures: 0 };
    const { impl, calls } = fetchMock([
      { status: 200, body: { enabled: true, public_key: "BKey" } },
      { status: 201, body: registration },
      { status: 200, body: [registration] },
      { status: 204 },
      { status: 202 },
    ]);
    const api = new TavrnApi({ baseUrl: "https://n.example", fetchImpl: impl });
    expect(await api.push.vapid()).toEqual({ enabled: true, public_key: "BKey" });
    const subscription = { endpoint: "https://push.example/abc", keys: { p256dh: "p", auth: "a" }, expiration_time: null };
    expect(await api.push.subscribe(subscription)).toEqual(registration);
    expect(await api.push.subscriptions()).toEqual([registration]);
    await api.push.unsubscribe("s/1");
    await api.push.test();
    expect(calls.map((c) => `${c.init.method ?? "GET"} ${c.url}`)).toEqual([
      "GET https://n.example/api/v1/push/vapid",
      "PUT https://n.example/api/v1/users/me/push-subscriptions",
      "GET https://n.example/api/v1/users/me/push-subscriptions",
      "DELETE https://n.example/api/v1/users/me/push-subscriptions/s%2F1",
      "POST https://n.example/api/v1/users/me/push-subscriptions/test",
    ]);
    expect(JSON.parse(calls[1]!.init.body as string)).toEqual(subscription);
  });
});
