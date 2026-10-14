// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi, TavrnApiError } from "../src";

function fetchMock(responses: Array<{ status: number; body?: unknown; raw?: BodyInit; type?: string }>) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let i = 0;
  const impl = vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init });
    const r = responses[Math.min(i++, responses.length - 1)]!;
    const body = r.raw ?? (r.body === undefined ? null : JSON.stringify(r.body));
    return new Response(body, { status: r.status, headers: { "Content-Type": r.type ?? "application/json" } });
  });
  return { impl: impl as unknown as typeof fetch, calls };
}

const headersOf = (init: RequestInit) => init.headers as Record<string, string>;

describe("voice API (VOICE.md)", () => {
  it("joins, reports the own state, leaves and lists the room's voice channels", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: { token: "lk", epoch: 3 } }, { status: 200, body: { participants: [] } }, { status: 204 }, { status: 200, body: { items: [] } }]);
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    expect((await api.voice.join("R", "C")).token).toBe("lk");
    expect(calls[0]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/voice/join");
    expect(calls[0]!.init.method).toBe("POST");
    await api.voice.updateState("R", "C", { muted: true, deafened: false });
    expect(calls[1]!.init.method).toBe("PATCH");
    expect(calls[1]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/voice/state");
    expect(JSON.parse(String(calls[1]!.init.body))).toEqual({ muted: true, deafened: false });
    await expect(api.voice.leave("R", "C")).resolves.toBeUndefined();
    expect(calls[2]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/voice/leave");
    expect((await api.voice.roomStates("R")).items).toEqual([]);
    expect(calls[3]!.url).toBe("https://n.example/api/v1/rooms/R/voice");
  });

  it("carries the session start of a channel and sets a voice channel's status through the channel update (§5, §2a)", async () => {
    const { impl, calls } = fetchMock([
      { status: 200, body: { token: "lk", epoch: 3, session_started_at: "2026-10-14T12:00:00.000Z", participants: [] } },
      { status: 200, body: { items: [{ room_id: "R", channel_id: "C", epoch: 3, session_started_at: null, participants: [] }] } },
      { status: 200, body: { id: "C", kind: "voice", status: "Raid night" } },
    ]);
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    expect((await api.voice.join("R", "C")).session_started_at).toBe("2026-10-14T12:00:00.000Z");
    const states = await api.voice.roomStates("R");
    expect(states.items[0]!.session_started_at).toBeNull();
    const channel = await api.channels.update("R", "C", { status: "Raid night" });
    expect(channel.status).toBe("Raid night");
    expect(calls[2]!.init.method).toBe("PATCH");
    expect(calls[2]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C");
    expect(JSON.parse(String(calls[2]!.init.body))).toEqual({ status: "Raid night" });
  });

  it("joins and leaves as the device's screen publisher with the role in the body, the device without a body (§4b)", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: { token: "lk", identity: "a@n.example/D#screen" } }, { status: 204 }, { status: 200, body: { token: "c" } }, { status: 204 }, { status: 200, body: { token: "d" } }, { status: 204 }]);
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    expect((await api.voice.join("R", "C", "screen")).identity).toBe("a@n.example/D#screen");
    expect(calls[0]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/voice/join");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ role: "screen" });
    await api.voice.leave("R", "C", "screen");
    expect(calls[1]!.url).toBe("https://n.example/api/v1/rooms/R/channels/C/voice/leave");
    expect(JSON.parse(String(calls[1]!.init.body))).toEqual({ role: "screen" });
    await api.calls.join("V", "screen");
    expect(calls[2]!.url).toBe("https://n.example/api/v1/conversations/V/call/join");
    expect(JSON.parse(String(calls[2]!.init.body))).toEqual({ role: "screen" });
    await api.calls.leave("V", "screen");
    expect(JSON.parse(String(calls[3]!.init.body))).toEqual({ role: "screen" });
    // The device itself sends no role, as before (older nodes know none).
    await api.calls.join("V");
    expect(JSON.parse(String(calls[4]!.init.body))).toEqual({});
    await api.voice.leave("R", "C");
    expect(JSON.parse(String(calls[5]!.init.body))).toEqual({});
  });

  it("loads the voice state of all rooms at once (GET /users/me/voice)", async () => {
    const rooms = [{ room_id: "R", channels: [{ room_id: "R", channel_id: "C", epoch: 1, participants: [] }] }];
    const { impl, calls } = fetchMock([{ status: 200, body: { rooms } }]);
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    expect((await api.voice.mine()).rooms).toEqual(rooms);
    expect(calls[0]!.url).toBe("https://n.example/api/v1/users/me/voice");
    expect(calls[0]!.init.method ?? "GET").toBe("GET");
  });

  it("moderates by user address (encoded) and passes problem codes with meta through", async () => {
    const { impl, calls } = fetchMock([
      { status: 200, body: { participants: [] } },
      { status: 204 },
      { status: 204 },
      { status: 409, body: { type: "x", title: "full", status: 409, detail: "", code: "voice.channel_full", meta: { user_limit: 1 } } },
    ]);
    const api = new TavrnApi({ fetchImpl: impl, getToken: () => "tok" });
    await api.voice.serverMute("R", "C", "bob@b.example", true);
    expect(calls[0]!.url).toContain("/rooms/R/channels/C/voice/members/bob%40b.example/mute");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ muted: true });
    await api.voice.disconnect("R", "C", "bob@b.example");
    expect(calls[1]!.url).toContain("/voice/members/bob%40b.example/disconnect");
    await api.voice.move("R", "C", "bob@b.example", "C2");
    expect(JSON.parse(String(calls[2]!.init.body))).toEqual({ channel_id: "C2" });
    const err = (await api.voice.join("R", "C").catch((e: unknown) => e)) as TavrnApiError;
    expect(err.code).toBe("voice.channel_full");
    expect((err.problem as { meta?: { user_limit?: number } }).meta?.user_limit).toBe(1);
  });
});

describe("soundboard API (VOICE.md §8)", () => {
  it("lists, uploads with percent-encoded name and duration, fetches audio and deletes", async () => {
    const { impl, calls } = fetchMock([
      { status: 200, body: [] },
      { status: 201, body: { id: "S1", name: "Tusch 🎺" } },
      { status: 200, raw: new Uint8Array([1, 2, 3]), type: "audio/ogg" },
      { status: 204 },
    ]);
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    expect(await api.soundboard.list("R")).toEqual([]);
    const clip = new Blob([new Uint8Array([9])], { type: "audio/ogg" });
    expect((await api.soundboard.create("R", "Tusch 🎺", clip, 1234.4)).id).toBe("S1");
    const h = headersOf(calls[1]!.init);
    expect(calls[1]!.url).toBe("https://n.example/api/v1/rooms/R/soundboard");
    expect(h["Content-Type"]).toBe("audio/ogg");
    expect(h["Tavrn-Sound-Name"]).toBe("Tusch%20%F0%9F%8E%BA");
    expect(h["Tavrn-Sound-Duration-Ms"]).toBe("1234");
    expect(h.Authorization).toBe("Bearer tok");
    const audio = await api.soundboard.audio("R", "S1");
    expect(new Uint8Array(await audio.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    expect(calls[2]!.url).toBe("https://n.example/api/v1/rooms/R/soundboard/S1/audio");
    await api.soundboard.delete("R", "S1");
    expect(calls[3]!.init.method).toBe("DELETE");
  });

  it("clamps the declared duration to 1–5000 ms and reports upload errors as TavrnApiError", async () => {
    const { impl, calls } = fetchMock([
      { status: 201, body: { id: "S2" } },
      { status: 413, body: { type: "x", title: "t", status: 413, detail: "", code: "soundboard.too_large" } },
    ]);
    const api = new TavrnApi({ fetchImpl: impl });
    await api.soundboard.create("R", "x", new Blob([new Uint8Array([1])], { type: "audio/ogg" }), 9000);
    expect(headersOf(calls[0]!.init)["Tavrn-Sound-Duration-Ms"]).toBe("5000");
    const err = (await api.soundboard.create("R", "x", new Blob([new Uint8Array([1])], { type: "audio/ogg" }), 100).catch((e: unknown) => e)) as TavrnApiError;
    expect(err).toBeInstanceOf(TavrnApiError);
    expect(err.code).toBe("soundboard.too_large");
  });
});
