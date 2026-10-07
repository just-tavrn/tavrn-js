// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TavrnSocket } from "../src/socket";

/** Minimal WebSocket stand-in that simulates the node's frames. */
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  readyState = 0;
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((m: { data: string }) => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) {
    FakeWebSocket.instances.push(this);
  }
  send(data: string) {
    this.sent.push(data);
  }
  close(code = 1000, reason = "") {
    this.readyState = 3;
    (this.onclose as ((ev: { code: number; reason: string }) => void) | null)?.({ code, reason });
  }
  // Testhilfen
  serverOpen() {
    this.readyState = 1;
    this.onopen?.();
  }
  serverSend(frame: unknown) {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }
}

describe("TavrnSocket", () => {
  beforeEach(() => {
    FakeWebSocket.instances = [];
    vi.useFakeTimers();
  });
  afterEach(() => vi.useRealTimers());

  function make(overrides: Partial<ConstructorParameters<typeof TavrnSocket>[0]> = {}) {
    const statuses: string[] = [];
    const events: unknown[] = [];
    const socket = new TavrnSocket({
      url: "ws://x/api/v1/ws",
      getToken: () => "tok",
      WebSocketImpl: FakeWebSocket as unknown as typeof WebSocket,
      onStatus: (s) => statuses.push(s),
      onEvent: (e) => events.push(e),
      ...overrides,
    });
    return { socket, statuses, events };
  }

  it("sends hello, becomes ready and dispatches events", async () => {
    const { socket, statuses, events } = make();
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    const ws = FakeWebSocket.instances[0]!;
    ws.serverOpen();
    expect(JSON.parse(ws.sent[0]!)).toMatchObject({ op: "hello", token: "tok" });
    ws.serverSend({ op: "ready", session_id: "s1" });
    expect(socket.status).toBe("ready");
    expect(socket.sessionId).toBe("s1");
    const seen: unknown[] = [];
    socket.on("message.create", (d) => seen.push(d));
    ws.serverSend({ op: "event", id: "e1", type: "message.create", data: { id: "m1" } });
    expect(seen).toEqual([{ id: "m1" }]);
    expect(events).toHaveLength(1);
    ws.serverSend({ op: "ping" });
    expect(JSON.parse(ws.sent.at(-1)!)).toEqual({ op: "pong" });
    expect(statuses).toEqual(["connecting", "ready"]);
  });

  it("sends typing hints for channels and direct messages", async () => {
    const { socket } = make();
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    const ws = FakeWebSocket.instances[0]!;
    ws.serverOpen();
    ws.serverSend({ op: "ready", session_id: "s1" });
    socket.typing("R", "C");
    socket.typingIn("D");
    expect(ws.sent.slice(-2).map((s) => JSON.parse(s))).toEqual([
      { op: "typing", room_id: "R", channel_id: "C" },
      { op: "typing", conversation_id: "D" },
    ]);
  });

  it("reconnects with backoff after a drop, but not after an auth error", async () => {
    const onAuthFailure = vi.fn();
    const { socket } = make({ onAuthFailure });
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    FakeWebSocket.instances[0]!.close(1006);
    expect(socket.status).toBe("reconnecting");
    await vi.advanceTimersByTimeAsync(2000);
    expect(FakeWebSocket.instances).toHaveLength(2);
    FakeWebSocket.instances[1]!.close(4001);
    expect(onAuthFailure).toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it("refreshes once on 4001 and reconnects with the new token", async () => {
    let token = "old";
    const onAuthFailure = vi.fn();
    const refreshToken = vi.fn(async () => {
      token = "new";
      return token;
    });
    const { socket } = make({ getToken: () => token, refreshToken, onAuthFailure });
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    FakeWebSocket.instances[0]!.serverOpen();
    FakeWebSocket.instances[0]!.close(4001, "auth.token_expired");
    await vi.runOnlyPendingTimersAsync();
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(onAuthFailure).not.toHaveBeenCalled();
    expect(FakeWebSocket.instances).toHaveLength(2);
    const ws = FakeWebSocket.instances[1]!;
    ws.serverOpen();
    expect(JSON.parse(ws.sent[0]!)).toMatchObject({ op: "hello", token: "new" });
    ws.serverSend({ op: "ready", session_id: "s2" });
    expect(socket.status).toBe("ready");
    // A later expiry refreshes again (the counter resets with `ready`).
    ws.close(4001, "auth.token_expired");
    await vi.runOnlyPendingTimersAsync();
    expect(refreshToken).toHaveBeenCalledTimes(2);
    expect(onAuthFailure).not.toHaveBeenCalled();
  });

  it("ends the session when the refresh is refused or 4001 follows right after a refresh", async () => {
    const onAuthFailure = vi.fn();
    const { socket } = make({ refreshToken: async () => null, onAuthFailure });
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    FakeWebSocket.instances[0]!.close(4001, "auth.token_expired");
    await vi.runOnlyPendingTimersAsync();
    expect(onAuthFailure).toHaveBeenCalledTimes(1);
    expect(socket.status).toBe("closed");

    const second = vi.fn();
    const refresh = vi.fn(async () => "fresh");
    const s2 = make({ refreshToken: refresh, onAuthFailure: second }).socket;
    FakeWebSocket.instances = [];
    s2.connect();
    await vi.runOnlyPendingTimersAsync();
    FakeWebSocket.instances[0]!.close(4001, "auth.token_invalid");
    await vi.runOnlyPendingTimersAsync();
    FakeWebSocket.instances[1]!.close(4001, "auth.token_invalid");
    await vi.runOnlyPendingTimersAsync();
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(second).toHaveBeenCalledTimes(1);

    const third = vi.fn();
    const never = vi.fn(async () => "x");
    const s3 = make({ refreshToken: never, onAuthFailure: third }).socket;
    FakeWebSocket.instances = [];
    s3.connect();
    await vi.runOnlyPendingTimersAsync();
    FakeWebSocket.instances[0]!.close(4001, "auth.account_disabled");
    expect(never).not.toHaveBeenCalled();
    expect(third).toHaveBeenCalledTimes(1);
  });

  it("keeps the session when the refresh fails for network reasons and retries later", async () => {
    const onAuthFailure = vi.fn();
    let fail = true;
    const refreshToken = vi.fn(async () => {
      if (fail) throw new Error("offline");
      return "new";
    });
    const { socket } = make({ refreshToken, onAuthFailure });
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    FakeWebSocket.instances[0]!.close(4001, "auth.token_expired");
    await vi.advanceTimersByTimeAsync(0);
    expect(socket.status).toBe("reconnecting");
    expect(onAuthFailure).not.toHaveBeenCalled();
    fail = false;
    await vi.advanceTimersByTimeAsync(2000);
    expect(FakeWebSocket.instances).toHaveLength(2);
    FakeWebSocket.instances[1]!.close(4001, "auth.token_expired");
    await vi.runOnlyPendingTimersAsync();
    expect(refreshToken).toHaveBeenCalledTimes(2);
    expect(onAuthFailure).not.toHaveBeenCalled();
    expect(FakeWebSocket.instances).toHaveLength(3);
  });

  it("reloads on a resync hint at any time and keeps the connection", async () => {
    let resyncs = 0;
    const { socket, statuses, events } = make({ onResync: () => (resyncs += 1) });
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    const ws = FakeWebSocket.instances[0]!;
    ws.serverOpen();
    ws.serverSend({ op: "ready", session_id: "s1" });
    ws.serverSend({ op: "event", id: "e1", type: "message.create", data: { id: "m1" } });
    // Mid-session (a node with several instances lost events on its bus): reload, the connection stays.
    ws.serverSend({ op: "resync" });
    expect(resyncs).toBe(1);
    expect(socket.status).toBe("ready");
    expect(ws.readyState).toBe(1);
    ws.serverSend({ op: "event", id: "e2", type: "message.create", data: { id: "m2" } });
    expect(events).toHaveLength(2);
    expect(statuses).toEqual(["connecting", "ready"]);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it("does not reconnect when a newer connection of the same app token replaced it (4004)", async () => {
    const closes: number[] = [];
    const { socket, statuses } = make({ onClose: (code) => closes.push(code) });
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    const ws = FakeWebSocket.instances[0]!;
    ws.serverOpen();
    ws.serverSend({ op: "ready", session_id: "s1" });
    ws.close(4004, "replaced");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(closes).toEqual([4004]);
    expect(statuses.at(-1)).toBe("closed");
    expect(socket.status).toBe("closed");
  });

  it("reports every close code to onClose and keeps reconnecting after ordinary closes", async () => {
    const closes: number[] = [];
    const { socket } = make({ onClose: (code) => closes.push(code) });
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    FakeWebSocket.instances[0]!.close(1006);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(closes).toEqual([1006]);
    expect(FakeWebSocket.instances.length).toBeGreaterThan(1);
    socket.close();
  });

  it("close() stops reconnections", async () => {
    const { socket } = make();
    socket.connect();
    await vi.runOnlyPendingTimersAsync();
    socket.close();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(socket.status).toBe("closed");
  });
});
