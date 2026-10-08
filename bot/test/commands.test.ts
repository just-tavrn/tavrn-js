// SPDX-License-Identifier: Apache-2.0
// Command handling of the bot runtime (APPLICATIONS.md §5.6–§5.8) against recorded `command.invoke` frames: the
// frames go through a real TavrnSocket (fake WebSocket) into the router, the node's routes are a fake `request`.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TavrnSocket } from "@tavrn/sdk";
import type { Decrypted, EncryptedEnvelope } from "@tavrn/e2ee";
import { CommandRouter, type CommandCrypto, type InvokeContext } from "../src/commands";
import { silentLogger } from "../src/logger";

const APP = "01J9ZK3G5M8Q2W4E6R8T0Y2AP1";
const CMD = "01J9ZK3G5M8Q2W4E6R8T0Y2CM1";
const CONV = "01J9ZK3G5M8Q2W4E6R8T0Y2CV1";
const APP_REF = `h.test/${APP}`;

/** A recorded `command.invoke` frame (the node's JSON, §5.6). */
function frame(over: Record<string, unknown> = {}) {
  return {
    op: "event",
    id: "01J9ZK3G5M8Q2W4E6R8T0Y2EV1",
    type: "command.invoke",
    data: {
      interaction_id: "01J9ZK3G5M8Q2W4E6R8T0Y2IN1",
      application_id: APP,
      command: { id: CMD, name: "weather" },
      conversation_id: CONV,
      room_id: "01J9ZK3G5M8Q2W4E6R8T0Y2RM1",
      channel_id: CONV,
      encrypted: false,
      user: "alice@t.test",
      user_id: "01J9ZK3G5M8Q2W4E6R8T0Y2US1",
      device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2DV1",
      permissions: "3",
      args: { city: "Berlin" },
      args_ciphertext: null,
      epoch: null,
      locale: "de",
      expires_at: "2026-10-06T12:15:00.000Z",
      ...over,
    },
  };
}

class FakeWebSocket {
  static last: FakeWebSocket | null = null;
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((m: { data: string }) => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) {
    FakeWebSocket.last = this;
  }
  send() {}
  close() {
    this.readyState = 3;
  }
  deliver(raw: string) {
    this.onmessage?.({ data: raw });
  }
}

interface Call {
  method: string;
  path: string;
  body: Record<string, unknown>;
}

function context(crypto: CommandCrypto | null = null, fail?: (c: Call) => Error | null) {
  const calls: Call[] = [];
  const ctx: InvokeContext = {
    node: "t.test",
    appRef: APP_REF,
    deviceId: "01J9ZK3G5M8Q2W4E6R8T0Y2BD1",
    crypto,
    request: async <T>(method: string, path: string, body?: unknown) => {
      const call = { method, path, body: body as Record<string, unknown> };
      calls.push(call);
      const err = fail?.(call);
      if (err) throw err;
      return { interaction_id: "x", outcome: (call.body?.type as string) ?? "reply", id: "01J9ZK3G5M8Q2W4E6R8T0Y2NEW" } as T;
    },
  };
  return { ctx, calls };
}

/** Feeds raw frames through a TavrnSocket into the router, as the bot runtime does. */
function wire(router: CommandRouter, ctx: InvokeContext) {
  const done: Promise<unknown>[] = [];
  const socket = new TavrnSocket({
    url: "ws://t.test/api/v1/ws",
    getToken: () => "app-token",
    WebSocketImpl: FakeWebSocket as unknown as typeof WebSocket,
    onEvent: (e) => {
      if (e.type === "command.invoke") done.push(router.handle(e.data, ctx));
    },
  });
  socket.connect();
  return { socket, done };
}

const CB = `/interactions/01J9ZK3G5M8Q2W4E6R8T0Y2IN1/callback`;
const FU = `/interactions/01J9ZK3G5M8Q2W4E6R8T0Y2IN1/messages`;

describe("commands of the bot runtime (APPLICATIONS.md §5)", () => {
  beforeEach(() => vi.useRealTimers());
  afterEach(() => vi.useRealTimers());

  it("runs the handler of a frame received on the socket and replies in an unencrypted conversation", async () => {
    const router = new CommandRouter({ logger: silentLogger });
    const seen: unknown[] = [];
    router.register("weather", async (i) => {
      seen.push({ args: i.args, user: i.user, conversation: i.conversation, locale: i.locale, encrypted: i.encrypted });
      await i.reply(`12 °C in ${String(i.args.city)}`, { mentions: ["Alice@T.test", "alice@t.test"] });
    });
    const { ctx, calls } = context();
    const { socket, done } = wire(router, ctx);
    await new Promise((r) => setTimeout(r, 0));
    FakeWebSocket.last!.deliver(JSON.stringify(frame()));
    await Promise.all(done);
    socket.close();
    expect(seen).toEqual([{ args: { city: "Berlin" }, user: "alice@t.test", conversation: `t.test/${CONV}`, locale: "de", encrypted: false }]);
    expect(calls).toEqual([{ method: "POST", path: CB, body: { type: "reply", content: { type: "text", body: "12 °C in Berlin" }, ephemeral: false, mentions: ["alice@t.test"] } }]);
  });

  it("ephemeral replies, defer with follow-ups, and reply after defer becomes a follow-up", async () => {
    const router = new CommandRouter({ logger: silentLogger });
    router.register("weather", (i) => i.ephemeral({ type: "text", body: "only you" }).then(() => undefined));
    router.register("forecast", async (i) => {
      await i.defer();
      await i.followUp("day 1");
      await i.reply("day 2", { ephemeral: true });
    });
    const { ctx, calls } = context();
    await router.handle(frame().data, ctx);
    await router.handle(frame({ command: { id: CMD, name: "forecast" } }).data, ctx);
    expect(calls.map((c) => [c.path, c.body])).toEqual([
      [CB, { type: "reply", content: { type: "text", body: "only you" }, ephemeral: true, mentions: [] }],
      [CB, { type: "defer", ephemeral: false }],
      [FU, { content: { type: "text", body: "day 1" }, ephemeral: false, mentions: [] }],
      [FU, { content: { type: "text", body: "day 2" }, ephemeral: true, mentions: [] }],
    ]);
  });

  it("commands invoked in a thread know it; replies there go into it (the node's default), replyInThread too", async () => {
    const router = new CommandRouter({ logger: silentLogger });
    const THREAD = "01J9ZK3G5M8Q2W4E6R8T0Y2TH1";
    const seen: (string | null)[] = [];
    router.register("weather", async (i) => {
      seen.push(i.threadId);
      await i.replyInThread("in the thread");
      await i.followUp("more", { threadId: "01J9ZK3G5M8Q2W4E6R8T0Y2TH2" });
    });
    const { ctx, calls } = context();
    await router.handle(frame({ thread_id: THREAD }).data, ctx);
    await router.handle(frame({ thread_id: undefined }).data, ctx);
    expect(seen).toEqual([THREAD, null]);
    expect(calls[0]).toEqual({ method: "POST", path: CB, body: { type: "reply", content: { type: "text", body: "in the thread" }, ephemeral: false, mentions: [] } });
    expect(calls[1]).toEqual({ method: "POST", path: FU, body: { content: { type: "text", body: "more" }, ephemeral: false, mentions: [], thread_id: "01J9ZK3G5M8Q2W4E6R8T0Y2TH2" } });
  });

  it("replyInThread outside a thread starts a thread in the channel and answers there, follow-ups follow", async () => {
    const router = new CommandRouter({ logger: silentLogger });
    router.register("weather", async (i) => {
      await i.replyInThread({ type: "text", body: "Forecast\nfor the week" });
      await i.followUp("day 2");
    });
    const calls: Call[] = [];
    const ctx: InvokeContext = {
      ...context().ctx,
      request: async <T>(method: string, path: string, body?: unknown) => {
        calls.push({ method, path, body: body as Record<string, unknown> });
        return (path.endsWith("/threads") ? { id: "01J9ZK3G5M8Q2W4E6R8T0Y2NEW" } : { outcome: "reply" }) as T;
      },
    };
    await router.handle(frame().data, ctx);
    expect(calls.map((c) => [c.path, c.body])).toEqual([
      ["/rooms/01J9ZK3G5M8Q2W4E6R8T0Y2RM1/channels/" + CONV + "/threads", { title: "Forecast for the week" }],
      [CB, { type: "reply", content: { type: "text", body: "Forecast\nfor the week" }, ephemeral: false, mentions: [], thread_id: "01J9ZK3G5M8Q2W4E6R8T0Y2NEW" }],
      [FU, { content: { type: "text", body: "day 2" }, ephemeral: false, mentions: [], thread_id: "01J9ZK3G5M8Q2W4E6R8T0Y2NEW" }],
    ]);
  });

  it("replyInThread needs a room channel (direct messages have no threads)", async () => {
    const router = new CommandRouter({ logger: silentLogger });
    const errors: unknown[] = [];
    router.register("weather", async (i) => {
      await i.replyInThread("x").catch((e: unknown) => errors.push(e));
      await i.reply("plain");
    });
    const { ctx, calls } = context();
    await router.handle(frame({ room_id: null, channel_id: null }).data, ctx);
    expect(errors).toHaveLength(1);
    expect((errors[0] as { code?: string }).code).toBe("not_member");
    expect(calls.map((c) => c.path)).toEqual([CB]);
  });

  it("refuses a second first answer and follow-ups before the first answer", async () => {
    const router = new CommandRouter({ logger: silentLogger });
    const errors: string[] = [];
    router.register("weather", async (i) => {
      await i.followUp("too early").catch((e: { code: string }) => errors.push(e.code));
      await i.reply("first");
      await i.reply("second").catch((e: { code: string }) => errors.push(e.code));
      await i.defer().catch((e: { code: string }) => errors.push(e.code));
    });
    const { ctx, calls } = context();
    await router.handle(frame().data, ctx);
    expect(errors).toEqual(["interaction_answered", "interaction_answered", "interaction_answered"]);
    expect(calls).toHaveLength(1);
  });

  it("defers automatically for slow handlers, answers generically for failures, unknown commands and silence", async () => {
    const router = new CommandRouter({ logger: silentLogger, autoDeferMs: 20 });
    router.register("weather", async (i) => {
      await new Promise((r) => setTimeout(r, 60));
      await i.reply("late but fine");
    });
    router.register("boom", () => {
      throw new Error("secret detail that must not reach the node");
    });
    router.register("silent", () => undefined);
    const { ctx, calls } = context();
    await router.handle(frame().data, ctx);
    await router.handle(frame({ command: { id: CMD, name: "boom" } }).data, ctx);
    await router.handle(frame({ command: { id: CMD, name: "nope" } }).data, ctx);
    await router.handle(frame({ command: { id: CMD, name: "silent" } }).data, ctx);
    expect(calls.map((c) => [c.path, c.body])).toEqual([
      [CB, { type: "defer", ephemeral: false }],
      [FU, { content: { type: "text", body: "late but fine" }, ephemeral: false, mentions: [] }],
      [CB, { type: "error", message: "The command failed." }],
      [CB, { type: "error", message: "This command is not available right now." }],
      [CB, { type: "error", message: "The command did not answer." }],
    ]);
  });

  it("ignores malformed frames and caps error notices at 200 characters", async () => {
    const router = new CommandRouter({ logger: silentLogger });
    router.register("weather", (i) => i.error("x".repeat(500)).then(() => undefined));
    const { ctx, calls } = context();
    expect(await router.handle({ interaction_id: 1 }, ctx)).toBeNull();
    expect(await router.handle(null, ctx)).toBeNull();
    await router.handle(frame().data, ctx);
    expect(calls).toHaveLength(1);
    expect((calls[0]!.body.message as string).length).toBe(200);
    expect(() => router.register("Bad Name", () => undefined)).toThrow(TypeError);
  });

  describe("encrypted conversations (§5.8)", () => {
    const Q = `t.test/${CONV}`;
    function argsContent(over: Record<string, unknown> = {}) {
      return { type: "command.args", command: `${APP_REF}/${CMD}`, nonce: "AAAAAAAAAAAAAAAAAAAAAA", issued_at: new Date(Date.now() - 1000).toISOString(), args: { city: "Köln" }, ...over };
    }
    function fakeCrypto(content: unknown, opts: { member?: boolean; fail?: Decrypted } = {}) {
      const log: { decrypted: EncryptedEnvelope[]; encrypted: unknown[]; joined: string[] } = { decrypted: [], encrypted: [], joined: [] };
      const crypto: CommandCrypto = {
        hasGroup: () => opts.member ?? true,
        decrypt: async (q, env) => {
          expect(q).toBe(Q);
          log.decrypted.push(env);
          return opts.fail ?? { ok: true, content: content as Record<string, unknown> };
        },
        encrypt: async (_q, c) => {
          log.encrypted.push(c);
          return { content: "CIPHERTEXT", epoch: 43 };
        },
        join: (q) => log.joined.push(q),
      };
      return { crypto, log };
    }
    const encFrame = (over: Record<string, unknown> = {}) => frame({ encrypted: true, args: null, args_ciphertext: "ARGS-CIPHERTEXT", epoch: 42, ...over }).data;

    it("decrypts and checks the arguments, then answers with ciphertext of the bot device", async () => {
      const router = new CommandRouter({ logger: silentLogger });
      let args: unknown = null;
      router.register("weather", async (i) => {
        args = i.args;
        await i.reply("Köln: 9 °C");
        await i.followUp("more", { ephemeral: true });
      });
      const { crypto, log } = fakeCrypto(argsContent());
      const { ctx, calls } = context(crypto);
      await router.handle(encFrame(), ctx);
      expect(args).toEqual({ city: "Köln" });
      // The ciphertext is decrypted as a message of the invoker's device (signature checked by the session manager).
      expect(log.decrypted).toEqual([{ id: "interaction:01J9ZK3G5M8Q2W4E6R8T0Y2IN1", author: "alice@t.test", device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2DV1", epoch: 42, content: "ARGS-CIPHERTEXT" }]);
      expect(log.encrypted).toEqual([
        { type: "text", body: "Köln: 9 °C" },
        { type: "text", body: "more" },
      ]);
      expect(calls.map((c) => c.body)).toEqual([
        { type: "reply", content: "CIPHERTEXT", epoch: 43, device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2BD1", ephemeral: false, mentions: [] },
        { content: "CIPHERTEXT", epoch: 43, device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2BD1", ephemeral: true, mentions: [] },
      ]);
    });

    it("replyInThread starts a thread with an encrypted title of the channel's group", async () => {
      const router = new CommandRouter({ logger: silentLogger });
      router.register("weather", (i) => i.replyInThread("Köln: 9 °C", { title: "Wetter" }).then(() => undefined));
      const { crypto, log } = fakeCrypto(argsContent());
      const { ctx, calls } = context(crypto);
      await router.handle(encFrame(), ctx);
      expect(log.encrypted).toEqual([{ type: "thread.title", body: "Wetter" }, { type: "text", body: "Köln: 9 °C" }]);
      expect(calls[0]!.body).toEqual({ title: "CIPHERTEXT", title_epoch: 43 });
      expect(calls[1]!.body.thread_id).toBe("01J9ZK3G5M8Q2W4E6R8T0Y2NEW");
    });

    it("refuses arguments of another command, stale or replayed arguments and bad signatures; joins when not a member", async () => {
      const router = new CommandRouter({ logger: silentLogger });
      const ran: unknown[] = [];
      router.register("weather", async (i) => {
        ran.push(i.args);
        await i.reply("ok");
      });
      const refused = { type: "error", message: "The command's arguments could not be verified." };
      const cases: [unknown, Partial<{ member: boolean; fail: Decrypted }>, unknown][] = [
        [argsContent({ command: `${APP_REF}/01J9ZK3G5M8Q2W4E6R8T0Y2CM2` }), {}, refused],
        [argsContent({ issued_at: new Date(Date.now() - 6 * 60_000).toISOString(), nonce: "BBBBBBBBBBBBBBBBBBBBBB" }), {}, refused],
        [argsContent(), { fail: { ok: false, reason: "bad_signature" } }, refused],
        [{ type: "text", body: "not args" }, {}, refused],
        [argsContent(), { member: false }, { type: "error", message: "The bot is joining this channel's encryption. Try again in a moment." }],
      ];
      for (const [content, opts, expected] of cases) {
        const { crypto, log } = fakeCrypto(content, opts);
        const { ctx, calls } = context(crypto);
        await router.handle(encFrame(), ctx);
        expect(calls.map((c) => c.body)).toEqual([expected]);
        if (opts.member === false) expect(log.joined).toEqual([Q]);
      }
      expect(ran).toEqual([]);
      // Replay: the same nonce twice.
      const { crypto } = fakeCrypto(argsContent({ nonce: "CCCCCCCCCCCCCCCCCCCCCC" }));
      const first = context(crypto);
      await router.handle(encFrame(), first.ctx);
      const second = context(crypto);
      await router.handle(encFrame({ interaction_id: "01J9ZK3G5M8Q2W4E6R8T0Y2IN2" }), second.ctx);
      expect(first.calls[0]!.body.type).toBe("reply");
      expect(second.calls.map((c) => c.body)).toEqual([refused]);
      // Missing ciphertext or invoker device.
      const third = context(fakeCrypto(argsContent({ nonce: "DDDDDDDDDDDDDDDDDDDDDD" })).crypto);
      await router.handle(encFrame({ args_ciphertext: null }), third.ctx);
      expect(third.calls.map((c) => c.body)).toEqual([refused]);
    });
  });
});
