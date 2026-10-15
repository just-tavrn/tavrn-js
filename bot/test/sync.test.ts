// SPDX-License-Identifier: Apache-2.0
// Resyncs and unknown conversations of the bot runtime, against the fake node.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { BotError, createBot, type Bot, type BotLogger } from "../src";
import { BASE, DOMAIN, FakeNode, TOKEN, message, respond, settle } from "./fake-node";

const UNKNOWN = "01J9ZK3G5M8Q2W4E6R8T0Y2C99";

let dir: string;
let node: FakeNode;
let bot: Bot;
let logged: { level: string; message: string; fields?: Record<string, unknown> }[];

const recording: BotLogger = {
  debug: (message, fields) => logged.push({ level: "debug", message, fields }),
  info: (message, fields) => logged.push({ level: "info", message, fields }),
  warn: (message, fields) => logged.push({ level: "warn", message, fields }),
  error: (message, fields) => logged.push({ level: "error", message, fields }),
};

async function startBot(extra: Partial<Parameters<typeof createBot>[0]> = {}): Promise<Bot> {
  bot = createBot({ node: BASE, token: TOKEN, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: recording, fetchImpl: node.fetch, WebSocketImpl: node.WebSocket, ...extra });
  await bot.start();
  return bot;
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-sync-"));
  node = new FakeNode();
  logged = [];
});

afterEach(async () => {
  await bot?.stop().catch(() => undefined);
  await rm(dir, { recursive: true, force: true });
});

describe("resync", () => {
  it("never overlaps: resyncs during a running one are coalesced into one more run", async () => {
    await startBot();
    let inFlight = 0;
    let maxInFlight = 0;
    let lists = 0;
    node.route("GET", /^\/api\/v1\/rooms$/, async () => {
      lists += 1;
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 20));
      inFlight -= 1;
      return [{ id: "01J9ZK3G5M8Q2W4E6R8T0Y2R01", name: "Room" }];
    });
    const socket = node.sockets[0]!;
    for (let i = 0; i < 4; i++) socket.deliver({ op: "resync" });
    await new Promise((r) => setTimeout(r, 150));
    expect(maxInFlight).toBe(1);
    expect(lists).toBe(2);
  });

  it("loads the rooms of a node with bounded concurrency", async () => {
    const rooms = Array.from({ length: 10 }, (_, i) => ({ id: `01J9ZK3G5M8Q2W4E6R8T0Y2R${String(i).padStart(2, "0")}`, name: `Room ${i}` }));
    node.route("GET", /^\/api\/v1\/rooms$/, () => rooms);
    let inFlight = 0;
    let maxInFlight = 0;
    node.route("GET", /^\/api\/v1\/rooms\/([^/]+)$/, async (_c, m) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight -= 1;
      return { id: m[1], name: "Room", channels: [] };
    });
    await startBot();
    expect(node.requests(/^\/api\/v1\/rooms\/[^/]+$/, "GET")).toHaveLength(10);
    expect(maxInFlight).toBeGreaterThan(1);
    expect(maxInFlight).toBeLessThanOrEqual(4);
  });
});

describe("unknown conversations", () => {
  it("reloads the rooms once for an unknown id, not on every send", async () => {
    await startBot();
    node.route("GET", /^\/api\/v1\/conversations\/[^/]+$/, () => respond(404, { type: "about:blank", title: "", status: 404, detail: "", code: "conversation.not_found" }));
    const before = node.requests(/^\/api\/v1\/rooms$/, "GET").length;
    for (let i = 0; i < 3; i++) {
      const err = await bot.send(`${DOMAIN}/${UNKNOWN}`, "hi").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(BotError);
      expect((err as BotError).code).toBe("not_member");
    }
    expect(node.requests(/^\/api\/v1\/rooms$/, "GET").length - before).toBe(1);
    // A channel that appears by its event is known at once.
    node.emit("channel.create", { id: UNKNOWN, room_id: "01J9ZK3G5M8Q2W4E6R8T0Y2R01", kind: "text", name: "new", encrypted: false, no_bots_effective: false });
    await settle();
    node.route("POST", /\/messages$/, () => message({ id: "01J9ZK3G5M8Q2W4E6R8T0Y2M77", conversation_id: UNKNOWN }));
    await expect(bot.send(`${DOMAIN}/${UNKNOWN}`, "hi")).resolves.toMatchObject({ id: "01J9ZK3G5M8Q2W4E6R8T0Y2M77" });
  });
});
