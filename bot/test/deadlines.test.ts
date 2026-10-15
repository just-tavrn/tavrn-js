// SPDX-License-Identifier: Apache-2.0
// Request and stop deadlines of the bot runtime, against the fake node.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createBot, type Bot, type BotLogger } from "../src";
import { BASE, CHANNEL, FakeNode, TOKEN, message, settle } from "./fake-node";

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
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-deadlines-"));
  node = new FakeNode();
  logged = [];
});

afterEach(async () => {
  await bot?.stop().catch(() => undefined);
  await rm(dir, { recursive: true, force: true });
});

describe("deadlines", () => {
  it("a request to a node that never answers fails with network.timeout", async () => {
    await startBot({ requestTimeoutMs: 50, rateLimit: false });
    node.route("GET", /^\/api\/v1\/rooms$/, (c) => new Promise((_, reject) => c.signal?.addEventListener("abort", () => reject(c.signal!.reason))));
    await expect(bot.rooms()).rejects.toMatchObject({ code: "network.timeout" });
  });

  it("stop() does not wait forever for a handler that never finishes", async () => {
    await startBot({ stopTimeoutMs: 50 });
    bot.on("message", () => new Promise<void>(() => undefined));
    node.emit("message.create", message({ conversation_id: CHANNEL }));
    await settle();
    const started = Date.now();
    await bot.stop();
    expect(Date.now() - started).toBeLessThan(2000);
    expect(logged.some((l) => l.level === "warn" && l.message.includes("still running"))).toBe(true);
  });
});
