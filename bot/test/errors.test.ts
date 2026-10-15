// SPDX-License-Identifier: Apache-2.0
// Error classes and background failures of the bot runtime, against the fake node.
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
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-errors-"));
  node = new FakeNode();
  logged = [];
});

afterEach(async () => {
  await bot?.stop().catch(() => undefined);
  await rm(dir, { recursive: true, force: true });
});

describe("error classes", () => {
  it("refuses a malformed conversation id with a RangeError before any request", async () => {
    await startBot();
    const calls = node.calls.length;
    for (const bad of ["not-a-node/x", "h.test/notaulid", "/01J9ZK3G5M8Q2W4E6R8T0Y2C01"]) {
      await expect(bot.send(bad, "x")).rejects.toBeInstanceOf(RangeError);
    }
    expect(node.calls.length).toBe(calls);
  });
});

describe("background failures", () => {
  it("are logged instead of vanishing", async () => {
    await startBot();
    node.emit("message.create", message({ conversation_id: CHANNEL, mentions: [42 as unknown as string] }));
    await settle();
    expect(logged.some((l) => l.level === "warn" && l.message === "background task failed")).toBe(true);
  });
});
