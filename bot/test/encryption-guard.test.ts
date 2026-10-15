// SPDX-License-Identifier: Apache-2.0
// The node's `encrypted` flag can only add encryption: the runtime never writes a DM or group DM in plaintext (they are
// always end-to-end encrypted, PROTOCOL.md §8), nor a conversation it saw encrypted, whatever the node answers. A
// refused write sends nothing at all (no message, no upload, no edit). Against the fake node (test/fake-node.ts).
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createBot, type Bot } from "../src";
import { silentLogger } from "../src/logger";
import { ALICE, BASE, BOT_ADDRESS, CHANNEL, DOMAIN, FakeNode, ROOM, TOKEN, message, settle } from "./fake-node";

const DM = "01J9ZK3G5M8Q2W4E6R8T0Y2V01";
const MSG = "01J9ZK3G5M8Q2W4E6R8T0Y2M01";

let dir: string;
let node: FakeNode;
let bot: Bot;

async function startBot(): Promise<Bot> {
  bot = createBot({ node: BASE, token: TOKEN, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: silentLogger, fetchImpl: node.fetch, WebSocketImpl: node.WebSocket, joinPolicy: "lazy" });
  await bot.start();
  return bot;
}

/** Every request that writes to a conversation (messages, uploads, edits, votes, threads). */
const writes = (id: string) => node.calls.filter((c) => c.method !== "GET" && c.path.includes(`/conversations/${id}/`));

const plainDm = { id: DM, kind: "dm", encrypted: false, members: [{ address: ALICE }, { address: BOT_ADDRESS }], created_at: "2026-10-15T10:00:00Z" };

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-guard-"));
  node = new FakeNode();
});

afterEach(async () => {
  await bot?.stop().catch(() => undefined);
  await rm(dir, { recursive: true, force: true });
});

describe("plaintext is refused where the conversation is end-to-end encrypted", () => {
  it("a DM the node reports as unencrypted gets nothing in plaintext: no message, no upload", async () => {
    await startBot();
    node.route("GET", new RegExp(`/conversations/${DM}$`), () => plainDm);
    await expect(bot.send(`${DOMAIN}/${DM}`, "the private answer")).rejects.toMatchObject({ code: "encryption_downgrade" });
    await expect(bot.send(DM, "again", { files: [{ name: "a.txt", data: new TextEncoder().encode("secret") }] })).rejects.toBeTruthy();
    expect(writes(DM)).toEqual([]);
  });

  it("a group DM the node reports as unencrypted is refused as well", async () => {
    await startBot();
    node.route("GET", new RegExp(`/conversations/${DM}$`), () => ({ ...plainDm, kind: "group" }));
    await expect(bot.send(DM, "hello group")).rejects.toMatchObject({ code: "encryption_downgrade" });
    expect(writes(DM)).toEqual([]);
  });

  it("opening a DM that the node creates unencrypted is refused, and nothing is written to it later", async () => {
    await startBot();
    node.route("POST", /\/conversations$/, () => plainDm);
    await expect(bot.dm(ALICE, "hi")).rejects.toMatchObject({ code: "encryption_downgrade" });
    await expect(bot.send(DM, "hi")).rejects.toBeTruthy();
    expect(writes(DM)).toEqual([]);
  });

  it("an edit follows the conversation, not the message's flag: a plaintext edit in a DM is refused", async () => {
    await startBot();
    node.route("GET", new RegExp(`/conversations/${DM}$`), () => plainDm);
    const own = message({ conversation_id: DM, author: BOT_ADDRESS, encrypted: false, content: { type: "text", body: "draft" } });
    node.route("GET", new RegExp(`/conversations/${DM}/messages$`), (c) => (c.query.get("around") === MSG ? [own] : []));
    await expect(bot.edit(DM, MSG, "the private answer")).rejects.toMatchObject({ code: "encryption_downgrade" });
    expect(writes(DM)).toEqual([]);
  });

  it("a channel seen encrypted stays encrypted for writes when the node later says otherwise", async () => {
    node.route("GET", /^\/api\/v1\/rooms\/([^/]+)$/, () => ({
      id: ROOM,
      name: "Room",
      channels: [{ id: CHANNEL, room_id: ROOM, kind: "text", name: "general", encrypted: true, no_bots_effective: false }],
    }));
    await startBot();
    node.emit("channel.update", { id: CHANNEL, room_id: ROOM, kind: "text", name: "general", encrypted: false, no_bots_effective: false });
    await settle();
    await expect(bot.send(CHANNEL, "hello")).rejects.toMatchObject({ code: "encryption_downgrade" });
    expect(writes(CHANNEL)).toEqual([]);
  });

  it("unencrypted channels are still written in plaintext", async () => {
    await startBot();
    node.route("POST", new RegExp(`/conversations/${CHANNEL}/messages$`), (c) => message({ content: (c.body as { content: unknown }).content }));
    await bot.send(CHANNEL, "hello");
    expect(writes(CHANNEL)).toHaveLength(1);
  });
});
