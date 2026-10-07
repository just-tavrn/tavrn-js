// SPDX-License-Identifier: Apache-2.0
// The bot runtime and threads against a real node (PROTOCOL.md §7e): incoming messages carry their thread, a reply
// stays in the thread, and replyInThread starts a thread from a channel message (encrypted title included).
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Message } from "@tavrn/sdk";
import { createBot, type Bot, type BotMessage } from "../../src";
import { silentLogger } from "../../src/logger";
import { createApp, encryptedRoom, install, registerUser, startNode, until, withCrypto, type TestNode } from "./harness";

let node: TestNode;
let dir: string;
const bots: Bot[] = [];

beforeAll(async () => {
  node = await startNode({ domain: "t.test" });
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-threads-"));
});

afterAll(async () => {
  for (const b of bots) await b.stop().catch(() => undefined);
  await node?.stop();
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("threads (PROTOCOL.md §7e)", () => {
  it("answers in a thread of an encrypted channel: a new thread from a message, then replies stay in it", async () => {
    const owner = await withCrypto(await registerUser(node, "alice"));
    const { room, channelId, q } = await encryptedRoom(owner, "Threads", { botsAllowed: true });
    const app = await createApp(owner);
    const b = createBot({ node: node.base, token: app.secret, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: silentLogger, backupDelayMs: 600_000 });
    bots.push(b);
    const received: BotMessage[] = [];
    b.on("message", async (m) => {
      received.push(m);
      if (!m.mentionsMe) return;
      if (m.threadId) await m.reply(`in thread: ${m.text}`);
      else await m.replyInThread(`thread for: ${m.text}`);
    });
    await b.start();
    await install(owner, room.id, app.ref);
    await until(async () => {
      await owner.mls.catchUp(q);
      return owner.mls.roster(q).length > 1;
    }, "the bot's leaf");

    const send = async (body: string, threadId?: string): Promise<Message> => {
      const sealed = await owner.mls.encrypt(q, { type: "text", body });
      return owner.api.conversations.send(channelId, { content: sealed.content, epoch: sealed.epoch, mentions: [app.botAddress], ...(threadId ? { thread_id: threadId } : {}) });
    };
    const root = await send("Deploy failed again");
    const thread = await until(async () => (await owner.api.threads.list(room.id, channelId)).items[0] ?? null, "the bot's thread");
    expect(thread).toMatchObject({ root_message_id: root.id, encrypted: true, title_author: app.botAddress });
    expect(await owner.mls.decryptThreadTitle(q, thread)).toEqual({ ok: true, title: "Deploy failed again" });
    const first = await until(async () => (await owner.api.threads.messages(channelId, thread.id))[0] ?? null, "the reply in the thread");
    expect(first).toMatchObject({ author: app.botAddress, thread_id: thread.id });
    expect(await owner.mls.decrypt(q, first)).toMatchObject({ ok: true, content: { body: "thread for: Deploy failed again" } });

    await send("still broken", thread.id);
    const answers = await until(async () => {
      const list = (await owner.api.threads.messages(channelId, thread.id)).filter((m) => m.author === app.botAddress);
      return list.length >= 2 ? list : null;
    }, "the answer inside the thread");
    expect(await owner.mls.decrypt(q, answers[0]!)).toMatchObject({ ok: true, content: { body: "in thread: still broken" } });
    expect(received.find((m) => m.text === "still broken")?.threadId).toBe(thread.id);
    // The channel itself shows only the root, with the thread's summary.
    const channel = await owner.api.conversations.messages(channelId, { limit: 10 });
    expect(channel.map((m) => m.id)).toEqual([root.id]);
    expect(channel[0]!.thread).toMatchObject({ id: thread.id, message_count: 3 });
  });
});
