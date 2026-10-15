// SPDX-License-Identifier: Apache-2.0
// The helpers of the bot runtime against a real node, in an encrypted channel (APPLICATIONS.md §3.3): embeds and
// encrypted files both ways, reactions (sent and the typed event), edits (own, re-encrypted with the signed context, and
// others' as `messageEdit`), history, threads with encrypted titles, a DM the bot opens, presence and a timeout.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { decryptAttachment, encryptAttachment, qualify } from "@tavrn/e2ee";
import type { Message } from "@tavrn/sdk";
import { createBot, type Bot, type BotMessage, type ReactionEvent } from "../../src";
import { silentLogger } from "../../src/logger";
import { createApp, encryptedRoom, install, registerUser, startNode, until, withCrypto, type TestNode } from "./harness";

/** view, send, manage messages, attach, react, threads, moderate members, pin, read history, polls. */
const PERMISSIONS = String([0n, 1n, 2n, 3n, 4n, 6n, 13n, 25n, 34n, 39n].reduce((acc, bit) => acc | (1n << bit), 0n));

let node: TestNode;
let dir: string;
const bots: Bot[] = [];

beforeAll(async () => {
  node = await startNode({ domain: "c.test" });
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-coverage-"));
});

afterAll(async () => {
  for (const b of bots) await b.stop().catch(() => undefined);
  await node?.stop();
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("bot helpers in an encrypted channel", () => {
  it("embeds, files, reactions, edits, history, threads, a DM, presence and a timeout", async () => {
    const owner = await withCrypto(await registerUser(node, "alice"));
    const { room, channelId, q } = await encryptedRoom(owner, "Coverage", { botsAllowed: true });
    const app = await createApp(owner, { permissions: PERMISSIONS });
    const b = createBot({ node: node.base, token: app.secret, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: silentLogger, backupDelayMs: 600_000 });
    bots.push(b);
    const received: BotMessage[] = [];
    const edits: BotMessage[] = [];
    const reactions: ReactionEvent[] = [];
    b.on("message", (m) => void received.push(m));
    b.on("messageEdit", (m) => void edits.push(m));
    b.onReaction((e) => void reactions.push(e));
    await b.start();
    await install(owner, room.id, app.ref, PERMISSIONS);
    await until(async () => {
      await owner.mls.catchUp(q);
      return owner.mls.roster(q).length > 1;
    }, "the bot's leaf");

    // An embed and an encrypted file: the member reads both, the node stored only ciphertext.
    const report = new TextEncoder().encode("42 tests passed\n");
    const sent = await b.send(q, { type: "text", body: "Build finished", embeds: [{ title: "Build #128", color: 3066993, fields: [{ name: "Branch", value: "main" }] }] }, { files: [{ name: "report.txt", data: report, mime: "text/plain" }] });
    expect(sent).toMatchObject({ encrypted: true, attachments: [{ id: expect.any(String) }] });
    await owner.mls.catchUp(q);
    const d = await owner.mls.decrypt(q, sent);
    expect(d.ok).toBe(true);
    const content = (d as { content: Record<string, unknown> }).content;
    expect(content).toMatchObject({ body: "Build finished", embeds: [{ title: "Build #128" }], attachments: [{ name: "report.txt", mime: "text/plain", size: report.length }] });
    const meta = (content.attachments as { id: string; key: string; nonce: string; sha256: string }[])[0]!;
    const blob = new Uint8Array(await (await owner.api.attachments.download(meta.id)).arrayBuffer());
    expect(Buffer.from(blob).includes(Buffer.from("42 tests"))).toBe(false);
    expect(new TextDecoder().decode(await decryptAttachment(blob, meta))).toBe("42 tests passed\n");

    // A member's encrypted file reaches the bot decrypted.
    const file = new File([new TextEncoder().encode("secret plan")], "plan.md", { type: "text/markdown" });
    const { blob: cipher, meta: fileMeta } = await encryptAttachment(file);
    const up = await owner.api.attachments.uploadToConversation(channelId, cipher, "", undefined, "documents");
    const sealed = await owner.mls.encrypt(q, { type: "text", body: "see the plan", attachments: [{ id: up.id, ...fileMeta }] }, { ctx: { thread_id: null, reply_to: null } });
    const theirs: Message = await owner.api.conversations.send(channelId, { content: sealed.content, epoch: sealed.epoch, attachments: [up.id], mentions: [] });
    const got = await until(() => received.find((m) => m.id === theirs.id), "the member's message");
    expect(got.attachments).toEqual([{ id: up.id, name: "plan.md", mime: "text/markdown", size: 11, spoiler: false }]);
    expect(new TextDecoder().decode((await got.download()).data)).toBe("secret plan");

    // Reactions: the member reacts to the bot's message (typed event), the bot reacts to the member's.
    await owner.api.conversations.react(channelId, sent.id, "👍");
    const r = await until(() => reactions.find((e) => e.messageId === sent.id), "the reaction event");
    expect(r).toMatchObject({ emoji: "👍", count: 1, added: true, conversation: q, encrypted: true });
    await got.react("✅");
    const [after] = await owner.api.conversations.messages(channelId, { around: theirs.id, limit: 1 });
    expect(after!.reactions).toEqual([{ emoji: "✅", count: 1, me: false }]);

    // Edits: the bot's own (re-encrypted, the member reads it with a valid signed context), the member's (an event).
    const edited = await b.edit(q, sent.id, "Build finished (2 flaky tests retried)");
    expect(edited.edited_at).toBeTruthy();
    const de = await owner.mls.decrypt(q, edited);
    expect(de).toMatchObject({ ok: true, content: { body: "Build finished (2 flaky tests retried)", embeds: [{ title: "Build #128" }] } });
    const resealed = await owner.mls.encrypt(q, { type: "text", body: "see the new plan", attachments: [{ id: up.id, ...fileMeta }] }, { ctx: { thread_id: null, reply_to: null } });
    await owner.api.conversations.edit(channelId, theirs.id, { content: resealed.content, epoch: resealed.epoch, mentions: [] });
    expect((await until(() => edits.find((m) => m.id === theirs.id), "the messageEdit event")).text).toBe("see the new plan");

    // History, decrypted, newest first.
    const history = await b.messages(q, { limit: 10 });
    expect(history.map((m) => m.text)).toEqual(["see the new plan", "Build finished (2 flaky tests retried)"]);

    // A thread with an encrypted title and a first message, then archived.
    const thread = await b.createThread(q, { title: "Release 0.4", content: "Checklist follows" });
    expect(thread).toMatchObject({ title: "Release 0.4", encrypted: true, conversation: q });
    const listed = await owner.api.threads.get(thread.id);
    expect(await owner.mls.decryptThreadTitle(q, listed)).toEqual({ ok: true, title: "Release 0.4" });
    const [first] = await owner.api.threads.messages(channelId, thread.id);
    expect(await owner.mls.decrypt(q, first!)).toMatchObject({ ok: true, content: { body: "Checklist follows" } });
    expect((await b.threads(q)).items.map((t) => t.title)).toContain("Release 0.4");
    expect((await b.archiveThread(q, thread.id)).archived).toBe(true);
    const renamed = await b.updateThread(q, thread.id, { title: "Release 0.4.0" });
    expect(await owner.mls.decryptThreadTitle(q, renamed.raw)).toEqual({ ok: true, title: "Release 0.4.0" });

    // A DM the bot opens with its owner (no message request for the owner): encrypted, the owner reads it.
    const dm = await b.dm(owner.address, "Your weekly report is ready");
    expect(dm.encrypted).toBe(true);
    const dq = qualify(node.domain, dm.conversation_id);
    await until(async () => (await owner.mls.processWelcomes(node.domain)).includes(dq) || owner.mls.hasGroup(dq), "the owner's Welcome");
    expect(await owner.mls.decrypt(dq, dm)).toMatchObject({ ok: true, content: { body: "Your weekly report is ready" } });

    // Presence: status and activity, as the member sees them.
    await b.setPresence({ status: "dnd", customStatus: { text: "Deploying", emoji: "🚀" } });
    await b.setActivity({ type: "watching", name: "3 servers" });
    const seen = await until(async () => (await owner.api.presence.list()).find((p) => p.user === app.botAddress && p.activity), "the bot's presence");
    expect(seen).toMatchObject({ status: "dnd", custom_status: { text: "Deploying" }, activity: { type: "watching", name: "3 servers" } });

    // Moderation: a timeout for a member.
    const bob = await registerUser(node, "bob");
    const invite = await owner.api.invites.create(room.id, {});
    await bob.api.invites.join(invite.code);
    const member = await b.timeout(room.id, bob.user.id, 5, { reason: "cool down" });
    expect(Date.parse(member.timeout_until!)).toBeGreaterThan(Date.now());
    await b.timeout({ node: node.domain, roomId: room.id }, bob.user.id, 0);
    expect((await b.members(room.id, { limit: 50 })).find((m) => m.user.id === bob.user.id)?.timeout_until ?? null).toBeNull();
  });
});
