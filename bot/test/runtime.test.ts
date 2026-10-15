// SPDX-License-Identifier: Apache-2.0
// The bot runtime's helpers and typed events against the fake node (test/fake-node.ts): what goes over the wire,
// which inputs are refused before anything is sent, and how node events become `reaction`, `messageEdit`,
// `messageDelete`, `memberJoin`, `thread` and `dmRequest` events. Plaintext conversations only; the encrypted paths
// run against a real node in test/node/.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createBot, type Bot, type BotMessage, type DmRequestEvent, type MemberEvent, type MessageDeleteEvent, type ReactionEvent, type ThreadEvent } from "../src";
import { silentLogger } from "../src/logger";
import { ALICE, ALICE_ID, BASE, BOT_ADDRESS, CHANNEL, DOMAIN, FORUM, FakeNode, ROOM, TOKEN, VOICE, message, respond, settle } from "./fake-node";

const MSG = "01J9ZK3G5M8Q2W4E6R8T0Y2M01";
const THREAD = "01J9ZK3G5M8Q2W4E6R8T0Y2T01";

let dir: string;
let node: FakeNode;
let bot: Bot;

async function startBot(extra: Partial<Parameters<typeof createBot>[0]> = {}): Promise<Bot> {
  bot = createBot({ node: BASE, token: TOKEN, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: silentLogger, fetchImpl: node.fetch, WebSocketImpl: node.WebSocket, ...extra });
  await bot.start();
  return bot;
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-unit-"));
  node = new FakeNode();
});

afterEach(async () => {
  await bot?.stop().catch(() => undefined);
  await rm(dir, { recursive: true, force: true });
});

describe("the fake node", () => {
  it("lets the runtime start: identity, attested device, KeyPackages, rooms", async () => {
    await startBot();
    expect(bot.info).toMatchObject({ address: BOT_ADDRESS, homeDomain: DOMAIN });
    expect(node.requests(/\/users\/me\/identity$/, "PUT")).toHaveLength(1);
    expect(node.requests(/\/key-packages$/, "POST").length).toBeGreaterThan(0);
    expect(node.unrouted).toEqual([]);
  });
});

describe("reactions (js #18)", () => {
  it("turns reaction changes of seen messages into reaction events and sends its own reactions", async () => {
    await startBot();
    const events: ReactionEvent[] = [];
    bot.onReaction((e) => void events.push(e));
    const q = `${DOMAIN}/${CHANNEL}`;
    node.emit("message.create", message());
    await settle();
    node.emit("message.update", message({ reactions: [{ emoji: "👍", count: 1, me: false }] }));
    node.emit("message.update", message({ reactions: [{ emoji: "👍", count: 2, me: false }, { emoji: "🎉", count: 1, me: false }] }));
    node.emit("message.update", message({ reactions: [{ emoji: "🎉", count: 1, me: false }] }));
    await settle();
    expect(events.map((e) => [e.emoji, e.count, e.added])).toEqual([
      ["👍", 1, true],
      ["👍", 2, true],
      ["🎉", 1, true],
      ["👍", 0, false],
    ]);
    expect(events[0]).toMatchObject({ node: DOMAIN, conversation: q, conversationId: CHANNEL, roomId: ROOM, messageId: MSG, user: null, encrypted: false });
    expect(bot.reactionsOf(q, MSG)).toEqual(new Map([["🎉", 1]]));

    // A pin or an edit without reaction changes is no reaction event; an update naming the user (tavrn-protocol#43) is
    // reported with the user, also for a message the bot never saw.
    node.emit("message.update", message({ pinned: true, reactions: [{ emoji: "🎉", count: 1, me: false }] }));
    node.emit("message.update", { ...message({ id: "01J9ZK3G5M8Q2W4E6R8T0Y2M02", reactions: [{ emoji: "✅", count: 4, me: false }] }), reaction: { emoji: "✅", user: "Bob@H.test", added: true } });
    node.emit("message.update", message({ id: "01J9ZK3G5M8Q2W4E6R8T0Y2M03", reactions: [{ emoji: "✅", count: 1, me: false }] }));
    await settle();
    expect(events.slice(4).map((e) => [e.messageId.slice(-3), e.emoji, e.count, e.user])).toEqual([["M02", "✅", 4, "bob@h.test"]]);

    node.route("PUT", /\/reactions\//, () => message({ reactions: [{ emoji: "🎉", count: 2, me: true }] }));
    node.route("DELETE", /\/reactions\//, () => message({ reactions: [{ emoji: "🎉", count: 1, me: false }] }));
    await bot.react(q, MSG, "🎉");
    await bot.unreact(q, MSG, "🎉");
    await bot.react(q, MSG, "<:party:01J9ZK3G5M8Q2W4E6R8T0Y2E01>");
    expect(node.requests(/\/reactions\//).map((c) => `${c.method} ${decodeURIComponent(c.path)}`)).toEqual([
      `PUT /api/v1/conversations/${CHANNEL}/messages/${MSG}/reactions/🎉`,
      `DELETE /api/v1/conversations/${CHANNEL}/messages/${MSG}/reactions/🎉`,
      `PUT /api/v1/conversations/${CHANNEL}/messages/${MSG}/reactions/<:party:01J9ZK3G5M8Q2W4E6R8T0Y2E01>`,
    ]);
    await expect(bot.react(q, MSG, "two words")).rejects.toThrow(RangeError);
    await expect(bot.react(q, "not-an-id", "👍")).rejects.toThrow(/ULID/);
  });

  it("reacts from a received message", async () => {
    await startBot();
    node.route("PUT", /\/reactions\//, () => message({ reactions: [{ emoji: "👀", count: 1, me: true }] }));
    const got: BotMessage[] = [];
    bot.on("message", (m) => void got.push(m));
    node.emit("message.create", message());
    await settle();
    await got[0]!.react("👀");
    expect(node.requests(/\/reactions\//, "PUT")).toHaveLength(1);
  });
});

describe("edits, deletions, history", () => {
  it("emits messageEdit for edits of others and messageDelete", async () => {
    await startBot();
    const edits: BotMessage[] = [];
    const deletes: MessageDeleteEvent[] = [];
    bot.on("messageEdit", (m) => void edits.push(m));
    bot.on("messageDelete", (d) => void deletes.push(d));
    node.emit("message.create", message());
    await settle();
    node.emit("message.update", message({ edited_at: new Date().toISOString(), content: { type: "text", body: "hello (edited)" } }));
    node.emit("message.delete", { room_id: ROOM, conversation_id: CHANNEL, id: MSG });
    await settle();
    expect(edits.map((m) => m.text)).toEqual(["hello (edited)"]);
    expect(edits[0]!.editedAt).not.toBeNull();
    expect(deletes).toEqual([{ node: DOMAIN, conversation: `${DOMAIN}/${CHANNEL}`, conversationId: CHANNEL, roomId: ROOM, messageId: MSG }]);
  });

  it("edits its own plaintext message signed again, keeps the rest of the content, refuses others' messages", async () => {
    await startBot();
    const own = message({ author: BOT_ADDRESS, content: { type: "text", body: "Build running", embeds: [{ title: "CI" }] } });
    node.route("GET", new RegExp(`/conversations/${CHANNEL}/messages$`), (c) => (c.query.get("around") === MSG ? [own] : []));
    node.route("PATCH", /\/messages\//, (c) => ({ ...own, content: (c.body as { content: unknown }).content, edited_at: new Date().toISOString() }));
    await bot.edit(CHANNEL, MSG, "Build passed");
    const [patch] = node.requests(/\/messages\//, "PATCH");
    expect(patch!.path).toBe(`/api/v1/conversations/${CHANNEL}/messages/${MSG}`);
    expect(patch!.body).toMatchObject({ content: { type: "text", body: "Build passed", embeds: [{ title: "CI" }] }, mentions: [], mentions_everyone: false });
    expect(typeof (patch!.body as { signature: unknown }).signature).toBe("string");
    await expect(bot.edit(CHANNEL, "01J9ZK3G5M8Q2W4E6R8T0Y2M09", "x")).rejects.toMatchObject({ code: "not_found" });
    await expect(bot.edit(CHANNEL, MSG, { type: "text", body: "x".repeat(4001) })).rejects.toThrow(RangeError);
    node.route("GET", new RegExp(`/conversations/${CHANNEL}/messages$`), () => [message()]);
    await expect(bot.edit(CHANNEL, MSG, "x")).rejects.toMatchObject({ code: "not_author" });
  });

  it("deletes, pins, reads the history and pins decrypted, marks read and types", async () => {
    await startBot();
    node.route("DELETE", /\/messages\//, () => respond(204));
    node.route("PUT", /\/pins\//, () => message({ pinned: true }));
    node.route("GET", /\/pins$/, () => ({ messages: [message({ pinned: true })] }));
    node.route("GET", new RegExp(`/conversations/${CHANNEL}/messages$`), () => [message(), message({ id: "01J9ZK3G5M8Q2W4E6R8T0Y2M02", content: "not an object" })]);
    node.route("PUT", /\/read$/, (c) => ({ conversation_id: CHANNEL, ...(c.body as object) }));
    await bot.deleteMessage(CHANNEL, MSG);
    await bot.pin(CHANNEL, MSG);
    expect((await bot.pins(CHANNEL)).map((m) => m.text)).toEqual(["hello"]);
    const history = await bot.messages(CHANNEL, { limit: 20, threadId: THREAD });
    expect(history.map((m) => m.id)).toEqual([MSG]);
    expect(node.requests(new RegExp(`/conversations/${CHANNEL}/messages$`), "GET").at(-1)!.query.toString()).toBe(`limit=20&thread=${THREAD}`);
    await bot.markRead(CHANNEL, MSG);
    expect(bot.typing(CHANNEL)).toBe(true);
    expect(node.operations()).toContainEqual({ op: "typing", conversation_id: CHANNEL });
    await expect(bot.messages(CHANNEL, { limit: 500 })).rejects.toThrow(RangeError);
    expect(node.requests(/\/messages\//, "DELETE").map((c) => c.path)).toEqual([`/api/v1/conversations/${CHANNEL}/messages/${MSG}`]);
  });
});

describe("sending: embeds and files", () => {
  it("checks embeds before sending and uploads plaintext files", async () => {
    await startBot();
    node.route("POST", /\/messages$/, (c) => message({ author: BOT_ADDRESS, ...(c.body as object) }));
    node.route("POST", /\/uploads$/, (c) => ({ id: "01J9ZK3G5M8Q2W4E6R8T0Y2F01", name: decodeURIComponent(c.headers["tavrn-file-name"] ?? ""), mime: c.headers["content-type"], size: 5, sha256: "x" }));
    await bot.send(CHANNEL, { type: "text", body: "", embeds: [{ title: "Build #128", color: 3066993, fields: [{ name: "Branch", value: "main", inline: true }] }] });
    await expect(bot.send(CHANNEL, { type: "text", body: "", embeds: [{ url: "http://insecure.example" }] })).rejects.toMatchObject({ code: "message.embeds_invalid" });
    await expect(bot.send(CHANNEL, { type: "text", body: "" })).rejects.toThrow(/empty/);
    await expect(bot.send(CHANNEL, { type: "system.join" })).rejects.toThrow(/reserved/);
    await bot.send(CHANNEL, "", { files: [{ name: "report.txt", data: new TextEncoder().encode("hello"), mime: "text/plain", spoiler: true }] });
    const sends = node.requests(/\/messages$/, "POST");
    expect(sends).toHaveLength(2);
    expect(sends[1]!.body).toMatchObject({ content: { type: "text", body: "📎" }, attachments: ["01J9ZK3G5M8Q2W4E6R8T0Y2F01"], spoilers: ["01J9ZK3G5M8Q2W4E6R8T0Y2F01"] });
    const [upload] = node.requests(/\/uploads$/);
    expect(upload!.path).toBe(`/api/v1/conversations/${CHANNEL}/uploads`);
    expect(upload!.headers["tavrn-file-name"]).toBe("report.txt");
    await expect(bot.send(CHANNEL, "x", { files: Array.from({ length: 11 }, (_, i) => ({ name: `${i}.txt`, data: new Uint8Array(1) })) })).rejects.toThrow(/at most 10/);
  });

  it("downloads a plaintext attachment and checks its hash", async () => {
    await startBot();
    const bytes = new TextEncoder().encode("hello");
    const sha = Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("base64url");
    node.route("GET", /\/blobs\//, () => new Response(bytes));
    const got: BotMessage[] = [];
    bot.on("message", (m) => void got.push(m));
    node.emit("message.create", message({ attachments: [{ id: "01J9ZK3G5M8Q2W4E6R8T0Y2F01", name: "a.txt", mime: "text/plain", size: 5, sha256: sha }] }));
    node.emit("message.create", message({ id: "01J9ZK3G5M8Q2W4E6R8T0Y2M02", attachments: [{ id: "01J9ZK3G5M8Q2W4E6R8T0Y2F02", name: "b.txt", mime: "text/plain", size: 5, sha256: "wrong" }] }));
    await settle();
    expect(got[0]!.attachments).toEqual([{ id: "01J9ZK3G5M8Q2W4E6R8T0Y2F01", name: "a.txt", mime: "text/plain", size: 5, spoiler: false }]);
    const file = await got[0]!.download();
    expect(new TextDecoder().decode(file.data)).toBe("hello");
    await expect(got[1]!.download()).rejects.toThrow();
    await expect(got[0]!.download("01J9ZK3G5M8Q2W4E6R8T0Y2F09")).rejects.toMatchObject({ code: "not_found" });
  });
});

describe("threads (PROTOCOL.md §7e)", () => {
  const thread = (over: Record<string, unknown> = {}) => ({ id: THREAD, room_id: ROOM, channel_id: CHANNEL, encrypted: false, title: "Deploy", title_author: BOT_ADDRESS, created_by: BOT_ADDRESS, created_by_id: "x", created_at: "", last_message_at: "", message_count: 0, participant_ids: [], tags: [], locked: false, root_deleted: false, archived_at: null, ...over });

  it("creates threads and forum posts with client ids, lists, archives and deletes them", async () => {
    await startBot();
    node.route("POST", /\/threads$/, (c) => thread({ id: (c.body as { id?: string }).id ?? THREAD, title: (c.body as { title: string }).title }));
    node.route("GET", /\/threads$/, () => ({ items: [thread()], next: null }));
    node.route("GET", /\/threads\/[^/]+$/, () => thread());
    node.route("PATCH", /\/threads\/[^/]+$/, (c) => thread({ archived_at: (c.body as { archived?: boolean }).archived ? "now" : null }));
    node.route("DELETE", /\/threads\/[^/]+$/, () => respond(204));
    node.route("POST", /\/follow$/, () => ({}));

    const t = await bot.createThread(CHANNEL, { title: "Deploy", rootMessageId: MSG });
    expect(t).toMatchObject({ title: "Deploy", conversation: `${DOMAIN}/${CHANNEL}`, roomId: ROOM, archived: false });
    const [plain, post] = [
      node.requests(/\/threads$/, "POST")[0]!,
      (await bot.createThread(FORUM, { title: "Ideas", content: "First idea", tags: ["01J9ZK3G5M8Q2W4E6R8T0Y2G01"] }), node.requests(/\/threads$/, "POST")[1]!),
    ];
    // A plaintext thread without a first message needs no client id; a forum post gets one so its first message is signed.
    expect(plain.path).toBe(`/api/v1/rooms/${ROOM}/channels/${CHANNEL}/threads`);
    expect(plain.body).toEqual({ title: "Deploy", root_message_id: MSG });
    expect(post.path).toBe(`/api/v1/rooms/${ROOM}/channels/${FORUM}/threads`);
    expect(post.body).toMatchObject({ id: expect.stringMatching(/^[0-9A-Z]{26}$/), title: "Ideas", tags: ["01J9ZK3G5M8Q2W4E6R8T0Y2G01"], message: { content: { type: "text", body: "First idea" }, signature: expect.any(String) } });
    await expect(bot.createThread(FORUM, { title: "No message" })).rejects.toThrow(/first message/);
    await expect(bot.createThread(CHANNEL, { title: "x".repeat(101) })).rejects.toThrow(RangeError);
    await expect(bot.createThread(CHANNEL, { title: "Tags", tags: ["01J9ZK3G5M8Q2W4E6R8T0Y2G01"] })).rejects.toThrow(/forum/);

    expect((await bot.threads(CHANNEL, { archived: "all" })).items.map((x) => x.title)).toEqual(["Deploy"]);
    expect(node.requests(/\/threads$/, "GET")[0]!.query.get("archived")).toBe("all");
    expect((await bot.archiveThread(CHANNEL, THREAD)).archived).toBe(true);
    await bot.updateThread(CHANNEL, THREAD, { title: "Deploy v2", locked: true });
    expect(node.requests(/\/threads\/[^/]+$/, "PATCH").map((c) => c.body)).toEqual([{ archived: true }, { title: "Deploy v2", locked: true }]);
    await expect(bot.updateThread(CHANNEL, THREAD, {})).rejects.toThrow(RangeError);
    await bot.followThread(CHANNEL, THREAD);
    await bot.deleteThread(CHANNEL, THREAD);
    expect(node.requests(/\/threads\/[^/]+$/, "DELETE")).toHaveLength(1);
  });

  it("answers in a thread that another member started in the meantime", async () => {
    await startBot();
    node.route("POST", /\/threads$/, () => respond(409, { type: "about:blank", title: "Conflict", status: 409, code: "thread.exists", meta: { thread_id: THREAD } }));
    node.route("GET", /\/threads\/[^/]+$/, () => thread());
    node.route("POST", /\/messages$/, (c) => message({ author: BOT_ADDRESS, ...(c.body as object) }));
    const got: BotMessage[] = [];
    bot.on("message", (m) => void got.push(m));
    node.emit("message.create", message());
    await settle();
    await got[0]!.replyInThread("on it");
    expect(node.requests(/\/messages$/, "POST")[0]!.body).toMatchObject({ thread_id: THREAD, content: { body: "on it" } });
  });

  it("emits thread events", async () => {
    await startBot();
    const events: ThreadEvent[] = [];
    bot.on("thread", (e) => void events.push(e));
    node.emit("thread.create", { room_id: ROOM, thread: thread() });
    node.emit("thread.delete", { room_id: ROOM, channel_id: CHANNEL, id: THREAD });
    await settle();
    expect(events.map((e) => [e.action, e.threadId, e.conversation, !!e.thread])).toEqual([
      ["create", THREAD, `${DOMAIN}/${CHANNEL}`, true],
      ["delete", THREAD, `${DOMAIN}/${CHANNEL}`, false],
    ]);
  });
});

describe("rooms, members, moderation", () => {
  it("calls the moderation routes with checked input", async () => {
    await startBot();
    node.route("PUT", /\/timeout$/, (c) => ({ user: { id: ALICE_ID }, ...(c.body as object) }));
    node.route("DELETE", /\/members\//, () => respond(204));
    node.route("POST", /\/bans$/, (c) => c.body);
    node.route("DELETE", /\/bans\//, () => respond(204));
    node.route("GET", /\/bans$/, () => []);
    node.route("GET", /\/audit-log$/, () => []);
    node.route("GET", /\/members$/, () => []);
    const m = { node: DOMAIN, roomId: ROOM };
    await bot.timeout(m, ALICE_ID, 10, { reason: "spam" });
    await bot.timeout(`${DOMAIN}/${ROOM}`, ALICE_ID, 0);
    await bot.kick(ROOM, ALICE_ID, { reason: "bye" });
    await bot.ban(m, " Alice@H.test ", { reason: "spam" });
    await bot.ban(m, "spam.example");
    await bot.unban(m, ALICE);
    await bot.bans(m);
    await bot.auditLog(m, { limit: 10 });
    await bot.members(m, { limit: 50 });
    expect(node.requests(/\/timeout$/).map((c) => [c.path, c.body])).toEqual([
      [`/api/v1/rooms/${ROOM}/members/${ALICE_ID}/timeout`, { minutes: 10, reason: "spam" }],
      [`/api/v1/rooms/${ROOM}/members/${ALICE_ID}/timeout`, { minutes: 0 }],
    ]);
    expect(node.requests(/\/members\/[^/]+$/, "DELETE")[0]!.body).toEqual({ reason: "bye" });
    expect(node.requests(/\/bans$/, "POST").map((c) => c.body)).toEqual([{ subject: ALICE, reason: "spam" }, { subject: "spam.example" }]);
    await expect(bot.timeout(m, ALICE_ID, 40_321)).rejects.toThrow(RangeError);
    await expect(bot.timeout(m, ALICE_ID, 1.5)).rejects.toThrow(RangeError);
    await expect(bot.kick(m, ALICE_ID, { reason: "x".repeat(501) })).rejects.toThrow(RangeError);
    await expect(bot.ban(m, "not a subject")).rejects.toThrow(RangeError);
    await expect(bot.kick({ node: DOMAIN, roomId: null }, ALICE_ID)).rejects.toMatchObject({ code: "not_member" });
    await expect(bot.kick({ node: "elsewhere.test", roomId: ROOM }, ALICE_ID)).rejects.toMatchObject({ code: "not_member" });
  });

  it("sets the voice channel status, searches and closes a poll", async () => {
    await startBot();
    node.route("PATCH", /\/channels\/[^/]+$/, (c) => ({ id: VOICE, ...(c.body as object) }));
    node.route("GET", /\/search$/, () => ({ results: [], searched: {} }));
    node.route("PATCH", /\/messages\//, (c) => message({ poll_closes_at: (c.body as { poll_closes_at: string }).poll_closes_at }));
    await bot.setVoiceStatus(ROOM, VOICE, "  Raid night ");
    expect(node.requests(/\/channels\/[^/]+$/, "PATCH")[0]!.body).toEqual({ status: "Raid night" });
    await expect(bot.setVoiceStatus(ROOM, VOICE, "x".repeat(129))).rejects.toThrow(RangeError);
    await bot.search(ROOM, { q: "deploy", limit: 5 });
    expect(node.requests(/\/search$/)[0]!.query.get("q")).toBe("deploy");
    const at = new Date(Date.now() + 60_000);
    await bot.closePoll(CHANNEL, MSG, at);
    await bot.closePoll(CHANNEL, MSG);
    const closes = node.requests(/\/messages\//, "PATCH").map((c) => (c.body as { poll_closes_at: string }).poll_closes_at);
    expect(closes[0]).toBe(at.toISOString());
    expect(Date.parse(closes[1]!)).toBeLessThanOrEqual(Date.now());
  });

  it("emits member events", async () => {
    await startBot();
    const joins: MemberEvent[] = [];
    const leaves: MemberEvent[] = [];
    bot.on("memberJoin", (e) => void joins.push(e));
    bot.on("memberLeave", (e) => void leaves.push(e));
    node.emit("member.join", { room_id: ROOM, user: { id: ALICE_ID, address: ALICE, username: "alice" } });
    node.emit("member.leave", { room_id: ROOM, user_id: ALICE_ID });
    await settle();
    expect(joins).toMatchObject([{ node: DOMAIN, roomId: ROOM, userId: ALICE_ID, user: ALICE }]);
    expect(leaves).toMatchObject([{ node: DOMAIN, roomId: ROOM, userId: ALICE_ID, user: null, profile: null }]);
  });
});

describe("presence (APPLICATIONS.md §7)", () => {
  it("sets status, custom status and activity with the protocol's limits", async () => {
    await startBot();
    node.route("PUT", /\/users\/me\/presence$/, (c) => c.body);
    node.route("PUT", /\/users\/me\/activity$/, (c) => c.body);
    node.route("DELETE", /\/users\/me\/activity$/, () => ({}));
    await bot.setPresence({ status: "dnd", customStatus: { text: "Deploying", emoji: "🚀" } });
    await bot.setActivity({ type: "watching", name: "3 servers" });
    await bot.clearActivity();
    expect(node.requests(/\/users\/me\/(presence|activity)$/).map((c) => [c.method, c.body])).toEqual([
      ["PUT", { status: "dnd", custom_status: { text: "Deploying", emoji: "🚀", expires_at: null } }],
      ["PUT", { type: "watching", name: "3 servers" }],
      ["DELETE", undefined],
    ]);
    await expect(bot.setActivity({ type: "coding" as never, name: "x" })).rejects.toThrow(RangeError);
    await expect(bot.setActivity({ type: "playing", name: "x".repeat(129) })).rejects.toThrow(RangeError);
    await expect(bot.setPresence({ status: "away" as never })).rejects.toThrow(RangeError);
    await expect(bot.setPresence({ customStatus: { text: "" } })).rejects.toThrow(RangeError);
  });
});

describe("DMs (PROTOCOL.md §8a)", () => {
  it("announces message requests and answers them", async () => {
    await startBot();
    const requests: DmRequestEvent[] = [];
    bot.on("dmRequest", (e) => void requests.push(e));
    node.route("POST", /\/accept$/, () => ({}));
    node.route("POST", /\/decline$/, () => respond(204));
    const conv = "01J9ZK3G5M8Q2W4E6R8T0Y2V01";
    node.emit("conversation.request", { request: { conversation: { id: conv, kind: "dm", encrypted: true, members: [] }, from: { address: ALICE }, shared_rooms: [] } });
    await settle();
    expect(requests).toMatchObject([{ node: DOMAIN, conversation: `${DOMAIN}/${conv}`, from: ALICE }]);
    await bot.acceptDm(requests[0]!.conversation);
    await bot.declineDm(conv, { block: true, reason: "spam" });
    expect(node.requests(/\/(accept|decline)$/).map((c) => [c.path, c.body])).toEqual([
      [`/api/v1/conversations/${conv}/accept`, {}],
      [`/api/v1/conversations/${conv}/decline`, { block: true, reason: "spam" }],
    ]);
    await expect(bot.openDm("not an address")).rejects.toThrow(RangeError);
  });
});

describe("rate limits (APPLICATIONS.md §2.7)", () => {
  it("waits for Retry-After and repeats the request; rateLimit: false hands the 429 over", async () => {
    let refused = 0;
    node.route("PUT", /\/reactions\//, () => {
      if (refused++ < 1) return respond(429, { type: "about:blank", title: "Too many", status: 429, code: "rate_limited" }, { "Retry-After": "0" });
      return message();
    });
    await startBot();
    await bot.react(CHANNEL, MSG, "👍");
    expect(node.requests(/\/reactions\//)).toHaveLength(2);
    await bot.stop();

    node = new FakeNode();
    node.route("PUT", /\/reactions\//, () => respond(429, { type: "about:blank", title: "Too many", status: 429, code: "rate_limited" }, { "Retry-After": "0" }));
    await startBot({ rateLimit: false, keyFile: join(dir, "key2.txt"), stateDir: join(dir, "state2") });
    await expect(bot.react(CHANNEL, MSG, "👍")).rejects.toMatchObject({ status: 429 });
  });
});

describe("the raw API", () => {
  it("gives the client of a connected node and refuses unknown nodes", async () => {
    await startBot();
    node.route("GET", /\/webhooks$/, () => []);
    expect(await bot.api().webhooks.list(ROOM)).toEqual([]);
    expect(node.requests(/\/webhooks$/)[0]!.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(() => bot.api("other.test")).toThrow(expect.objectContaining({ code: "not_member" }));
  });
});
