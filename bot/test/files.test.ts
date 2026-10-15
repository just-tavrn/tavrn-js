// SPDX-License-Identifier: Apache-2.0
// `bot.files` against the fake node (FILES.md §3 "Bots"): listings over every page, uploads from bytes and from disk,
// folders, downloads, deletes, the checks before anything is sent, and `files.update` as the `files` event. Plaintext
// files channels only; the encrypted channel runs against a real node in test/node/files.test.ts.
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { BotError, JOINABLE_KINDS, createBot, type Bot, type FilesEvent } from "../src";
import { silentLogger } from "../src/logger";
import { BASE, CHANNEL, DOMAIN, FakeNode, ROOM, TOKEN, respond, settle } from "./fake-node";

const FILES = "01J9ZK3G5M8Q2W4E6R8T0Y2C09";
const HIDDEN = "01J9ZK3G5M8Q2W4E6R8T0Y2C08";
const FOLDER = "01J9ZK3G5M8Q2W4E6R8T0Y2F01";
const q = `${DOMAIN}/${FILES}`;
const base = `/api/v1/rooms/${ROOM}/channels/${FILES}/files`;

let dir: string;
let node: FakeNode;
let bot: Bot;

function entry(over: Record<string, unknown> = {}) {
  return { id: "01J9ZK3G5M8Q2W4E6R8T0Y2E01", channel_id: FILES, parent_id: null, kind: "file", name: "report.txt", mime: "text/plain", size: 5, sha256: "x", created_by: "01J9ZK3G5M8Q2W4E6R8T0Y2B01", created_at: "2026-10-15T10:00:00Z", updated_at: "2026-10-15T10:00:00Z", thumbnail_size: 0, ...over };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-files-"));
  node = new FakeNode();
  node.route("GET", /^\/api\/v1\/rooms\/([^/]+)$/, (_c, m) => ({
    id: m[1],
    name: "Room",
    channels: [
      { id: CHANNEL, room_id: ROOM, kind: "text", name: "general", encrypted: false, no_bots_effective: false },
      { id: FILES, room_id: ROOM, kind: "files", name: "Shared", encrypted: false, no_bots_effective: false },
    ],
  }));
  bot = createBot({ node: BASE, token: TOKEN, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: silentLogger, fetchImpl: node.fetch, WebSocketImpl: node.WebSocket });
  await bot.start();
});

afterEach(async () => {
  await bot?.stop().catch(() => undefined);
  await rm(dir, { recursive: true, force: true });
});

describe("bot.files in an unencrypted files channel", () => {
  it("lists a folder over every page", async () => {
    node.route("GET", new RegExp(`^${base}$`), (c) => {
      if (!c.query.get("after")) return { entries: [entry({ id: "01J9ZK3G5M8Q2W4E6R8T0Y2E02", kind: "folder", name: "Builds", mime: "", size: 0 })], next_after: "01J9ZK3G5M8Q2W4E6R8T0Y2E02", path: [] };
      return { entries: [entry()], next_after: null, path: [] };
    });
    const list = await bot.files.list(q, FOLDER);
    expect(list.map((e) => [e.kind, e.name, e.size, e.locked, e.conversation, e.roomId])).toEqual([
      ["folder", "Builds", 0, false, q, ROOM],
      ["file", "report.txt", 5, false, q, ROOM],
    ]);
    const calls = node.requests(new RegExp(`^${base}$`), "GET");
    expect(calls.map((c) => [c.query.get("parent"), c.query.get("limit"), c.query.get("after")])).toEqual([
      [FOLDER, "200", null],
      [FOLDER, "200", "01J9ZK3G5M8Q2W4E6R8T0Y2E02"],
    ]);
    // A bare channel id means the home node; the top level has no parent.
    await bot.files.list(FILES);
    expect(node.requests(new RegExp(`^${base}$`), "GET").at(-1)!.query.get("parent")).toBeNull();
  });

  it("uploads bytes and files from disk, creates folders, downloads and deletes", async () => {
    node.route("POST", new RegExp(`^${base}/upload$`), async (c) => respond(201, entry({ name: decodeURIComponent(c.headers["tavrn-file-name"]!), mime: c.headers["content-type"], size: (c.body as Blob).size, parent_id: c.headers["tavrn-parent"] ?? null })));
    node.route("POST", new RegExp(`^${base}/folders$`), (c) => respond(201, entry({ id: FOLDER, kind: "folder", name: (c.body as { name: string }).name, mime: "", size: 0 })));
    node.route("GET", new RegExp(`^${base}/[^/]+/download$`), () => new Response(new TextEncoder().encode("hello"), { headers: { "Content-Type": "text/plain" } }));
    node.route("DELETE", new RegExp(`^${base}/[^/]+$`), () => ({ files: 1, folders: 0, bytes: 5 }));

    const folder = await bot.files.createFolder(q, "Reports");
    expect(folder).toMatchObject({ id: FOLDER, kind: "folder", name: "Reports" });
    expect(node.requests(/\/files\/folders$/, "POST")[0]!.body).toEqual({ name: "Reports", parent_id: null });

    const up = await bot.files.upload(q, { name: "Wochenbericht März.txt", data: new TextEncoder().encode("hello"), mime: "text/plain", folder });
    expect(up).toMatchObject({ name: "Wochenbericht März.txt", size: 5, parentId: FOLDER });
    const call = node.requests(/\/files\/upload$/, "POST")[0]!;
    expect(call.headers["tavrn-file-name"]).toBe(encodeURIComponent("Wochenbericht März.txt"));
    expect([call.headers["tavrn-parent"], call.headers["content-type"], call.headers["tavrn-conflict"]]).toEqual([FOLDER, "text/plain", undefined]);
    expect(await (call.body as Blob).text()).toBe("hello");

    const path = join(dir, "build-128.log");
    await writeFile(path, "42 tests passed\n");
    const fromDisk = await bot.files.upload(q, { path, rename: true });
    expect(fromDisk).toMatchObject({ name: "build-128.log", size: 16, mime: "application/octet-stream" });
    const second = node.requests(/\/files\/upload$/, "POST")[1]!;
    expect([second.headers["tavrn-conflict"], second.headers["tavrn-parent"]]).toEqual(["rename", undefined]);

    const file = await bot.files.download(up);
    expect(file).toMatchObject({ id: up.id, name: "Wochenbericht März.txt", mime: "text/plain", size: 5 });
    expect(new TextDecoder().decode(file.data)).toBe("hello");
    expect(await bot.files.delete(up)).toEqual({ files: 1, folders: 0, bytes: 5 });
    expect(node.requests(new RegExp(`^${base}/${up.id}$`), "DELETE")).toHaveLength(1);
    // By reference: the channel and the id are enough to delete.
    await bot.files.delete({ conversation: q, id: FOLDER });
    expect(node.requests(new RegExp(`^${base}/${FOLDER}$`), "DELETE")).toHaveLength(1);
  });

  it("refuses bad input before anything is sent", async () => {
    const before = node.calls.length;
    await expect(bot.files.upload(q, { name: "a/b.txt", data: new Uint8Array(1) })).rejects.toThrow(RangeError);
    await expect(bot.files.upload(q, { name: "..", data: new Uint8Array(1) })).rejects.toThrow(RangeError);
    await expect(bot.files.upload(q, { name: "x.txt" })).rejects.toThrow(TypeError);
    await expect(bot.files.upload(q, { name: "x.txt", data: new Uint8Array(1), path: "/tmp/x" })).rejects.toThrow(TypeError);
    await expect(bot.files.createFolder(q, " ")).rejects.toThrow(RangeError);
    expect(node.calls.slice(before).filter((c) => c.path.includes("/files"))).toEqual([]);
    // Not a files channel, or not one the bot can view.
    await expect(bot.files.list(`${DOMAIN}/${CHANNEL}`)).rejects.toMatchObject({ code: "not_found" });
    const err = await bot.files.list(`${DOMAIN}/${HIDDEN}`).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BotError);
    expect(err).toMatchObject({ code: "not_member" });
  });

  it("passes the node's refusals through (scopes, rights, names)", async () => {
    node.route("POST", new RegExp(`^${base}/upload$`), () => respond(403, { type: "about:blank", title: "Forbidden", status: 403, code: "app.scope_missing", detail: "The token lacks the scope messages:write", meta: { scope: "messages:write" } }));
    await expect(bot.files.upload(q, { name: "x.txt", data: new Uint8Array(1) })).rejects.toMatchObject({ code: "app.scope_missing", status: 403 });
  });

  it("turns files.update into the files event and joins encrypted files channels like text channels", async () => {
    const events: FilesEvent[] = [];
    bot.on("files", (e) => void events.push(e));
    node.emit("files.update", { room_id: ROOM, channel_id: FILES, parent_id: FOLDER });
    node.emit("files.update", { room_id: ROOM, channel_id: FILES, parent_id: null });
    node.emit("files.update", { channel_id: FILES });
    await settle();
    expect(events).toEqual([
      { node: DOMAIN, conversation: q, roomId: ROOM, channelId: FILES, folderId: FOLDER },
      { node: DOMAIN, conversation: q, roomId: ROOM, channelId: FILES, folderId: null },
    ]);
    expect(JOINABLE_KINDS.has("files")).toBe(true);
  });
});
