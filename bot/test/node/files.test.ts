// SPDX-License-Identifier: Apache-2.0
// `bot.files` against a real node in an end-to-end encrypted files channel (FILES.md §3 "Bots", §8): the bot joins the
// channel's group, writes folders and files whose records and chunks only members can open, reads and downloads a
// member's upload, gets the `files` event, numbers taken names, and may delete only its own entries.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { decryptFileBytes, decryptFileRecord, encryptFileRecord, encryptFileStream, fileKeyText, newFileKey, qualify, recordKey } from "@tavrn/e2ee";
import { newUlid } from "@tavrn/sdk";
import { createBot, type Bot, type FilesEvent } from "../../src";
import { silentLogger } from "../../src/logger";
import { createApp, install, registerUser, startNode, until, withCrypto, type TestNode } from "./harness";

/** view, send, attach, read history. */
const PERMISSIONS = String([0n, 1n, 3n, 34n].reduce((acc, bit) => acc | (1n << bit), 0n));

let node: TestNode;
let dir: string;
const bots: Bot[] = [];

beforeAll(async () => {
  node = await startNode({ domain: "f.test" });
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-files-"));
});

afterAll(async () => {
  for (const b of bots) await b.stop().catch(() => undefined);
  await node?.stop();
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("bot.files in an encrypted files channel", () => {
  it("writes and reads records and chunks as a group member, numbers names, deletes its own entries only", async () => {
    const owner = await withCrypto(await registerUser(node, "alice"));
    const room = await owner.api.rooms.create({ name: "Archive" });
    const channel = await owner.api.channels.create(room.id, { kind: "files", name: "Vault" } as never);
    expect(channel.encrypted).toBe(true);
    await owner.api.channels.update(room.id, channel.id, { bots_allowed: true });
    const q = qualify(node.domain, channel.id);
    await owner.mls.ensureJoined(q, { canCreate: true });

    const app = await createApp(owner, { permissions: PERMISSIONS });
    const b = createBot({ node: node.base, token: app.secret, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: silentLogger, backupDelayMs: 600_000 });
    bots.push(b);
    const events: FilesEvent[] = [];
    b.on("files", (e) => void events.push(e));
    await b.start();
    await install(owner, room.id, app.ref, PERMISSIONS);
    // Files channels are joined eagerly like text channels.
    await until(async () => {
      await owner.mls.catchUp(q);
      return owner.mls.roster(q).length > 1;
    }, "the bot's leaf in the files channel's group");

    // The bot's folder and file: the node keeps no name, the member opens the record and the chunks.
    const folder = await b.files.createFolder(q, "Builds");
    expect(folder).toMatchObject({ kind: "folder", name: "Builds", encrypted: true, locked: false });
    const text = "42 tests passed\n";
    const up = await b.files.upload(q, { name: "report.txt", data: new TextEncoder().encode(text), mime: "text/plain", folder });
    expect(up).toMatchObject({ name: "report.txt", mime: "text/plain", size: text.length, parentId: folder.id, encrypted: true });
    expect(up.raw.name).toBe("");
    await owner.mls.catchUp(q);
    const { entries } = await owner.api.files.list(room.id, channel.id, { parent: folder.id });
    expect(entries.map((e) => [e.id, e.name])).toEqual([[up.id, ""]]);
    const opened = await decryptFileRecord(owner.mls, q, entries[0]!);
    if (!opened.ok) throw new Error(`record not readable: ${opened.reason}`);
    expect(opened.record).toMatchObject({ name: "report.txt", mime: "text/plain", size: text.length });
    const stored = new Uint8Array(await (await owner.api.files.download(room.id, channel.id, up.id)).arrayBuffer());
    expect(Buffer.from(stored).includes(Buffer.from("42 tests"))).toBe(false);
    expect(new TextDecoder().decode(await decryptFileBytes(recordKey(opened.record), "content", stored))).toBe(text);

    // A taken name: refused, or numbered on request (the node cannot see names, the bot checks the folder).
    await expect(b.files.upload(q, { name: "Report.TXT", data: new Uint8Array(3), folder })).rejects.toMatchObject({ code: "files.name_taken" });
    const again = await b.files.upload(q, { name: "report.txt", data: new Uint8Array(3), folder, rename: true });
    expect(again.name).toBe("report (2).txt");

    // A member's encrypted upload reaches the bot as an event; the bot lists and downloads it decrypted.
    events.length = 0;
    const fileKey = newFileKey();
    const plan = new File([new TextEncoder().encode("secret plan")], "plan.md", { type: "text/markdown" });
    const { blob } = await encryptFileStream(plan, { fileKey });
    const id = newUlid();
    const record = await encryptFileRecord(owner.mls, q, { entry: id, kind: "file", name: "plan.md", mime: "text/markdown", size: plan.size, key: fileKeyText(fileKey) });
    await owner.api.files.uploadEncrypted(room.id, channel.id, blob, { id, record: record.record, recordEpoch: record.record_epoch, category: "documents", parentId: null });
    await until(() => events.find((e) => e.conversation === q && e.folderId === null), "the files event");
    const top = await b.files.list(q);
    expect(top.map((e) => [e.kind, e.name, e.locked])).toEqual([
      ["folder", "Builds", false],
      ["file", "plan.md", false],
    ]);
    const theirs = top[1]!;
    const got = await b.files.download(theirs);
    expect([got.name, got.mime, new TextDecoder().decode(got.data)]).toEqual(["plan.md", "text/markdown", "secret plan"]);
    expect(new TextDecoder().decode((await b.files.download({ conversation: q, id })).data)).toBe("secret plan");

    // Others' entries need manage_files; its own go (the folder with both of its files).
    await expect(b.files.delete(theirs)).rejects.toMatchObject({ code: "files.manage_forbidden" });
    expect(await b.files.delete(folder)).toMatchObject({ files: 2, folders: 1 });
    expect((await b.files.list(q)).map((e) => e.name)).toEqual(["plan.md"]);
  });
});
