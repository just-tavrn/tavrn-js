// SPDX-License-Identifier: Apache-2.0
// The bot runtime against a real node (APPLICATIONS.md §11 step 5): key file bootstrap and restart, a missing or
// wrong key, reading and answering in an encrypted channel, plaintext sending, token expiry and rotation,
// `stop()` flushing the history backups (opt-in), no backups by default, and the "bots allowed" channel setting.
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { qualify, splitIdentity } from "@tavrn/e2ee";
import { TavrnApi, type Message } from "@tavrn/sdk";
import { createBot, type Bot, type BotMessage, type TokenExpiringEvent } from "../../src";
import { silentLogger } from "../../src/logger";
import { createApp, encryptedRoom, install, registerUser, startNode, until, withCrypto, type CryptoUser, type TestNode } from "./harness";

let node: TestNode;
let dir: string;
const bots: Bot[] = [];

beforeAll(async () => {
  node = await startNode({ domain: "h.test" });
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-test-"));
});

afterAll(async () => {
  for (const b of bots) await b.stop().catch(() => undefined);
  await node?.stop();
  if (dir) await rm(dir, { recursive: true, force: true });
});

function bot(token: string, name: string, extra: Partial<Parameters<typeof createBot>[0]> = {}): Bot {
  const b = createBot({ node: node.base, token, keyFile: join(dir, name, "key.txt"), stateDir: join(dir, name, "state"), logger: silentLogger, backupDelayMs: 600_000, ...extra });
  bots.push(b);
  return b;
}

/** Messages of a conversation as the user sees them, decrypted. */
async function decryptedFrom(user: CryptoUser, channelId: string, author: string): Promise<string[]> {
  const q = qualify(user.node.domain, channelId);
  await user.mls.catchUp(q);
  const list: Message[] = await user.api.conversations.messages(channelId, { limit: 50 });
  const out: string[] = [];
  for (const m of list.filter((x) => x.author === author)) {
    const d = await user.mls.decrypt(q, m);
    if (d.ok) out.push(String(d.content.body));
  }
  return out;
}

describe("bot key file and state (APPLICATIONS.md §3.1–§3.2)", () => {
  it("first start creates the key file and identity, a restart reuses the state, a missing or wrong key fails clearly", async () => {
    const owner = await registerUser(node, "owner");
    const app = await createApp(owner);
    const first = bot(app.secret, "boot");
    await first.start();
    const keyPath = join(dir, "boot", "key.txt");
    expect((await stat(keyPath)).mode & 0o777).toBe(0o600);
    const keyText = await readFile(keyPath, "utf8");
    expect(keyText).toContain(`Account: ${app.botAddress}`);
    const keys = await node.api.keys.get(app.botUsername);
    expect(keys.kind).toBe("bot");
    expect(keys.identity_public_key).toBeTruthy();
    // The token's device is attested and has KeyPackages (§3.2).
    expect(keys.devices.map((d) => d.device_id)).toEqual([first.info.deviceId]);
    const appApi = new TavrnApi({ baseUrl: node.base, getToken: () => app.secret });
    expect((await appApi.keys.countKeyPackages(first.info.deviceId)).count).toBeGreaterThanOrEqual(5);
    const stateFile = JSON.parse(await readFile(join(dir, "boot", "state", "state.json"), "utf8")) as { account: string; device_id: string };
    expect(stateFile).toMatchObject({ account: app.botAddress, device_id: first.info.deviceId });
    expect((await stat(join(dir, "boot", "state", "state.json"))).mode & 0o777).toBe(0o600);
    await first.stop();

    // Restart with the same key file and state directory: same identity, nothing new published.
    const second = bot(app.secret, "boot");
    await second.start();
    expect(await readFile(keyPath, "utf8")).toBe(keyText);
    const again = await node.api.keys.get(app.botUsername);
    expect(again.identity_public_key).toBe(keys.identity_public_key);
    expect(again.devices.map((d) => d.device_id)).toEqual([first.info.deviceId]);
    await second.stop();

    // The identity exists but this process has no key: a clear error, and no key file is created.
    const missing = bot(app.secret, "nokey");
    await expect(missing.start()).rejects.toMatchObject({ code: "key_missing", message: expect.stringContaining("restore the key file or ask the owner to reset the bot identity") });
    await expect(stat(join(dir, "nokey", "key.txt"))).rejects.toMatchObject({ code: "ENOENT" });

    // Another bot's key file is refused.
    const other = await createApp(owner);
    const otherBot = bot(other.secret, "other");
    await otherBot.start();
    await otherBot.stop();
    const wrong = bot(app.secret, "wrong", { keyFile: join(dir, "other", "key.txt") });
    await expect(wrong.start()).rejects.toMatchObject({ code: "key_mismatch" });

    // The key text itself (TAVRN_BOT_KEY) works in place of the file (with the device's own state directory: a fresh
    // directory for the same token would be a device whose key is lost, ENCRYPTION.md §3.1).
    const byKey = bot(app.secret, "bykey", { key: keyText.split("\n").find((l) => l.startsWith("key:"))!.slice(4).trim(), stateDir: join(dir, "boot", "state") });
    await byKey.start();
    await byKey.stop();
  });

  it("refuses tokens that are not app tokens and a node that did not issue the token", async () => {
    const user = await registerUser(node, "notbot");
    await expect(bot(user.token, "session").start()).rejects.toMatchObject({ code: "token_invalid" });
    const owner = await registerUser(node, "owner");
    const app = await createApp(owner);
    await expect(bot(app.secret, "elsewhere", { node: "other.example" }).start()).rejects.toMatchObject({ code: "node_invalid" });
  });
});

describe("messages in an encrypted channel (APPLICATIONS.md §3.3)", () => {
  it("joins after the installation, reads and answers encrypted, sends plaintext signed, and stop flushes the backups", async () => {
    const owner = await withCrypto(await registerUser(node, "alice"));
    const { room, channelId, q } = await encryptedRoom(owner);
    const app = await createApp(owner);
    const b = bot(app.secret, "echo", { historyBackup: true });
    const received: BotMessage[] = [];
    b.on("message", async (m) => {
      received.push(m);
      if (m.mentionsMe) await m.reply(`echo: ${m.text}`);
    });
    const installs: string[] = [];
    b.on("install", (e) => void installs.push(e.roomId));
    await b.start();
    await install(owner, room.id, app.ref);
    await until(() => installs.includes(room.id), "application.install");

    // Eager join: the bot's device becomes a leaf of the channel's group.
    await until(async () => {
      await owner.mls.catchUp(q);
      return owner.mls.roster(q).some((i) => splitIdentity(i).address === app.botAddress);
    }, "the bot's leaf");
    expect(await owner.mls.ghostCheck(q, [owner.address, app.botAddress])).toEqual([]);

    const sealed = await owner.mls.encrypt(q, { type: "text", body: "Hallo Bot" });
    await owner.api.conversations.send(channelId, { content: sealed.content, epoch: sealed.epoch, mentions: [app.botAddress] });
    const replies = await until(async () => {
      const r = await decryptedFrom(owner, channelId, app.botAddress);
      return r.length ? r : null;
    }, "the bot's encrypted answer");
    expect(replies).toEqual(["echo: Hallo Bot"]);
    expect(received[0]).toMatchObject({ encrypted: true, text: "Hallo Bot", author: owner.address, authorKind: "user", mentionsMe: true, roomId: room.id, conversation: q });
    const stored = (await owner.api.conversations.messages(channelId, { limit: 10 })).find((m) => m.author === app.botAddress)!;
    expect(stored).toMatchObject({ encrypted: true, author_kind: "bot", reply_to_id: received[0]!.id, device_id: b.info.deviceId });

    // An unencrypted channel: plaintext, signed by the bot device (FEDERATION.md §10.3).
    const plain = await owner.api.channels.create(room.id, { name: "offen", kind: "text", encrypted: false } as never);
    await until(async () => {
      try {
        return await b.send(qualify(node.domain, plain.id), "plain hello");
      } catch {
        return null;
      }
    }, "a plaintext message");
    const pm = (await owner.api.conversations.messages(plain.id, { limit: 5 })).find((m) => m.author === app.botAddress)!;
    expect(pm.content).toEqual({ type: "text", body: "plain hello" });
    expect(await owner.mls.verifyPlaintext(qualify(node.domain, plain.id), pm)).toBe("valid");

    // The epoch keys of the channel wait for their backup (debounced for 10 minutes): stop uploads them.
    const appApi = new TavrnApi({ baseUrl: node.base, getToken: () => app.secret });
    expect((await appApi.backups.list()).items.map((i) => i.conversation)).not.toContain(q);
    await b.stop();
    expect((await appApi.backups.list()).items.map((i) => i.conversation)).toContain(q);
    await expect(b.send(q, "after stop")).rejects.toMatchObject({ code: "stopped" });
  });
});

describe("history backups are opt-in (design note 4.7)", () => {
  it("uploads nothing by default; a fresh state directory reads only new messages", async () => {
    const owner = await withCrypto(await registerUser(node, "hilde"));
    const { room, channelId, q } = await encryptedRoom(owner, "Ohne Backup");
    const app = await createApp(owner);
    const appApi = new TavrnApi({ baseUrl: node.base, getToken: () => app.secret });
    const keyFile = join(dir, "nobackup", "key.txt");
    const first = bot(app.secret, "nobackup", { keyFile, stateDir: join(dir, "nobackup", "state-1") });
    const seen: string[] = [];
    first.on("message", (m) => void seen.push(m.text));
    await first.start();
    await install(owner, room.id, app.ref);
    await until(async () => {
      await owner.mls.catchUp(q);
      return owner.mls.roster(q).some((i) => splitIdentity(i).address === app.botAddress);
    }, "the bot's leaf");
    const old = await owner.mls.encrypt(q, { type: "text", body: "before the restart" });
    await owner.api.conversations.send(channelId, { content: old.content, epoch: old.epoch });
    await until(() => seen.includes("before the restart"), "the first message");
    await first.stop();
    expect((await appApi.backups.list()).items).toEqual([]);

    // The state directory is lost: the operator starts the bot with a new token (a new device, the old device key lived
    // in the lost directory) and the same key file. The bot joins again and reads what comes now, not what came before.
    const created = await owner.api.applications.createToken(app.id, { name: "second" });
    const second = bot(created.secret, "nobackup", { keyFile, stateDir: join(dir, "nobackup", "state-2") });
    const later: string[] = [];
    second.on("message", (m) => void later.push(m.text));
    await second.start();
    await until(async () => {
      await owner.mls.catchUp(q);
      return owner.mls.roster(q).includes(`${app.botAddress}/${second.info.deviceId}`);
    }, "the new device's leaf");
    const fresh = await owner.mls.encrypt(q, { type: "text", body: "after the restart" });
    await owner.api.conversations.send(channelId, { content: fresh.content, epoch: fresh.epoch });
    await until(() => later.includes("after the restart"), "the new message");
    expect(later).not.toContain("before the restart");
    await second.stop();
    expect((await appApi.backups.list()).items).toEqual([]);
  });
});

describe("bots allowed per encrypted channel (APPLICATIONS.md §3.5)", () => {
  it("joins an encrypted channel of a new room only once the channel allows bots", async () => {
    const owner = await withCrypto(await registerUser(node, "greta"));
    const { room, channelId, q } = await encryptedRoom(owner, "Geschlossen", { botsAllowed: false });
    const app = await createApp(owner);
    const b = bot(app.secret, "perchannel");
    await b.start();
    await install(owner, room.id, app.ref);
    const botIn = async () => {
      await owner.mls.catchUp(q);
      return owner.mls.roster(q).some((i) => splitIdentity(i).address === app.botAddress);
    };
    await new Promise((r) => setTimeout(r, 1500));
    expect(await botIn()).toBe(false);
    await owner.api.channels.update(room.id, channelId, { bots_allowed: true });
    await until(botIn, "the bot joins after the channel allows bots");
  });
});

describe("tokens (APPLICATIONS.md §2.2)", () => {
  it("emits tokenExpiring for application.token_expiring and rotates the secret", async () => {
    const owner = await registerUser(node, "owner");
    const app = await createApp(owner, { expiresInDays: 3 });
    const b = bot(app.secret, "expiry");
    const expiring: TokenExpiringEvent[] = [];
    b.on("tokenExpiring", (e) => void expiring.push(e));
    const rotated: string[] = [];
    b.on("tokenRotated", (e) => void rotated.push(e.secret));
    await b.start();
    const resp = await fetch(`${node.base}/api/v1/dev/notify-expiring-tokens`, { method: "POST" });
    expect(resp.ok).toBe(true);
    await until(() => expiring.length > 0, "application.token_expiring");
    expect(expiring[0]).toMatchObject({ applicationId: app.id, tokenId: app.tokenId, days: 7 });

    const { secret } = await b.rotateToken();
    expect(rotated).toEqual([secret]);
    expect(secret).not.toBe(app.secret);
    expect(b.currentToken).toBe(secret);
    // The runtime goes on with the new secret.
    const me = await new TavrnApi({ baseUrl: node.base, getToken: () => secret }).users.me();
    expect(me.address).toBe(app.botAddress);
    await b.stop();
  });
});
