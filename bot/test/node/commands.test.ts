// SPDX-License-Identifier: Apache-2.0
// `bot.command()` against a real node (APPLICATIONS.md §5.5–§5.8): a `/weather`-style command answered by the bot
// runtime in an unencrypted and an encrypted channel, with a reply, defer + follow-up and an ephemeral reply; the
// encrypted arguments are made by the invoker's client with `encryptCommandArgs` and checked by the runtime.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { encryptCommandArgs, qualify, splitIdentity } from "@tavrn/e2ee";
import type { InvokeResponse, Message } from "@tavrn/sdk";
import { createBot, type Bot } from "../../src";
import { silentLogger } from "../../src/logger";
import { createApp, encryptedRoom, install, registerUser, startNode, until, withCrypto, type CryptoUser, type TestNode } from "./harness";

let node: TestNode;
let dir: string;
let bot: Bot | null = null;

beforeAll(async () => {
  node = await startNode({ domain: "h.test" });
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-cmd-"));
});

afterAll(async () => {
  await bot?.stop().catch(() => undefined);
  await node?.stop();
  if (dir) await rm(dir, { recursive: true, force: true });
});

/** The text of a reply as the invoker sees it (decrypted in encrypted conversations). */
async function textOf(user: CryptoUser, q: string, m: { id: string; author: string; device_id?: string | null; epoch?: number | null; content: unknown; encrypted?: boolean }): Promise<string> {
  if (typeof m.content !== "string") return String((m.content as { body?: unknown }).body);
  await user.mls.catchUp(q);
  const d = await user.mls.decrypt(q, { id: m.id, author: m.author, device_id: m.device_id, epoch: m.epoch, content: m.content });
  if (!d.ok) throw new Error(`not decrypted: ${d.reason}`);
  return String(d.content.body);
}

describe("bot.command() on a node (APPLICATIONS.md §5)", () => {
  it("answers /weather with reply, defer + follow-up and ephemeral replies, unencrypted and encrypted", async () => {
    const owner = await withCrypto(await registerUser(node, "alice"));
    const { room, channelId, q } = await encryptedRoom(owner);
    const plain = await owner.api.channels.create(room.id, { name: "offen", kind: "text", encrypted: false } as never);
    const app = await createApp(owner);
    bot = createBot({ node: node.base, token: app.secret, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: silentLogger });
    const seen: { command: string; args: unknown; encrypted: boolean }[] = [];
    bot.command("weather", async (i) => {
      seen.push({ command: i.command.name, args: i.args, encrypted: i.encrypted });
      const city = String(i.args.city ?? "?");
      if (i.args.mode === "later") {
        await i.defer();
        await new Promise((r) => setTimeout(r, 50));
        await i.followUp(`${city}: tomorrow sunny`);
      } else if (i.args.mode === "private") {
        await i.ephemeral(`${city}: only for you`);
      } else {
        await i.reply(`${city}: 12 °C`);
      }
    });
    await bot.start();
    const set = await bot.setCommands([
      {
        name: "weather",
        description: "Weather for a city",
        args: [
          { name: "city", description: "City name", type: "string", required: true, max_length: 100 },
          { name: "mode", description: "How to answer", type: "string", required: false, options: [{ name: "Later", value: "later" }, { name: "Private", value: "private" }] },
        ],
      },
    ] as never);
    const commandRef = `${app.ref}/${set.commands[0]!.id}`;
    await install(owner, room.id, app.ref);
    await until(async () => {
      await owner.mls.catchUp(q);
      return owner.mls.roster(q).some((i) => splitIdentity(i).address === app.botAddress);
    }, "the bot's leaf");

    // The palette offers the command; invocations are answered by the runtime within the 3 seconds.
    const palette = await owner.api.commands.palette(plain.id);
    expect(palette.map((c) => c.name)).toContain("weather");
    const invoke = (conversationId: string, args: Record<string, unknown>) => owner.api.commands.invoke(conversationId, { command: commandRef, args } as never);

    // Unencrypted: reply, ephemeral, defer + follow-up.
    const replied: InvokeResponse = await invoke(plain.id, { city: "Berlin" });
    expect(replied.outcome).toBe("reply");
    expect(replied.message).toMatchObject({ author: app.botAddress, author_kind: "bot", content: { type: "text", body: "Berlin: 12 °C" } });
    expect(replied.message?.interaction).toMatchObject({ command: "weather", user: owner.address });
    const eph = await invoke(plain.id, { city: "Bonn", mode: "private" });
    expect(eph).toMatchObject({ outcome: "reply", message: null });
    expect(eph.ephemeral?.content).toEqual({ type: "text", body: "Bonn: only for you" });
    const deferred = await invoke(plain.id, { city: "Hamburg", mode: "later" });
    expect(deferred.outcome).toBe("defer");
    await until(async () => (await owner.api.conversations.messages(plain.id, { limit: 10 })).find((m: Message) => m.author === app.botAddress && (m.content as { body?: string }).body === "Hamburg: tomorrow sunny"), "the follow-up");

    // Interactions are limited to 5 per 5 s and invoker (§2.7).
    await new Promise((r) => setTimeout(r, 5_200));
    // Encrypted: the arguments travel as `command.args` ciphertext, the answers are ciphertext of the bot device.
    const encInvoke = async (args: Record<string, unknown>) => owner.api.commands.invoke(channelId, { command: commandRef, args: null, ...(await encryptCommandArgs(owner.mls, q, commandRef, args)) } as never);
    const encReply = await encInvoke({ city: "Köln" });
    expect(encReply.outcome).toBe("reply");
    expect(encReply.message).toMatchObject({ encrypted: true, author: app.botAddress, device_id: bot.info.deviceId });
    expect(await textOf(owner, q, encReply.message!)).toBe("Köln: 12 °C");
    const encEph = await encInvoke({ city: "Mainz", mode: "private" });
    expect(encEph.message).toBeNull();
    const e = encEph.ephemeral!;
    expect(await textOf(owner, q, { id: `ephemeral:${e.interaction_id}`, author: app.botAddress, device_id: e.device_id, epoch: e.epoch, content: e.content })).toBe("Mainz: only for you");
    const encDefer = await encInvoke({ city: "Trier", mode: "later" });
    expect(encDefer.outcome).toBe("defer");
    await until(async () => {
      for (const m of await owner.api.conversations.messages(channelId, { limit: 20 })) {
        if (m.author === app.botAddress && (await textOf(owner, q, m).catch(() => "")) === "Trier: tomorrow sunny") return m;
      }
      return null;
    }, "the encrypted follow-up");
    expect(seen).toEqual([
      { command: "weather", args: { city: "Berlin" }, encrypted: false },
      { command: "weather", args: { city: "Bonn", mode: "private" }, encrypted: false },
      { command: "weather", args: { city: "Hamburg", mode: "later" }, encrypted: false },
      { command: "weather", args: { city: "Köln" }, encrypted: true },
      { command: "weather", args: { city: "Mainz", mode: "private" }, encrypted: true },
      { command: "weather", args: { city: "Trier", mode: "later" }, encrypted: true },
    ]);
    expect(qualify(node.domain, channelId)).toBe(q);
  });
});
