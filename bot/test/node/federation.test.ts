// SPDX-License-Identifier: Apache-2.0
// A remote installation (APPLICATIONS.md §2.8, §4.5): a bot of a.test installed in a room of b.test. The runtime
// opens a federated session on b.test when it hears of the installation (`application.install` through a.test),
// joins the encrypted channel there, reads and answers; a restart finds b.test through
// `GET /applications/me/installations`.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { qualify, splitIdentity } from "@tavrn/e2ee";
import { createBot, type Bot } from "../../src";
import { silentLogger } from "../../src/logger";
import { createApp, encryptedRoom, install, registerUser, startFederation, until, withCrypto, type TestNode } from "./harness";

let a: TestNode;
let b: TestNode;
let dir: string;
const bots: Bot[] = [];

beforeAll(async () => {
  ({ a, b } = await startFederation());
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-fed-"));
});

afterAll(async () => {
  for (const x of bots) await x.stop().catch(() => undefined);
  await Promise.all([a?.stop(), b?.stop()]);
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("remote installations (APPLICATIONS.md §2.8, §4.5)", () => {
  it("connects to the room node on application.install, answers in its encrypted channel, and reconnects after a restart", async () => {
    const owner = await registerUser(a, "owner");
    const app = await createApp(owner, { public: true });
    const carol = await withCrypto(await registerUser(b, "carol"), [a]);
    const { room, channelId, q } = await encryptedRoom(carol);
    const make = () => {
      const x = createBot({ node: a.base, token: app.secret, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: silentLogger, backupDelayMs: 600_000 });
      x.on("message", async (m) => {
        if (m.mentionsMe) await m.reply(`echo from ${m.node}: ${m.text}`);
      });
      bots.push(x);
      return x;
    };
    const bot = make();
    await bot.start();
    expect(bot.nodes).toEqual(["a.test"]);

    // Carol installs the bot of a.test in her room on b.test.
    await install(carol, room.id, app.ref);
    await until(() => bot.nodes.includes("b.test"), "the federated session on b.test");
    await until(async () => {
      await carol.mls.catchUp(q);
      return carol.mls.roster(q).some((i) => splitIdentity(i).address === app.botAddress);
    }, "the bot's leaf in the channel of b.test");
    // Keys of the bot come from its home node a.test; it is a regular attested member.
    expect(await carol.mls.ghostCheck(q, [carol.address, app.botAddress])).toEqual([]);

    const ask = async (body: string) => {
      const sealed = await carol.mls.encrypt(q, { type: "text", body });
      await carol.api.conversations.send(channelId, { content: sealed.content, epoch: sealed.epoch, mentions: [app.botAddress] });
      return until(async () => {
        await carol.mls.catchUp(q);
        for (const m of await carol.api.conversations.messages(channelId, { limit: 20 })) {
          if (m.author !== app.botAddress) continue;
          const d = await carol.mls.decrypt(q, m);
          if (d.ok && d.content.body === `echo from b.test: ${body}`) return m;
        }
        return null;
      }, `the answer to "${body}"`);
    };
    const answer = await ask("Hallo von b.test");
    expect(answer).toMatchObject({ encrypted: true, author_kind: "bot" });

    // Restart: the installation index of a.test leads the runtime to b.test before start() resolves.
    await bot.stop();
    const again = make();
    await again.start();
    expect(again.nodes.sort()).toEqual(["a.test", "b.test"]);
    await ask("Wieder da?");
    expect(qualify("b.test", channelId)).toBe(q);
  });
});
