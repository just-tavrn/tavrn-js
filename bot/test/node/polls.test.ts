// SPDX-License-Identifier: Apache-2.0
// Polls with the bot runtime against a real node (PROTOCOL.md §7g): the bot sends an encrypted poll with a close time,
// members vote with encrypted vote records, the bot sees the votes (pollVote event, checked tally) and votes itself.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkPollVote, encryptPollVote, parsePoll, pollHash, pollVoteContent, tallyPoll } from "@tavrn/e2ee";
import { createBot, type Bot, type PollVoteEvent } from "../../src";
import { silentLogger } from "../../src/logger";
import { createApp, encryptedRoom, install, registerUser, startNode, until, withCrypto, type TestNode } from "./harness";

let node: TestNode;
let dir: string;
const bots: Bot[] = [];

beforeAll(async () => {
  node = await startNode({ domain: "t.test" });
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-polls-"));
});

afterAll(async () => {
  for (const b of bots) await b.stop().catch(() => undefined);
  await node?.stop();
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("polls (PROTOCOL.md §7g)", () => {
  it("creates an encrypted poll, follows the votes and votes itself", async () => {
    const owner = await withCrypto(await registerUser(node, "alice"));
    const { room, channelId, q } = await encryptedRoom(owner, "Polls", { botsAllowed: true });
    const app = await createApp(owner);
    const b = createBot({ node: node.base, token: app.secret, keyFile: join(dir, "key.txt"), stateDir: join(dir, "state"), logger: silentLogger, backupDelayMs: 600_000 });
    bots.push(b);
    const events: PollVoteEvent[] = [];
    b.onPollVote((e) => void events.push(e));
    await b.start();
    await install(owner, room.id, app.ref);
    await until(async () => {
      await owner.mls.catchUp(q);
      return owner.mls.roster(q).length > 1;
    }, "the bot's leaf");

    // The bot's poll: encrypted, with the plaintext close time.
    const closesAt = new Date(Date.now() + 3_600_000);
    const sent = await b.createPoll(q, { kind: "choice", question: "Release today?", options: ["Yes", "No", "Tomorrow"], maxChoices: 1 }, { closesAt });
    expect(sent.encrypted).toBe(true);
    expect(Date.parse(sent.poll_closes_at!)).toBe(Math.floor(closesAt.getTime()));
    const d = await owner.mls.decrypt(q, sent);
    expect(d.ok).toBe(true);
    const poll = parsePoll(d.ok ? d.content : null)!;
    expect(poll).toMatchObject({ kind: "choice", question: "Release today?", max_choices: 1 });
    const hash = await pollHash(d.ok ? d.content : {});

    // A member votes; the bot hears it and counts it.
    const content = pollVoteContent(poll, sent.id, hash, { choices: ["o1"] });
    const sealed = await encryptPollVote(owner.mls, q, content);
    await owner.api.polls.vote(channelId, sent.id, sealed);
    await until(() => events.find((e) => e.user === owner.address && !e.retracted), "the pollVote event");
    const results = await b.votes(q, sent.id);
    expect(results.tally).toMatchObject({ voters: 1, records: 1, best: ["o1"], closed: false });
    expect(results.votes[0]!.check).toMatchObject({ ok: true, selection: { choices: ["o1"] } });

    // The bot votes; the member verifies the bot's record against the bot's device.
    await b.vote(q, sent.id, { choices: ["o3"] });
    const { items } = await owner.api.polls.votes(channelId, sent.id);
    expect(items.map((v) => v.user).sort()).toEqual([owner.address, app.botAddress].sort());
    const checked = await Promise.all(items.map(async (r) => ({ user: r.user, updated_at: r.updated_at, check: await checkPollVote(owner.mls, q, r, poll, hash) })));
    expect(checked.every((c) => c.check.ok)).toBe(true);
    expect(tallyPoll(poll, checked, { closesAt: sent.poll_closes_at }).options.map((o) => o.count)).toEqual([1, 0, 1]);

    // Retracting is an event too; closing early stops votes.
    await owner.api.polls.retract(channelId, sent.id);
    await until(() => events.find((e) => e.user === owner.address && e.retracted), "the retraction event");
    await owner.api.polls.close(channelId, sent.id);
    await expect(b.vote(q, sent.id, { choices: ["o2"] })).rejects.toMatchObject({ code: "poll.closed" });
    expect((await b.votes(q, sent.id)).tally).toMatchObject({ closed: true, voters: 1 });
  });
});
