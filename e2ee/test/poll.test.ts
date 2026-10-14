// SPDX-License-Identifier: MPL-2.0
// Polls and date polls (PROTOCOL.md §7g): the poll and vote content checks, the poll hash, vote records through the
// session manager (the protocol's polls.json vectors: an encrypted vote and a signed plaintext vote by the vectors'
// device) and the tally.
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode, type PollVote } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { MlsManager } from "../src/mls";
import {
  checkPollVote,
  parsePoll,
  parsePollVote,
  pollContent,
  pollHash,
  pollVisibility,
  pollVoteContent,
  pollVoteRecordId,
  selectionFits,
  tallyPoll,
  type CheckedVote,
  type Poll,
  type VoteCheck,
} from "../src/poll";
import { Network } from "./fake-node";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const E: Record<string, any> = JSON.parse(readFileSync(new URL("../../protocol/testvectors/encryption.json", import.meta.url), "utf8"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const P: Record<string, any> = JSON.parse(readFileSync(new URL("../../protocol/testvectors/polls.json", import.meta.url), "utf8")).poll_vote;

beforeAll(() => ensureCrypto());

/** Bob's session manager; Alice (the vectors' voter) is a user of node.example with the vectors' attested device. */
async function reader(): Promise<MlsManager> {
  const net = new Network();
  const node = net.node("node.example");
  const att = E.device_attestation;
  node.addUser("alice", MasterSecret.fromBytes(b64urlDecode(E.keys.master_secret)));
  const share = E.device_share_key;
  node.users.get("alice")!.devices.set(att.device_id, { pk: att.device_public_key, sig: att.signature, spk: share.share_public_key, ssig: share.signature });
  const bobMaster = MasterSecret.generate();
  node.addUser("bob", bobMaster);
  const mls = new MlsManager({
    api: net.api("bob@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VB1"),
    client: Client.create("bob@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VB1"),
    address: "bob@node.example",
    deviceId: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1",
    homeDomain: "node.example",
    persist: async () => undefined,
    backupKey: () => bobMaster.backupKey(),
    ownIdentityKey: () => b64urlEncode(bobMaster.identityPublicKey()),
    pins: {},
    savePins: async () => undefined,
    meta: { convs: {} },
    saveMeta: async () => undefined,
    backupDelayMs: 60_000,
  });
  await mls.importHistoryKeys(P.conversation, [[42, b64urlDecode(P.content_key)]]);
  return mls;
}

const choice = (over: Record<string, unknown> = {}) => ({
  type: "poll",
  kind: "choice",
  question: "Lunch?",
  options: [
    { id: "a", label: "Pizza" },
    { id: "b", label: "Salad" },
    { id: "c", label: "Soup" },
  ],
  max_choices: 2,
  results_visible: "always",
  votes_visible: "public",
  ...over,
});
const dated = (over: Record<string, unknown> = {}) => ({
  type: "poll",
  kind: "date",
  question: "Dinner?",
  slots: [
    { id: "s1", start: "2026-11-06T19:00:00+01:00", end: "2026-11-06T22:00:00+01:00" },
    { id: "s2", start: "2026-11-07T00:00:00+01:00", all_day: true },
    { id: "s3", start: "2026-11-08T18:00:00Z" },
  ],
  results_visible: "after_vote",
  votes_visible: "hidden_until_close",
  ...over,
});

describe("parsePoll (PROTOCOL.md §7g)", () => {
  it("accepts both kinds and keeps only the known fields", () => {
    expect(parsePoll({ ...choice(), extra: 1, ctx: { thread_id: null, reply_to: null } })).toEqual({
      kind: "choice",
      question: "Lunch?",
      options: choice().options,
      max_choices: 2,
      results_visible: "always",
      votes_visible: "public",
    });
    const d = parsePoll(dated());
    expect(d?.kind).toBe("date");
    expect(d && d.kind === "date" ? d.slots : []).toEqual(dated().slots);
  });

  it("refuses everything outside the limits", () => {
    const bad: unknown[] = [
      null,
      "poll",
      { ...choice(), type: "text" },
      choice({ kind: "ranked" }),
      choice({ question: "   " }),
      choice({ question: "x".repeat(301) }),
      choice({ options: [{ id: "a", label: "A" }] }),
      choice({ options: Array.from({ length: 21 }, (_, i) => ({ id: `o${i}`, label: "x" })) }),
      choice({ options: [{ id: "a", label: "A" }, { id: "a", label: "B" }], max_choices: 1 }),
      choice({ options: [{ id: "a b", label: "A" }, { id: "b", label: "B" }], max_choices: 1 }),
      choice({ options: [{ id: "x".repeat(33), label: "A" }, { id: "b", label: "B" }], max_choices: 1 }),
      choice({ options: [{ id: "a", label: "" }, { id: "b", label: "B" }], max_choices: 1 }),
      choice({ options: [{ id: "a", label: "x".repeat(101) }, { id: "b", label: "B" }], max_choices: 1 }),
      choice({ max_choices: 0 }),
      choice({ max_choices: 4 }),
      choice({ max_choices: 1.5 }),
      choice({ max_choices: undefined }),
      choice({ results_visible: "never" }),
      choice({ votes_visible: "anonymous" }),
      dated({ slots: [] }),
      dated({ slots: Array.from({ length: 61 }, (_, i) => ({ id: `s${i}`, start: "2026-11-06T19:00:00Z" })) }),
      dated({ slots: [{ id: "s1", start: "2026-11-06T19:00:00" }] }),
      dated({ slots: [{ id: "s1", start: "2026-11-06" }] }),
      dated({ slots: [{ id: "s1", start: "2026-11-06T19:00:00Z", end: "2026-11-06T18:00:00Z" }] }),
      dated({ slots: [{ id: "s1", start: "2026-11-06T19:00:00Z", all_day: "yes" }] }),
      dated({ slots: [{ id: "s1", start: "2026-11-06T19:00:00Z" }, { id: "s1", start: "2026-11-07T19:00:00Z" }] }),
    ];
    for (const b of bad) expect(parsePoll(b), JSON.stringify(b)).toBeNull();
  });
});

describe("pollContent", () => {
  it("builds valid content with generated ids and defaults", () => {
    const c = pollContent({ kind: "choice", question: " Lunch? ", options: [" Pizza", "Salad"] });
    expect(c).toEqual({ type: "poll", kind: "choice", question: "Lunch?", options: [{ id: "o1", label: "Pizza" }, { id: "o2", label: "Salad" }], max_choices: 1, results_visible: "always", votes_visible: "public" });
    const d = pollContent({ kind: "date", question: "When?", slots: [{ start: "2026-11-06T19:00:00+01:00", allDay: true }, { start: "2026-11-07T19:00:00+01:00", end: "2026-11-07T21:00:00+01:00" }], votesVisible: "hidden_until_close" });
    expect(d.slots).toEqual([{ id: "s1", start: "2026-11-06T19:00:00+01:00", all_day: true }, { id: "s2", start: "2026-11-07T19:00:00+01:00", end: "2026-11-07T21:00:00+01:00" }]);
    expect(() => pollContent({ kind: "choice", question: "One?", options: ["only"] })).toThrow(RangeError);
    expect(() => pollContent({ kind: "choice", question: "Too many?", options: ["a", "b"], maxChoices: 3 })).toThrow(RangeError);
  });
});

describe("pollHash", () => {
  it("is the SHA-256 of the JCS form without ctx (polls.json)", async () => {
    expect(await pollHash(JSON.parse(P.poll_input))).toBe(P.poll_hash);
    expect(await pollHash(P.date_poll)).toBe(P.date_poll_hash);
    // ctx never changes the hash, every other field does.
    const poll = JSON.parse(P.poll_input) as Record<string, unknown>;
    const { ctx: _ctx, ...bare } = poll;
    expect(await pollHash(bare)).toBe(P.poll_hash);
    expect(await pollHash({ ...poll, question: "Edited" })).not.toBe(P.poll_hash);
    expect(await pollHash({ ...poll, extra: true })).not.toBe(P.poll_hash);
  });
});

describe("votes", () => {
  const poll = parsePoll(choice()) as Poll;
  const date = parsePoll(dated()) as Poll;
  const hash = "a".repeat(64);

  it("checks the selection against the poll", () => {
    expect(selectionFits(poll, { choices: ["a"] })).toBe(true);
    expect(selectionFits(poll, { choices: ["a", "c"] })).toBe(true);
    expect(selectionFits(poll, { choices: ["a", "b", "c"] })).toBe(false);
    expect(selectionFits(poll, { choices: ["a", "a"] })).toBe(false);
    expect(selectionFits(poll, { choices: ["z"] })).toBe(false);
    expect(selectionFits(poll, { choices: [] })).toBe(false);
    expect(selectionFits(poll, { answers: { s1: "yes" } })).toBe(false);
    expect(selectionFits(date, { answers: { s1: "yes", s3: "no" } })).toBe(true);
    expect(selectionFits(date, { answers: { s9: "yes" } })).toBe(false);
    expect(selectionFits(date, { answers: { s1: "perhaps" } })).toBe(false);
    expect(selectionFits(date, { answers: {} })).toBe(false);
    expect(selectionFits(date, { choices: ["s1"] })).toBe(false);
  });

  it("builds and parses the vote content with its binding", () => {
    const v = pollVoteContent(poll, "M1", hash, { choices: ["b"] }, new Date("2026-11-01T18:00:00.123Z"));
    expect(v).toEqual({ type: "poll.vote", choices: ["b"], voted_at: "2026-11-01T18:00:00Z", ctx: { poll: "M1", poll_hash: hash } });
    expect(parsePollVote(v, poll, "M1", hash)).toEqual({ ok: true, vote: v, selection: { choices: ["b"] } });
    expect(parsePollVote(v, poll, "M2", hash)).toEqual({ ok: false, reason: "envelope_mismatch" });
    expect(parsePollVote(v, poll, "M1", "b".repeat(64))).toEqual({ ok: false, reason: "stale" });
    expect(parsePollVote({ ...v, ctx: { ...v.ctx, extra: 1 } }, poll, "M1", hash)).toEqual({ ok: false, reason: "envelope_mismatch" });
    expect(parsePollVote({ ...v, type: "text" }, poll, "M1", hash)).toEqual({ ok: false, reason: "invalid" });
    expect(parsePollVote({ ...v, choices: ["a", "b", "c"] }, poll, "M1", hash)).toEqual({ ok: false, reason: "invalid" });
    expect(parsePollVote({ ...v, voted_at: "yesterday" }, poll, "M1", hash)).toEqual({ ok: false, reason: "invalid" });
    expect(() => pollVoteContent(poll, "M1", hash, { choices: ["z"] })).toThrow(RangeError);
    expect(() => pollVoteContent(poll, "M1", "ABC", { choices: ["a"] })).toThrow(RangeError);
  });

  it("decrypts and verifies the encrypted vote of polls.json; refuses it as a message and elsewhere", async () => {
    const mls = await reader();
    const vectorPoll = parsePoll(JSON.parse(P.poll_input))!;
    const record: PollVote = { conversation_id: "01J9ZK3G5M8Q2W4E6R8T0Y2V00", message_id: P.poll_message_id, user: P.author, user_id: "U1", device_id: P.device_id, epoch: P.epoch, content: P.vote_content, signature: null, created_at: "2026-11-01T18:00:01Z", updated_at: "2026-11-01T18:00:01Z" };
    const ok = await checkPollVote(mls, P.conversation, record, vectorPoll, P.poll_hash);
    expect(ok).toEqual({ ok: true, vote: JSON.parse(P.vote_json), selection: { choices: ["a", "c"] } });
    // An edited poll: the same vote is stale, never counted.
    expect(await checkPollVote(mls, P.conversation, record, vectorPoll, "0".repeat(64))).toEqual({ ok: false, reason: "stale" });
    // Served for another poll message: the signed ctx does not match.
    expect(await checkPollVote(mls, P.conversation, { ...record, message_id: "01J9ZK3G5M8Q2W4E6R8T0Y2VP9" }, vectorPoll, P.poll_hash)).toEqual({ ok: false, reason: "envelope_mismatch" });
    // Served as somebody else's vote: the AAD names the author.
    const other = await checkPollVote(await reader(), P.conversation, { ...record, user: "bob@node.example" }, vectorPoll, P.poll_hash);
    expect(other.ok).toBe(false);
    // Vote content is never shown as a message.
    expect(await (await reader()).decrypt(P.conversation, { id: "m1", author: P.author, device_id: P.device_id, epoch: P.epoch, content: P.vote_content })).toEqual({ ok: false, reason: "invalid" });
    // A message ciphertext is never a vote.
    const msg = E.content;
    expect(await (await reader()).decryptPollVote(msg.conversation, { user: msg.author, device_id: msg.device_id, epoch: 42, content: msg.content })).toEqual({ ok: false, reason: "invalid" });
    expect(pollVoteRecordId(record)).toBe(`poll-vote:${P.author}`);
    // The genuine record still counts after the node served it under another poll.
    expect((await checkPollVote(mls, P.conversation, record, vectorPoll, P.poll_hash)).ok).toBe(true);
  });

  it("verifies the signed plaintext vote of polls.json", async () => {
    const mls = await reader();
    const datePoll = parsePoll(P.date_poll)!;
    const record: PollVote = { conversation_id: "01J9ZK3G5M8Q2W4E6R8T0Y2V09", message_id: P.plaintext_vote.ctx.poll, user: P.author, user_id: "U1", device_id: P.device_id, epoch: null, content: P.plaintext_vote, signature: P.plaintext_signature, created_at: "2026-11-01T17:05:01Z", updated_at: "2026-11-01T17:05:01Z" };
    expect(await checkPollVote(mls, P.plaintext_conversation, record, datePoll, P.date_poll_hash)).toEqual({ ok: true, vote: P.plaintext_vote, selection: { answers: { s1: "yes", s2: "maybe" } } });
    // Unsigned: counted, marked unverified.
    expect(await checkPollVote(mls, P.plaintext_conversation, { ...record, signature: null }, datePoll, P.date_poll_hash)).toMatchObject({ ok: true, unverified: true });
    // Changed by the node: the signature no longer matches.
    const changed = { ...record, content: { ...P.plaintext_vote, answers: { s1: "no", s2: "maybe" } } };
    expect(await checkPollVote(await reader(), P.plaintext_conversation, changed, datePoll, P.date_poll_hash)).toEqual({ ok: false, reason: "bad_signature" });
  });
});

describe("tallyPoll", () => {
  const poll = parsePoll(choice()) as Poll;
  const date = parsePoll(dated()) as Poll;
  const ok = (sel: { choices: string[] } | { answers: Record<string, "yes" | "maybe" | "no"> }, unverified = false): VoteCheck => ({ ok: true, vote: { type: "poll.vote", voted_at: "2026-11-01T18:00:00Z", ctx: { poll: "M", poll_hash: "h" }, ...sel }, selection: sel, ...(unverified ? { unverified: true as const } : {}) });
  const at = (m: number) => new Date(Date.UTC(2026, 10, 1, 18, m)).toISOString();

  it("counts one vote per member, the newest record, and leaves stale, late and rejected votes out", () => {
    const votes: CheckedVote[] = [
      { user: "a@x", updated_at: at(1), check: ok({ choices: ["a"] }) },
      { user: "a@x", updated_at: at(5), check: ok({ choices: ["b", "c"] }) },
      { user: "b@x", updated_at: at(2), check: ok({ choices: ["b"] }, true) },
      { user: "c@x", updated_at: at(3), check: { ok: false, reason: "stale" } },
      { user: "d@x", updated_at: at(4), check: { ok: false, reason: "bad_signature" } },
      { user: "e@x", updated_at: at(30), check: ok({ choices: ["a"] }) },
    ];
    const t = tallyPoll(poll, votes, { closesAt: at(20), now: new Date(at(40)) });
    expect(t.closed).toBe(true);
    expect(t.records).toBe(5);
    expect(t.voters).toBe(2);
    expect([t.stale, t.late, t.rejected, t.unverified]).toEqual([1, 1, 1, 1]);
    expect(t.options.map((o) => [o.id, o.count, o.voters])).toEqual([
      ["a", 0, []],
      ["b", 2, ["a@x", "b@x"]],
      ["c", 1, ["a@x"]],
    ]);
    expect(t.best).toEqual(["b"]);
    expect(t.byUser.get("a@x")).toEqual({ choices: ["b", "c"] });
    expect(tallyPoll(poll, [], {}).best).toEqual([]);
    expect(tallyPoll(poll, votes, { closesAt: at(20), now: new Date(at(10)) }).closed).toBe(false);
  });

  it("ranks the date slots by 2 × yes + maybe", () => {
    const t = tallyPoll(date, [
      { user: "a@x", updated_at: at(1), check: ok({ answers: { s1: "yes", s2: "maybe", s3: "no" } }) },
      { user: "b@x", updated_at: at(2), check: ok({ answers: { s1: "maybe", s2: "yes" } }) },
      { user: "c@x", updated_at: at(3), check: ok({ answers: { s3: "yes" } }) },
    ]);
    expect(t.slots.map((s) => [s.id, s.yes, s.maybe, s.no, s.score])).toEqual([
      ["s1", 1, 1, 0, 3],
      ["s2", 1, 1, 0, 3],
      ["s3", 1, 0, 1, 2],
    ]);
    expect(t.best).toEqual(["s1", "s2"]);
    expect(t.slots[2]!.voters).toEqual({ yes: ["c@x"], maybe: [], no: ["a@x"] });
  });

  it("applies the cooperative visibility flags", () => {
    const after = parsePoll(choice({ results_visible: "after_vote", votes_visible: "hidden_until_close" })) as Poll;
    expect(pollVisibility(after, { closed: false }, false)).toEqual({ results: false, voters: false });
    expect(pollVisibility(after, { closed: false }, true)).toEqual({ results: true, voters: false });
    expect(pollVisibility(after, { closed: true }, false)).toEqual({ results: true, voters: true });
    const closeOnly = parsePoll(choice({ results_visible: "after_close" })) as Poll;
    expect(pollVisibility(closeOnly, { closed: false }, true)).toEqual({ results: false, voters: false });
    expect(pollVisibility(poll, { closed: false }, false)).toEqual({ results: true, voters: true });
  });
});
