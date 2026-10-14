// SPDX-License-Identifier: MPL-2.0
/**
 * Polls and date polls (PROTOCOL.md §7g): the poll content (`{ type: "poll", kind: "choice" | "date", … }`), the
 * vote content (`{ type: "poll.vote", choices | answers, voted_at, ctx: { poll, poll_hash } }`), the poll hash
 * (lowercase hex SHA-256 of the RFC 8785 form of the poll without its `ctx`), encrypting, signing and checking vote
 * records and the tally.
 *
 * A poll is an ordinary message; its votes are records next to it (`api.polls`), one per member. Encrypted votes are
 * content format 1 under the conversation's current epoch, signed by the voting device ({@link encryptPollVote},
 * {@link MlsManager.decryptPollVote}); plaintext votes carry the plaintext signature of FEDERATION.md §10.3 with empty
 * reply and thread, no mentions and no attachments ({@link signPlainPollVote}). {@link checkPollVote} turns a record
 * into a countable vote or the reason it does not count; {@link tallyPoll} counts at most one vote per member and
 * leaves out stale, late and unverifiable votes.
 */
import { jcs, type PollVote } from "@tavrn/sdk";
import type { DecryptFailure, MlsManager } from "./mls";
import type { PlainStatus } from "./plaintext";

export const POLL_TYPE = "poll";
export const POLL_VOTE_TYPE = "poll.vote";
/** Limits of PROTOCOL.md §7g. */
export const POLL_LIMITS = {
  question: 300,
  label: 100,
  minOptions: 2,
  maxOptions: 20,
  minSlots: 1,
  maxSlots: 60,
  id: 32,
  /** Bytes of a vote record's content (ciphertext or plaintext JSON). */
  voteBytes: 4096,
} as const;

export type PollKind = "choice" | "date";
export type PollResultsVisible = "always" | "after_vote" | "after_close";
export type PollVotesVisible = "public" | "hidden_until_close";
export type PollAnswer = "yes" | "maybe" | "no";

export interface PollOption {
  id: string;
  label: string;
}

export interface PollSlot {
  id: string;
  /** RFC 3339 with offset. */
  start: string;
  end?: string;
  all_day?: boolean;
}

interface PollBase {
  question: string;
  results_visible: PollResultsVisible;
  votes_visible: PollVotesVisible;
}

export interface ChoicePoll extends PollBase {
  kind: "choice";
  options: PollOption[];
  max_choices: number;
}

export interface DatePoll extends PollBase {
  kind: "date";
  slots: PollSlot[];
}

/** A checked poll (the fields of PROTOCOL.md §7g; unknown fields of the content are not kept here). */
export type Poll = ChoicePoll | DatePoll;

/** The vote content (inside the record). */
export interface PollVoteContent {
  type: "poll.vote";
  choices?: string[];
  answers?: Record<string, PollAnswer>;
  voted_at: string;
  ctx: { poll: string; poll_hash: string };
}

const ID = /^[A-Za-z0-9_-]{1,32}$/;
/** RFC 3339 date-time with seconds and an offset (the same pattern the node checks). */
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const HASH = /^[0-9a-f]{64}$/;
const RESULTS = new Set<string>(["always", "after_vote", "after_close"]);
const VOTES = new Set<string>(["public", "hidden_until_close"]);
const ANSWERS = new Set<string>(["yes", "maybe", "no"]);

const chars = (s: string) => Array.from(s).length;
const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** An RFC 3339 date-time with an offset (never a floating local time), as polls and votes use them. */
export function isPollTime(v: unknown): v is string {
  return typeof v === "string" && RFC3339.test(v) && Number.isFinite(Date.parse(v));
}

function text(v: unknown, max: number): string | null {
  if (typeof v !== "string") return null;
  const t = v.trim();
  return t && chars(t) <= max ? t : null;
}

function uniqueIds(list: { id: string }[]): boolean {
  return new Set(list.map((x) => x.id)).size === list.length;
}

/**
 * Checks a (decrypted or plaintext) content object against PROTOCOL.md §7g; null when it is no valid poll (clients
 * show it like an unknown type). `ctx` and unknown fields are ignored.
 */
export function parsePoll(content: unknown): Poll | null {
  if (!isObject(content) || content.type !== POLL_TYPE) return null;
  const question = text(content.question, POLL_LIMITS.question);
  if (!question || typeof content.results_visible !== "string" || !RESULTS.has(content.results_visible)) return null;
  if (typeof content.votes_visible !== "string" || !VOTES.has(content.votes_visible)) return null;
  const base = { question, results_visible: content.results_visible as PollResultsVisible, votes_visible: content.votes_visible as PollVotesVisible };
  if (content.kind === "choice") {
    const raw = content.options;
    if (!Array.isArray(raw) || raw.length < POLL_LIMITS.minOptions || raw.length > POLL_LIMITS.maxOptions) return null;
    const options: PollOption[] = [];
    for (const o of raw) {
      if (!isObject(o) || typeof o.id !== "string" || !ID.test(o.id)) return null;
      const label = text(o.label, POLL_LIMITS.label);
      if (!label) return null;
      options.push({ id: o.id, label });
    }
    const max = content.max_choices;
    if (!uniqueIds(options) || typeof max !== "number" || !Number.isInteger(max) || max < 1 || max > options.length) return null;
    return { kind: "choice", ...base, options, max_choices: max };
  }
  if (content.kind === "date") {
    const raw = content.slots;
    if (!Array.isArray(raw) || raw.length < POLL_LIMITS.minSlots || raw.length > POLL_LIMITS.maxSlots) return null;
    const slots: PollSlot[] = [];
    for (const s of raw) {
      if (!isObject(s) || typeof s.id !== "string" || !ID.test(s.id) || !isPollTime(s.start)) return null;
      const slot: PollSlot = { id: s.id, start: s.start };
      if (s.end !== undefined && s.end !== null) {
        if (!isPollTime(s.end) || Date.parse(s.end) <= Date.parse(s.start)) return null;
        slot.end = s.end;
      }
      if (s.all_day !== undefined && s.all_day !== null) {
        if (typeof s.all_day !== "boolean") return null;
        if (s.all_day) slot.all_day = true;
      }
      slots.push(slot);
    }
    if (!uniqueIds(slots)) return null;
    return { kind: "date", ...base, slots };
  }
  return null;
}

/** What a poll composer collects; {@link pollContent} turns it into the content object. */
export type PollInput =
  | { kind: "choice"; question: string; options: (string | PollOption)[]; maxChoices?: number; resultsVisible?: PollResultsVisible; votesVisible?: PollVotesVisible }
  | { kind: "date"; question: string; slots: (PollSlot | { start: string; end?: string; allDay?: boolean })[]; resultsVisible?: PollResultsVisible; votesVisible?: PollVotesVisible };

/**
 * The content object of a new poll (without `ctx`: the encrypting layer adds the message context). Options given as
 * plain labels get the ids `o1`, `o2`, …, slots without an id `s1`, `s2`, …. Throws RangeError when the result breaks
 * PROTOCOL.md §7g.
 */
export function pollContent(input: PollInput): Record<string, unknown> {
  const common = { type: POLL_TYPE, question: input.question.trim(), results_visible: input.resultsVisible ?? "always", votes_visible: input.votesVisible ?? "public" };
  let content: Record<string, unknown>;
  if (input.kind === "choice") {
    const options = input.options.map((o, i) => (typeof o === "string" ? { id: `o${i + 1}`, label: o.trim() } : { id: o.id, label: o.label.trim() }));
    content = { ...common, kind: "choice", options, max_choices: input.maxChoices ?? 1 };
  } else {
    const slots = input.slots.map((s, i) => {
      const out: Record<string, unknown> = { id: "id" in s && typeof s.id === "string" ? s.id : `s${i + 1}`, start: s.start };
      if (s.end) out.end = s.end;
      if (("all_day" in s && s.all_day) || ("allDay" in s && s.allDay)) out.all_day = true;
      return out;
    });
    content = { ...common, kind: "date", slots };
  }
  if (!parsePoll(content)) throw new RangeError("invalid poll (PROTOCOL.md §7g)");
  return content;
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * `poll_hash`: lowercase hex SHA-256 of the JCS form of the poll content as the client holds it (decrypted, or the
 * plaintext object), without its `ctx` member. Unknown fields are part of the hash.
 */
export async function pollHash(content: Record<string, unknown>): Promise<string> {
  const { ctx: _ctx, ...rest } = content;
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(jcs(rest)));
  return hex(digest);
}

/** The voter's choice: option ids of a choice poll, or answers per slot of a date poll. */
export type PollSelection = { choices: string[] } | { answers: Record<string, PollAnswer> };

/** Does the selection fit the poll (known ids, 1 to `max_choices` distinct choices, at least one answer)? */
export function selectionFits(poll: Poll, sel: { choices?: unknown; answers?: unknown }): boolean {
  if (poll.kind === "choice") {
    if (sel.answers !== undefined || !Array.isArray(sel.choices)) return false;
    const ids = new Set(poll.options.map((o) => o.id));
    const c = sel.choices as unknown[];
    return c.length >= 1 && c.length <= poll.max_choices && new Set(c).size === c.length && c.every((x) => typeof x === "string" && ids.has(x));
  }
  if (sel.choices !== undefined || !isObject(sel.answers)) return false;
  const ids = new Set(poll.slots.map((s) => s.id));
  const entries = Object.entries(sel.answers);
  return entries.length >= 1 && entries.every(([k, v]) => ids.has(k) && typeof v === "string" && ANSWERS.has(v));
}

/**
 * The vote content for a poll message: `messageId` and `hash` ({@link pollHash}) bind it to exactly this poll. Throws
 * RangeError when the selection does not fit the poll.
 */
export function pollVoteContent(poll: Poll, messageId: string, hash: string, selection: PollSelection, now: Date = new Date()): PollVoteContent {
  if (!selectionFits(poll, selection)) throw new RangeError("the selection does not fit the poll");
  if (!HASH.test(hash)) throw new RangeError("poll_hash must be lowercase hex SHA-256");
  const vote: PollVoteContent = { type: POLL_VOTE_TYPE, voted_at: now.toISOString().replace(/\.\d{3}Z$/, "Z"), ctx: { poll: messageId, poll_hash: hash } };
  if ("choices" in selection) vote.choices = [...selection.choices];
  else vote.answers = { ...selection.answers };
  return vote;
}

/** Why a vote record is not counted (besides the decryption and signature failures). */
export type VoteRejection =
  /** Cast on another version of the poll (an edited poll): shown as "voted on an earlier version". */
  | "stale"
  /** Bound to another poll (`ctx.poll`), or a malformed `ctx`. */
  | "envelope_mismatch"
  /** Not a vote, or the choices do not fit the poll. */
  | "invalid";

/** A record as a countable vote, or why it does not count. */
export type VoteCheck =
  | { ok: true; vote: PollVoteContent; selection: PollSelection; unverified?: true }
  | { ok: false; reason: VoteRejection | DecryptFailure | "bad_signature" | "replay" };

/**
 * Checks a decrypted (or plaintext) vote content against the poll the client renders (PROTOCOL.md §7g "Receivers",
 * steps 2 and 3).
 */
export function parsePollVote(content: unknown, poll: Poll, messageId: string, hash: string): VoteCheck {
  if (!isObject(content) || content.type !== POLL_VOTE_TYPE || !isPollTime(content.voted_at)) return { ok: false, reason: "invalid" };
  const ctx = content.ctx;
  if (!isObject(ctx) || Object.keys(ctx).length !== 2 || typeof ctx.poll !== "string" || typeof ctx.poll_hash !== "string") return { ok: false, reason: "envelope_mismatch" };
  if (ctx.poll !== messageId) return { ok: false, reason: "envelope_mismatch" };
  if (ctx.poll_hash !== hash) return { ok: false, reason: "stale" };
  if (!selectionFits(poll, content)) return { ok: false, reason: "invalid" };
  const selection: PollSelection = poll.kind === "choice" ? { choices: [...(content.choices as string[])] } : { answers: { ...(content.answers as Record<string, PollAnswer>) } };
  return { ok: true, vote: content as unknown as PollVoteContent, selection };
}

/** Encrypts a vote under the conversation's current epoch: the body of `PUT …/poll/vote` (`content`, `epoch`). */
export async function encryptPollVote(mls: Pick<MlsManager, "encrypt">, conversationId: string, vote: PollVoteContent): Promise<{ content: string; epoch: number }> {
  return mls.encrypt(conversationId, vote as unknown as Record<string, unknown>);
}

/**
 * The plaintext signature of a vote in an unencrypted conversation (FEDERATION.md §10.3; `conversation` qualified):
 * empty reply and thread, no `@everyone`, no mentions, no attachments. Null when this device cannot sign.
 */
export function signPlainPollVote(mls: Pick<MlsManager, "signPlaintext">, conversation: string, vote: PollVoteContent): string | null {
  return mls.signPlaintext(conversation, { reply_to: null, thread_id: null, mentions_everyone: false, mentions: [], attachments: [] }, vote as unknown as Record<string, unknown>);
}

/**
 * The id under which a voter's records are decrypted and replay-checked: one per voter, not per poll, so a vote the
 * node serves under another poll fails on its signed `ctx` (`envelope_mismatch`) without spoiling the genuine one.
 */
export function pollVoteRecordId(record: Pick<PollVote, "user">): string {
  return `poll-vote:${record.user}`;
}

/**
 * Checks a vote record (PROTOCOL.md §7g "Receivers", steps 1–3): encrypted content is decrypted and verified against
 * the voter's device ({@link MlsManager.decryptPollVote}), plaintext content's signature is checked (unsigned or
 * unverifiable votes count, marked `unverified`; a wrong signature or a replay does not), then the vote is checked
 * against the poll. `conversation` is the qualified id `<node>/<id>`.
 */
export async function checkPollVote(
  mls: Pick<MlsManager, "decryptPollVote" | "verifyPlaintext">,
  conversation: string,
  record: PollVote,
  poll: Poll,
  hash: string,
): Promise<VoteCheck> {
  if (typeof record.content === "string") {
    const d = await mls.decryptPollVote(conversation, record);
    if (!d.ok) return d;
    return parsePollVote(d.content, poll, record.message_id, hash);
  }
  if (!isObject(record.content)) return { ok: false, reason: "invalid" };
  if (new TextEncoder().encode(JSON.stringify(record.content)).length > POLL_LIMITS.voteBytes) return { ok: false, reason: "invalid" };
  let status: PlainStatus;
  try {
    status = await mls.verifyPlaintext(conversation, { id: pollVoteRecordId(record), author: record.user, device_id: record.device_id ?? null, reply_to_id: null, thread_id: null, mentions: [], mentions_everyone: false, attachments: [], content: record.content, signature: record.signature ?? null });
  } catch {
    status = "unverifiable";
  }
  if (status === "invalid") return { ok: false, reason: "bad_signature" };
  if (status === "replay") return { ok: false, reason: "replay" };
  const r = parsePollVote(record.content, poll, record.message_id, hash);
  return r.ok && status !== "valid" ? { ...r, unverified: true } : r;
}

/** A record with its check, as {@link tallyPoll} takes it. */
export interface CheckedVote {
  user: string;
  updated_at: string;
  check: VoteCheck;
}

export interface OptionTally {
  id: string;
  label: string;
  count: number;
  /** Addresses of the voters (for `votes_visible: "public"`; the client hides them while votes are hidden). */
  voters: string[];
}

export interface SlotTally {
  id: string;
  yes: number;
  maybe: number;
  no: number;
  voters: { yes: string[]; maybe: string[]; no: string[] };
  /** `2 × yes + maybe`: the ranking of the best slots. */
  score: number;
}

export interface PollTally {
  kind: PollKind;
  /** `poll_closes_at` has passed. */
  closed: boolean;
  /** Members whose vote counts. */
  voters: number;
  /** Members with a vote record (counted or not): the voter count of a poll the client cannot read. */
  records: number;
  /** Not counted: cast on an earlier version of the poll. */
  stale: number;
  /** Not counted: changed after the close time. */
  late: number;
  /** Not counted: not decryptable or verifiable, malformed, bound to another poll or not fitting the poll. */
  rejected: number;
  /** Counted votes that carry no checkable signature (plaintext conversations). */
  unverified: number;
  options: OptionTally[];
  slots: SlotTally[];
  /** Choice polls: the option ids with the most votes; date polls: the slot ids with the best score (empty without votes). */
  best: string[];
  /** The counted selection per voter (the viewer's own vote included). */
  byUser: Map<string, PollSelection>;
}

/**
 * Counts the votes of a poll (PROTOCOL.md §7g "Receivers"): per member only the newest record counts (the node keeps
 * one; several are tolerated), and only when it checked out, matches this version of the poll and was not changed
 * after `closesAt`. `now` decides `closed`.
 */
export function tallyPoll(poll: Poll, votes: CheckedVote[], opts: { closesAt?: string | null; now?: Date } = {}): PollTally {
  const closesAt = opts.closesAt ? Date.parse(opts.closesAt) : NaN;
  const now = (opts.now ?? new Date()).getTime();
  const newest = new Map<string, CheckedVote>();
  for (const v of votes) {
    const seen = newest.get(v.user);
    if (!seen || Date.parse(v.updated_at) > Date.parse(seen.updated_at)) newest.set(v.user, v);
  }
  const tally: PollTally = {
    kind: poll.kind,
    closed: Number.isFinite(closesAt) && now >= closesAt,
    voters: 0,
    records: newest.size,
    stale: 0,
    late: 0,
    rejected: 0,
    unverified: 0,
    options: poll.kind === "choice" ? poll.options.map((o) => ({ id: o.id, label: o.label, count: 0, voters: [] })) : [],
    slots: poll.kind === "date" ? poll.slots.map((s) => ({ id: s.id, yes: 0, maybe: 0, no: 0, voters: { yes: [], maybe: [], no: [] }, score: 0 })) : [],
    best: [],
    byUser: new Map(),
  };
  for (const [user, v] of [...newest].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (!v.check.ok) {
      if (v.check.reason === "stale") tally.stale++;
      else tally.rejected++;
      continue;
    }
    if (Number.isFinite(closesAt) && Date.parse(v.updated_at) > closesAt) {
      tally.late++;
      continue;
    }
    const sel = v.check.selection;
    tally.voters++;
    if (v.check.unverified) tally.unverified++;
    tally.byUser.set(user, sel);
    if ("choices" in sel) {
      for (const id of sel.choices) {
        const o = tally.options.find((x) => x.id === id);
        if (o) {
          o.count++;
          o.voters.push(user);
        }
      }
    } else {
      for (const [id, a] of Object.entries(sel.answers)) {
        const s = tally.slots.find((x) => x.id === id);
        if (!s) continue;
        s[a]++;
        s.voters[a].push(user);
      }
    }
  }
  if (poll.kind === "choice") {
    const top = Math.max(0, ...tally.options.map((o) => o.count));
    tally.best = top > 0 ? tally.options.filter((o) => o.count === top).map((o) => o.id) : [];
  } else {
    for (const s of tally.slots) s.score = 2 * s.yes + s.maybe;
    const top = Math.max(0, ...tally.slots.map((s) => s.score));
    tally.best = top > 0 ? tally.slots.filter((s) => s.score === top).map((s) => s.id) : [];
  }
  return tally;
}

/**
 * Whether the viewer may see the results now (`results_visible`, cooperative): always, after their own vote, or after
 * the close. And whether the voters' names may be shown (`votes_visible`).
 */
export function pollVisibility(poll: Poll, tally: Pick<PollTally, "closed">, hasVoted: boolean): { results: boolean; voters: boolean } {
  const results = poll.results_visible === "always" || (poll.results_visible === "after_vote" && (hasVoted || tally.closed)) || tally.closed;
  return { results, voters: results && (poll.votes_visible === "public" || tally.closed) };
}
