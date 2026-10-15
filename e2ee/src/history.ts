// SPDX-License-Identifier: MPL-2.0
/**
 * History for new members of encrypted channels (ENCRYPTION.md §7b, design note 4.13 item 11).
 *
 * Members hand the content keys of past epochs to a member who joined later, as far as the channel's policy
 * allows; under every policy that includes the epochs between the member's room join and its device's first leaf
 * (the device enters a channel's group only when the channel is opened or the room loaded). A share is never a chat message: it is the canonical JSON payload
 * `{type: "history_keys", v, conversation, to, epochs: [[epoch, key], …]}` encrypted and signed like
 * message content (§5.2), posted to `…/history-keys` of the node hosting the conversation. Format 2 (node capability
 * `history.shares2`): under a fresh key sealed to the verified share key of every device of the recipient, so only
 * those devices can read it. Format 1 (under the conversation's current epoch, readable by every leaf) is never sent;
 * it is still read for shares older clients left on the node. The recipient verifies the signature against an attested device in the group,
 * checks every key against a stored message of its epoch, signed by its author's attested device (no poisoned keys) and keeps accepted keys only
 * in the key store (the MLS client state, which is also what the history backup carries).
 *
 * The pure parts (policy, windows, chunking, sharer election, payload codec, key check) are exported for
 * tests; {@link HistorySync} runs the flows of one device.
 */
import { b64urlDecode, b64urlEncode, jcs, type HistoryPendingList, type HistoryShareList, type CreateHistoryShareRequest, type Message } from "@tavrn/sdk";
import { splitIdentity, splitQualified, type MlsManager } from "./mls";

export const HISTORY_KEYS_TYPE = "history_keys";
/** Boxes per format 2 share accepted by nodes (devices of the recipient). */
export const MAX_SHARE_BOXES = 20;
/** Epochs per share accepted by nodes (`epoch_to - epoch_from + 1`). */
export const MAX_EPOCHS_PER_SHARE = 1000;
/** Epochs per share sent by this client: keeps a share well below the node's 64 KiB limit. */
export const SHARE_CHUNK = 500;
/** Members that are not the elected sharer wait this long (times their rank) before sharing themselves. */
export const SHARER_BACKOFF_MS = 60_000;
const DAY_MS = 24 * 3600 * 1000;

export type HistoryPolicy = { kind: "since_join" } | { kind: "days"; days: number } | { kind: "all" };

/** Parses a channel's `history_for_new_members`; anything unknown is `since_join` (the safe default). */
export function parseHistoryPolicy(value: string | null | undefined): HistoryPolicy {
  if (value === "all") return { kind: "all" };
  const m = /^days:([1-9][0-9]{0,3})$/.exec(value ?? "");
  if (m) {
    const days = Number(m[1]);
    if (days >= 1 && days <= 3650) return { kind: "days", days };
  }
  return { kind: "since_join" };
}

/**
 * Does the policy give new members anything from before their join? Members wait for shares under every policy (the
 * messages since their join that were posted before their device entered the group), this only tells the settings.
 */
export function grantsHistory(p: HistoryPolicy): boolean {
  return p.kind !== "since_join";
}

/**
 * Start of the history a member gets (milliseconds): the join for `since_join`, `n` days before it for
 * `days:n`, null (everything) for `all`. Same rule as the node's cut of `GET …/messages`.
 */
export function historyWindowStart(p: HistoryPolicy, joinedAtMs: number): number | null {
  if (p.kind === "all") return null;
  if (p.kind === "days") return joinedAtMs - p.days * DAY_MS;
  return joinedAtMs;
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** The smallest ULID of millisecond `ms` (message ids are ULIDs; `after` cursors use it). */
export function ulidFloor(ms: number): string {
  let t = Math.max(0, Math.floor(ms));
  let head = "";
  for (let i = 0; i < 10; i++) {
    head = CROCKFORD[t % 32] + head;
    t = Math.floor(t / 32);
  }
  return `${head}0000000000000000`;
}

/**
 * Epochs to share with a new member: the device's known epochs older than the current one (the member has
 * the current epoch itself), limited to `fromEpoch` (the oldest epoch with a message in the window; null: none) and
 * later for a day window and for `since_join` (the window starts at the join).
 */
export function epochsToShare(p: HistoryPolicy, known: number[], current: number, fromEpoch: number | null): number[] {
  const lower = p.kind === "all" ? 0 : (fromEpoch ?? Number.POSITIVE_INFINITY);
  return [...new Set(known)].filter((e) => Number.isSafeInteger(e) && e >= lower && e < current).sort((a, b) => a - b);
}

/**
 * Epochs to share automatically with a member whose key was reset (ENCRYPTION.md §7b "History after a key reset"):
 * the device's known epochs older than the current one, from the oldest epoch with content after the reset
 * (`fromEpoch`, null: nothing since the reset) and never below `minEpoch` (the reset epoch + 1). Everything older is
 * restored only by an approved request.
 */
export function epochsSinceReset(known: number[], current: number, fromEpoch: number | null, minEpoch: number | null): number[] {
  if (fromEpoch === null) return [];
  const lower = Math.max(fromEpoch, minEpoch ?? fromEpoch);
  return [...new Set(known)].filter((e) => Number.isSafeInteger(e) && e >= lower && e < current).sort((a, b) => a - b);
}

/**
 * The longest gap between a member's room join and its first leaf that automatic shares fill (the lifetime of a
 * pending mark, §7b): a `since` the node reports earlier than this before this device saw the member's first leaf is
 * moved up to it.
 */
export const MAX_JOIN_GAP_MS = 30 * 24 * 3600 * 1000;

/** The join used for a waiting member's window: the node's `since`, bounded by when this device saw the member. */
export function boundedJoin(sinceMs: number, seenAtMs: number): number {
  const floor = seenAtMs - MAX_JOIN_GAP_MS;
  return Number.isFinite(sinceMs) ? Math.max(sinceMs, floor) : seenAtMs;
}

/**
 * Splits ascending epochs into shares of at most `max` epochs whose range (`last - first + 1`) stays within
 * {@link MAX_EPOCHS_PER_SHARE}.
 */
export function chunkEpochs(epochs: number[], max = SHARE_CHUNK): number[][] {
  const sorted = [...new Set(epochs)].sort((a, b) => a - b);
  const out: number[][] = [];
  let cur: number[] = [];
  for (const e of sorted) {
    if (cur.length && (cur.length >= max || e - cur[0]! >= MAX_EPOCHS_PER_SHARE)) {
      out.push(cur);
      cur = [];
    }
    cur.push(e);
  }
  if (cur.length) out.push(cur);
  return out;
}

/**
 * Deterministic choice of the sharing device: the lowest device identity among `candidates` (online members'
 * devices in the group, this one included) shares at once, the others wait `backoff × rank`. The device that
 * committed the member's Add (`preferred`) shares at once.
 */
export function sharerDelay(self: string, candidates: string[], preferred = false, backoff = SHARER_BACKOFF_MS): number {
  if (preferred) return 0;
  const sorted = [...new Set([...candidates, self])].sort();
  return sorted.indexOf(self) * backoff;
}

export interface HistoryPayload {
  type: typeof HISTORY_KEYS_TYPE;
  /** Share format: 1 (under the epoch key) or 2 (sealed per recipient device). */
  v: 1 | 2;
  /** Qualified conversation id. */
  conversation: string;
  /** Recipient address. */
  to: string;
  /** `[epoch, base64url content key]`, ascending. */
  epochs: [number, string][];
}

/** The canonical JSON of a share payload (the bytes the device signature covers). */
export function encodeHistoryPayload(conversation: string, to: string, keys: [number, Uint8Array][], v: 1 | 2 = 1): string {
  const payload: HistoryPayload = { type: HISTORY_KEYS_TYPE, v, conversation, to, epochs: keys.map(([e, k]) => [e, b64urlEncode(k)]) };
  return jcs(payload);
}

/**
 * Checks a decrypted share payload against what the share claims: type and version, conversation, recipient,
 * every epoch an integer within `[epochFrom, epochTo]` at most once, every key 32 bytes. Returns the keys
 * (caller zeroes them) or null when anything is off (the whole share is rejected).
 */
export function parseHistoryPayload(
  content: Record<string, unknown>,
  expected: { conversation: string; to: string; epochFrom: number; epochTo: number; v?: 1 | 2 },
): [number, Uint8Array][] | null {
  const keys = new Set(Object.keys(content));
  if (keys.size !== 5 || !["type", "v", "conversation", "to", "epochs"].every((k) => keys.has(k))) return null;
  if (content.type !== HISTORY_KEYS_TYPE || content.v !== (expected.v ?? 1)) return null;
  if (content.conversation !== expected.conversation || content.to !== expected.to) return null;
  if (!Array.isArray(content.epochs) || content.epochs.length > MAX_EPOCHS_PER_SHARE) return null;
  const out: [number, Uint8Array][] = [];
  const seen = new Set<number>();
  for (const entry of content.epochs as unknown[]) {
    if (!Array.isArray(entry) || entry.length !== 2) return null;
    const [epoch, key] = entry as [unknown, unknown];
    if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < expected.epochFrom || epoch > expected.epochTo || seen.has(epoch)) return null;
    if (typeof key !== "string") return null;
    let bytes: Uint8Array;
    try {
      bytes = b64urlDecode(key);
    } catch {
      return null;
    }
    if (bytes.length !== 32) return null;
    seen.add(epoch);
    out.push([epoch, bytes]);
  }
  return out;
}

function str16(s: string): Uint8Array {
  const b = new TextEncoder().encode(s);
  const out = new Uint8Array(2 + b.length);
  out[0] = (b.length >> 8) & 0xff;
  out[1] = b.length & 0xff;
  out.set(b, 2);
  return out;
}

function u64(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

/** History keys checked at once while a share is received (each check fetches the samples of its epoch). */
export const KEY_CHECK_CONCURRENCY = 6;

/** Runs `fn` for every item, at most `limit` at a time. */
async function eachLimited<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) await fn(items[next++]!);
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

/** A stored message used to check a key: author, device, epoch and the `content` value (§5.2). */
export interface KeySample {
  author: string;
  device_id: string;
  epoch: number;
  content: string;
}

/**
 * Does `key` open the AES-256-GCM ciphertext of `sample` (§5.2: same AAD, nonce and tag)? A key that does
 * not reproduce the authentication tag of a real message of its epoch is rejected.
 */
export async function epochKeyOpens(key: Uint8Array, conversation: string, sample: KeySample): Promise<boolean> {
  let bytes: Uint8Array;
  try {
    bytes = b64urlDecode(sample.content);
  } catch {
    return false;
  }
  if (key.length !== 32 || bytes.length < 1 + 8 + 12 + 16 + 64 || bytes[0] !== 1) return false;
  const epoch = Number(new DataView(bytes.buffer, bytes.byteOffset + 1, 8).getBigUint64(0));
  if (epoch !== sample.epoch) return false;
  const aad = concat(new Uint8Array([1]), str16(conversation), u64(epoch), str16(sample.author), str16(sample.device_id));
  try {
    const k = await crypto.subtle.importKey("raw", concat(key), "AES-GCM", false, ["decrypt"]);
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: concat(bytes.subarray(9, 21)), additionalData: aad, tagLength: 128 }, k, concat(bytes.subarray(21)));
    return true;
  } catch {
    return false;
  }
}

/**
 * The messages that can check a key of `epoch`, in the order they are tried: encrypted messages of that epoch, those
 * not written by the sharer first (a sharer could plant a message under a forged key and then "prove" that key with
 * it), the sharer's own last.
 */
export function pickSamples(messages: Pick<Message, "author" | "device_id" | "epoch" | "content" | "encrypted">[], epoch: number, sharer: string): KeySample[] {
  const usable = messages.filter((m) => m.encrypted && m.epoch === epoch && typeof m.content === "string" && !!m.device_id);
  const ordered = [...usable.filter((x) => x.author !== sharer), ...usable.filter((x) => x.author === sharer)];
  return ordered.map((m) => ({ author: m.author, device_id: m.device_id!, epoch, content: m.content as string }));
}

/** The first message of {@link pickSamples}: the one that checks a key of `epoch` when its author device is known. */
export function pickSample(messages: Pick<Message, "author" | "device_id" | "epoch" | "content" | "encrypted">[], epoch: number, sharer: string): KeySample | null {
  return pickSamples(messages, epoch, sharer)[0] ?? null;
}

// ---- Flows ---------------------------------------------------------------------------------------

/** The routes of the node hosting a conversation (bare conversation ids). */
export interface HistoryApi {
  share(conversationId: string, req: CreateHistoryShareRequest): Promise<unknown>;
  shares(conversationId: string): Promise<HistoryShareList>;
  ack(conversationId: string, shareId: string): Promise<unknown>;
  pending(conversationId: string): Promise<HistoryPendingList>;
  /**
   * `GET …/messages`; `threads: "all"` includes the messages of the channel's threads (forum posts), which the window
   * lookups need: a thread message is content of the channel like any other.
   */
  messages(conversationId: string, query: { limit?: number; after?: string; before?: string; epoch?: number; threads?: "all" }): Promise<Message[]>;
}

/** Channel kinds whose content is messages (others, such as files channels, keep records, FILES.md §8.7). */
const MESSAGE_KINDS = new Set(["text", "announcement", "forum"]);

/** One encrypted channel of a restore request (`HistoryRequest.channels`), times in milliseconds. */
export interface RestoreChannel {
  kind: string;
  /** The requester's normal window start; null = everything. */
  windowStart: number | null;
}

/** What this device can restore in one channel: the epochs it would send and how many of the window it lacks. */
export interface RestorePlan {
  epochs: number[];
  /** Epochs of the window this device does not hold (or cannot tell: `unknown`). */
  missing: number;
  unknown: boolean;
}

export interface HistorySyncDeps {
  mls: MlsManager;
  /** Own address and device id. */
  address: string;
  deviceId: string;
  /** Routes of node `domain`. */
  api(domain: string): HistoryApi;
  /** Is `address` online (presence)? This user counts as online. */
  isOnline(address: string): boolean;
  /**
   * The time of `address`'s last identity reset from its keys document (`identity_reset_at`, ENCRYPTION.md §2.3),
   * null if none: with nodes that do not report `key_reset_at`, a recipient reset after its join gets automatic shares
   * only from the reset on.
   */
  resetAt?(address: string): Promise<number | null>;
  /**
   * The oldest epoch of a non-message channel's encrypted content after `sinceMs` (files channels: `GET
   * records?since=`, FILES.md §8.7); null when there is none. Without it such channels are restored only for a window
   * without start.
   */
  firstEpoch?(conversation: string, kind: string, sinceMs: number): Promise<number | null>;
  /**
   * Whether node `domain` announces `history.shares2` (ENCRYPTION.md §7b "Format v2"); without it (or false) no share
   * is sent at all (format 1 is not sent any more).
   */
  shares2?(domain: string): boolean | Promise<boolean>;
  /**
   * Something went wrong with a share, or a share was not sent (`share_skipped`: no format 2 possible, the node lacks
   * `history.shares2` or a device of the recipient has no verified share key); never carries keys or payloads.
   */
  onLog?(event: "share_rejected" | "share_failed" | "keys_rejected" | "share_skipped", conversation: string): void;
  backoffMs?: number;
  setTimer?(fn: () => void, ms: number): unknown;
  clearTimer?(t: unknown): void;
}

/**
 * The history-sharing flows of one device: as a sharer (members marked `history_pending`, an Add this
 * device committed) and as a recipient (`history.keys_available`, channel open). Conversations are
 * qualified ids; `policy` is the channel's current `history_for_new_members`.
 */
export class HistorySync {
  /** When this device first saw a leaf of a waiting member in a group (`q|address` → ms): bounds the node's `since`. */
  private readonly firstSeen = new Map<string, number>();
  private readonly shared = new Set<string>();
  private readonly rejected = new Set<string>();
  private readonly timers = new Map<string, unknown>();
  private readonly preferred = new Map<string, Set<string>>();
  private readonly receiving = new Map<string, Promise<number>>();
  private readonly receiveQueued = new Map<string, Promise<number>>();
  private disposed = false;

  constructor(private readonly deps: HistorySyncDeps) {}

  private api(q: string): { api: HistoryApi; id: string } {
    const { domain, id } = splitQualified(q);
    return { api: this.deps.api(domain), id };
  }

  /** This device committed the Add of these users (MlsEvent `added`): it shares at once when they are pending. */
  noteAdded(q: string, addresses: string[]): void {
    const set = this.preferred.get(q) ?? new Set<string>();
    for (const a of addresses) {
      set.add(a);
      this.seen(q, a);
    }
    this.preferred.set(q, set);
  }

  /**
   * Members of `q` who wait for keys: share now when this device is elected, otherwise after the back-off
   * and only if they still wait.
   */
  async checkPending(q: string, policy: HistoryPolicy): Promise<void> {
    if (this.disposed || !this.deps.mls.hasGroup(q)) return;
    const { api, id } = this.api(q);
    const { items } = await api.pending(id);
    if (!items.length) return;
    // The member's join commit may still be on the way (`mls.commit` arrives with `history.pending`).
    await this.deps.mls.catchUp(q).catch(() => undefined);
    const self = `${this.deps.address}/${this.deps.deviceId}`;
    for (const entry of items) {
      if (entry.user === this.deps.address) continue;
      const key = `${q}|${entry.user}|${entry.since}`;
      if (this.shared.has(key) || this.timers.has(key)) continue;
      const roster = this.deps.mls.roster(q);
      // Without a device of the recipient in the group nobody can encrypt for it yet.
      if (!roster.some((i) => splitIdentity(i).address === entry.user)) continue;
      const candidates = roster.filter((i) => {
        const a = splitIdentity(i).address;
        return a !== entry.user && (a === this.deps.address || this.deps.isOnline(a));
      });
      const delay = sharerDelay(self, candidates, !!this.preferred.get(q)?.has(entry.user), this.deps.backoffMs ?? SHARER_BACKOFF_MS);
      // The join as the node reports it, but never earlier than this device's own knowledge allows (§7b step 2).
      const joinedAt = boundedJoin(Date.parse(entry.since), this.seen(q, entry.user));
      const reset = await this.resetOf(entry);
      const go = async () => {
        this.timers.delete(key);
        if (this.disposed) return;
        if (delay > 0) {
          const again = await api.pending(id).catch(() => null);
          if (!again?.items.some((i) => i.user === entry.user && i.since === entry.since)) return;
        }
        this.shared.add(key);
        try {
          if (reset) await this.shareSinceReset(q, entry.user, reset.at, reset.minEpoch);
          else await this.shareWith(q, entry.user, joinedAt, policy);
        } catch {
          this.deps.onLog?.("share_failed", q);
        }
      };
      if (delay === 0) await go();
      else this.timers.set(key, (this.deps.setTimer ?? setTimeout)(() => void go(), delay));
    }
  }

  /** When this device first saw `address` waiting in `q` with a leaf in the group (recorded now if not yet). */
  private seen(q: string, address: string): number {
    const k = `${q}|${address}`;
    let at = this.firstSeen.get(k);
    if (at === undefined) {
      at = Date.now();
      this.firstSeen.set(k, at);
    }
    return at;
  }

  /**
   * The key reset of a waiting member: from the node (`key_reset_at`, `min_epoch`) or, with nodes that do not report
   * it, from the member's keys document when the reset is later than the pending mark's `since`.
   */
  private async resetOf(entry: { user: string; since: string; key_reset_at?: string | null; min_epoch?: number | null }): Promise<{ at: number; minEpoch: number | null } | null> {
    if (entry.key_reset_at) {
      const at = Date.parse(entry.key_reset_at);
      if (Number.isFinite(at)) return { at, minEpoch: entry.min_epoch ?? null };
    }
    const at = this.deps.resetAt ? await this.deps.resetAt(entry.user).catch(() => null) : null;
    const since = Date.parse(entry.since);
    return at !== null && Number.isFinite(at) && (!Number.isFinite(since) || at > since) ? { at, minEpoch: null } : null;
  }

  /**
   * Automatic shares for a member whose key was reset: only epochs since the reset (ENCRYPTION.md §7b "History after a
   * key reset"); without `minEpoch` from the node nothing up to the epoch of the newest message before the reset, and
   * nothing at all when that cannot be read.
   */
  async shareSinceReset(q: string, to: string, resetAtMs: number, minEpoch: number | null): Promise<number> {
    const { api, id } = this.api(q);
    const mls = this.deps.mls;
    const current = mls.epoch(q);
    if (current === null) return 0;
    const after = await api.messages(id, { after: ulidFloor(resetAtMs), limit: 20, threads: "all" });
    const since = after.filter((m) => m.encrypted && typeof m.epoch === "number").map((m) => m.epoch as number);
    let lower = minEpoch;
    if (lower === null) {
      const before = await api.messages(id, { before: ulidFloor(resetAtMs), limit: 1, threads: "all" });
      const last = before.find((m) => m.encrypted && typeof m.epoch === "number");
      lower = last ? (last.epoch as number) + 1 : 0;
    }
    const epochs = epochsSinceReset(mls.knownEpochs(q), current, since.length ? Math.min(...since) : null, lower);
    return this.sendChunks(q, to, epochs);
  }

  /** The oldest epoch with encrypted content after `startMs` (null start: from the beginning). */
  private async firstEpoch(q: string, channel: RestoreChannel): Promise<number | null | undefined> {
    const { api, id } = this.api(q);
    if (MESSAGE_KINDS.has(channel.kind)) {
      const page = await api.messages(id, { after: ulidFloor(channel.windowStart ?? 0), limit: 20, threads: "all" });
      const epochs = page.filter((m) => m.encrypted && typeof m.epoch === "number").map((m) => m.epoch as number);
      return epochs.length ? Math.min(...epochs) : null;
    }
    if (channel.windowStart === null) return 0;
    // Another kind with a window start: only its own listing knows (undefined = cannot tell).
    return this.deps.firstEpoch ? this.deps.firstEpoch(q, channel.kind, channel.windowStart) : undefined;
  }

  /**
   * What this device can restore of a requester's window in `q` (ENCRYPTION.md §7b): every epoch it holds from the
   * window's oldest content up to the epoch before the current one, and how many of those it lacks.
   */
  async restorePlan(q: string, channel: RestoreChannel): Promise<RestorePlan> {
    const current = this.deps.mls.epoch(q);
    if (current === null || !this.deps.mls.hasGroup(q)) return { epochs: [], missing: 0, unknown: true };
    const from = await this.firstEpoch(q, channel);
    if (from === undefined) return { epochs: [], missing: 0, unknown: true };
    if (from === null) return { epochs: [], missing: 0, unknown: false };
    const epochs = [...new Set(this.deps.mls.knownEpochs(q))].filter((e) => Number.isSafeInteger(e) && e >= from && e < current).sort((a, b) => a - b);
    return { epochs, missing: Math.max(0, current - from - epochs.length), unknown: false };
  }

  /**
   * After approving a restore request: sends the keys of the requester's window in `q` from this device (restore
   * shares, which the node accepts only from members with `restore_history` while the restore is valid). Nothing is
   * sent while no device of the requester is in the group.
   */
  async restore(q: string, to: string, channel: RestoreChannel): Promise<RestorePlan & { sent: number; skipped: boolean }> {
    if (this.disposed || !this.deps.mls.hasGroup(q)) return { epochs: [], missing: 0, unknown: true, sent: 0, skipped: true };
    await this.deps.mls.catchUp(q).catch(() => undefined);
    // A device of the requester attested under its current key (old leaves from before the reset do not count).
    const attested = await this.deps.mls.verifiedDevices(to, true).catch(() => null);
    const present = this.deps.mls.roster(q).some((i) => {
      const { address, deviceId } = splitIdentity(i);
      return address === to && (!attested || attested.has(deviceId));
    });
    if (!present) return { epochs: [], missing: 0, unknown: true, sent: 0, skipped: true };
    const plan = await this.restorePlan(q, channel);
    const sent = plan.epochs.length ? await this.sendChunks(q, to, plan.epochs) : 0;
    return { ...plan, sent, skipped: false };
  }

  /**
   * Sends the keys of the policy's window to `to` (chunked); an empty share if there is nothing to send. The window
   * starts `n` days before the join (`days:n`), at the join (`since_join`: the messages posted before the member's
   * device entered the group) or nowhere (`all`).
   */
  async shareWith(q: string, to: string, joinedAtMs: number, policy: HistoryPolicy): Promise<number> {
    const { api, id } = this.api(q);
    const mls = this.deps.mls;
    const current = mls.epoch(q);
    if (current === null) return 0;
    let fromEpoch: number | null = null;
    if (policy.kind !== "all") {
      // The oldest epoch with a message in the window (ascending page after the window start).
      const start = historyWindowStart(policy, Number.isFinite(joinedAtMs) ? joinedAtMs : Date.now()) ?? 0;
      const page = await api.messages(id, { after: ulidFloor(start), limit: 20, threads: "all" });
      const epochs = page.filter((m) => m.encrypted && typeof m.epoch === "number").map((m) => m.epoch as number);
      fromEpoch = epochs.length ? Math.min(...epochs) : null;
    }
    const epochs = epochsToShare(policy, mls.knownEpochs(q), current, fromEpoch);
    return this.sendChunks(q, to, epochs);
  }

  /**
   * The share keys to seal a format 2 share to (ENCRYPTION.md §7b "Sharing" step 0): when the hosting node announces
   * `history.shares2` and every attested device of `to` in the current roster has a verified share key, device id →
   * share key; otherwise null (format 1). Leaves of `to` that are not attested (old leaves after a key reset) cannot
   * receive keys anyway and do not count.
   */
  private async shareKeysFor(q: string, to: string): Promise<Record<string, Uint8Array> | null> {
    if (!(await this.deps.shares2?.(splitQualified(q).domain))) return null;
    const mls = this.deps.mls;
    await mls.catchUp(q).catch(() => undefined);
    const inRoster = [...new Set(mls.roster(q).map(splitIdentity).filter((i) => i.address === to).map((i) => i.deviceId))];
    let attested = await mls.verifiedDevices(to).catch(() => null);
    // A device the cached lookup does not know yet (it joined since): look the user's devices up again.
    const refresh = !attested || inRoster.some((d) => !attested!.has(d));
    if (refresh) {
      mls.forgetDevices(to);
      attested = await mls.verifiedDevices(to).catch(() => null);
    }
    const keys = await mls.verifiedShareKeys(to).catch(() => null);
    if (!attested || !keys) return null;
    const devices = inRoster.filter((d) => attested!.has(d));
    if (!devices.length || devices.length > MAX_SHARE_BOXES || !devices.every((d) => keys.has(d))) return null;
    return Object.fromEntries(devices.map((d) => [d, keys.get(d)!]));
  }

  /** Encrypts and posts `epochs` for `to` in chunks; one empty share when there are none (it clears a pending mark). */
  private async sendChunks(q: string, to: string, epochs: number[]): Promise<number> {
    const { api, id } = this.api(q);
    const mls = this.deps.mls;
    const chunks = epochs.length ? chunkEpochs(epochs) : [[]];
    const shareKeys = await this.shareKeysFor(q, to);
    if (!shareKeys) {
      // Format 1 would be readable by every leaf of the group, unattested ones included: nothing is sent.
      this.deps.onLog?.("share_skipped", q);
      return 0;
    }
    let sent = 0;
    for (const chunk of chunks) {
      const keys = mls.exportEpochKeys(q, chunk);
      let json: string;
      try {
        json = encodeHistoryPayload(q, to, keys, 2);
      } finally {
        for (const [, k] of keys) k.fill(0);
      }
      const { content, epoch, boxes } = await mls.encryptHistory(q, json, shareKeys);
      const from = chunk[0] ?? epoch;
      const last = chunk[chunk.length - 1] ?? epoch;
      await api.share(id, { to_user: to, epoch_from: from, epoch_to: last, ciphertext: content, v: 2, boxes });
      sent += keys.length;
    }
    return sent;
  }

  /**
   * Fetches, checks and stores the shares addressed to this user; returns the number of new keys. A call while a pass
   * runs (`history.keys_available` arriving after that pass read the list) queues one more pass after it, shared by
   * every call meanwhile: the running pass may have read the list before the announced share existed.
   */
  receive(q: string): Promise<number> {
    const running = this.receiving.get(q);
    if (!running) return this.startReceive(q);
    const queued = this.receiveQueued.get(q);
    if (queued) return queued;
    const next = running
      .catch(() => 0)
      .then(() => {
        this.receiveQueued.delete(q);
        // A pass started since the running one ended began after this call: it sees what this call was about.
        return this.receiving.get(q) ?? this.startReceive(q);
      });
    this.receiveQueued.set(q, next);
    return next;
  }

  private startReceive(q: string): Promise<number> {
    const p = this.receiveInner(q).finally(() => this.receiving.delete(q));
    this.receiving.set(q, p);
    return p;
  }

  private async receiveInner(q: string): Promise<number> {
    if (this.disposed || !this.deps.mls.hasGroup(q)) return 0;
    const mls = this.deps.mls;
    const { api, id } = this.api(q);
    const { items } = await api.shares(id);
    let total = 0;
    for (const share of items) {
      if (this.rejected.has(share.id)) continue;
      // The sharing device must be in the group; its signature is checked against its attestation.
      if (!mls.roster(q).includes(`${share.from_user}/${share.from_device}`)) {
        this.reject(q, share.id);
        continue;
      }
      // Format 2 (§7b): only with this device's own box; its key takes the place of the epoch key.
      const v = share.v === 2 ? 2 : 1;
      if (share.v !== undefined && share.v !== 1 && share.v !== 2) {
        this.reject(q, share.id);
        continue;
      }
      if (v === 2 && !share.box) {
        this.reject(q, share.id);
        continue;
      }
      const dec = await mls.decryptHistory(q, share.id, share.from_user, share.from_device, share.ciphertext, v === 2 ? share.box! : undefined);
      if (!dec.ok) {
        // A key that is still missing may arrive with the catch-up: try again later.
        if (dec.reason !== "missing_key") this.reject(q, share.id);
        continue;
      }
      const keys = parseHistoryPayload(dec.content, { conversation: q, to: this.deps.address, epochFrom: share.epoch_from, epochTo: share.epoch_to, v });
      if (!keys) {
        this.reject(q, share.id);
        continue;
      }
      const known = new Set(mls.knownEpochs(q));
      const accepted: [number, Uint8Array][] = [];
      let dropped = 0;
      try {
        // One request per epoch (§7b step 4), a few at a time.
        await eachLimited(
          keys.filter(([epoch]) => !known.has(epoch)),
          KEY_CHECK_CONCURRENCY,
          async ([epoch, key]) => {
            const samples = pickSamples(await api.messages(id, { epoch, limit: 10 }).catch(() => []), epoch, share.from_user);
            if (await this.keyProven(q, key, epoch, samples)) accepted.push([epoch, key]);
            else dropped++;
          },
        );
        accepted.sort((a, b) => a[0] - b[0]);
        total += await mls.importHistoryKeys(q, accepted);
      } finally {
        for (const [, k] of keys) k.fill(0);
      }
      if (dropped) this.deps.onLog?.("keys_rejected", q);
      await api.ack(id, share.id).catch(() => undefined);
    }
    return total;
  }

  /**
   * §7b step 4: the key must open a sample of its epoch whose signature verifies with the author's device. A sample
   * the key does not open, or whose signature fails, drops the key; one whose author device cannot be verified at all
   * (such as the recipient's own device from before an identity reset, whose attestation went with the old key) tells
   * nothing and is passed over for the next one. The sharer's own messages come last.
   */
  private async keyProven(q: string, key: Uint8Array, epoch: number, samples: KeySample[]): Promise<boolean> {
    for (const sample of samples) {
      // Tag and signature in one decryption; the tag alone only decides for a sample of an unverifiable device.
      const check = await this.deps.mls.checkSample(q, epoch, key, sample);
      if (check !== "unknown_device") return check === "proven";
      if (!(await epochKeyOpens(key, q, sample))) return false;
    }
    return false;
  }

  private reject(q: string, shareId: string) {
    this.rejected.add(shareId);
    this.deps.onLog?.("share_rejected", q);
  }

  dispose(): void {
    this.disposed = true;
    for (const t of this.timers.values()) (this.deps.clearTimer ?? clearTimeout)(t as ReturnType<typeof setTimeout>);
    this.timers.clear();
  }
}
