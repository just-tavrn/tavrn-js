// SPDX-License-Identifier: MPL-2.0
/**
 * History for new members of encrypted channels (ENCRYPTION.md §7b, design note 4.13 item 11).
 *
 * Members hand the content keys of past epochs to a member who joined later, as far as the channel's policy
 * allows. A share is never a chat message: it is the canonical JSON payload
 * `{type: "history_keys", v: 1, conversation, to, epochs: [[epoch, key], …]}` encrypted and signed like
 * message content (§5.2) under the conversation's **current** epoch, posted to `…/history-keys` of the node
 * hosting the conversation. The recipient verifies the signature against an attested device in the group,
 * checks every key against a stored message of its epoch, signed by its author's attested device (no poisoned keys) and keeps accepted keys only
 * in the key store (the MLS client state, which is also what the history backup carries).
 *
 * The pure parts (policy, windows, chunking, sharer election, payload codec, key check) are exported for
 * tests; {@link HistorySync} runs the flows of one device.
 */
import { b64urlDecode, b64urlEncode, jcs, type HistoryPendingList, type HistoryShareList, type CreateHistoryShareRequest, type Message } from "@tavrn/sdk";
import { splitIdentity, splitQualified, type MlsManager } from "./mls";

export const HISTORY_KEYS_TYPE = "history_keys";
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
 * the current epoch itself), limited to `fromEpoch` and later for a day window. `since_join` shares nothing.
 */
export function epochsToShare(p: HistoryPolicy, known: number[], current: number, fromEpoch: number | null): number[] {
  if (!grantsHistory(p)) return [];
  const lower = p.kind === "days" ? (fromEpoch ?? Number.POSITIVE_INFINITY) : 0;
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
  v: 1;
  /** Qualified conversation id. */
  conversation: string;
  /** Recipient address. */
  to: string;
  /** `[epoch, base64url content key]`, ascending. */
  epochs: [number, string][];
}

/** The canonical JSON of a share payload (the bytes the device signature covers). */
export function encodeHistoryPayload(conversation: string, to: string, keys: [number, Uint8Array][]): string {
  const payload: HistoryPayload = { type: HISTORY_KEYS_TYPE, v: 1, conversation, to, epochs: keys.map(([e, k]) => [e, b64urlEncode(k)]) };
  return jcs(payload);
}

/**
 * Checks a decrypted share payload against what the share claims: type and version, conversation, recipient,
 * every epoch an integer within `[epochFrom, epochTo]` at most once, every key 32 bytes. Returns the keys
 * (caller zeroes them) or null when anything is off (the whole share is rejected).
 */
export function parseHistoryPayload(
  content: Record<string, unknown>,
  expected: { conversation: string; to: string; epochFrom: number; epochTo: number },
): [number, Uint8Array][] | null {
  const keys = new Set(Object.keys(content));
  if (keys.size !== 5 || !["type", "v", "conversation", "to", "epochs"].every((k) => keys.has(k))) return null;
  if (content.type !== HISTORY_KEYS_TYPE || content.v !== 1) return null;
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
 * Picks the message that checks a key of `epoch`: an encrypted message of that epoch, preferably not written
 * by the sharer (a sharer could plant a message under a forged key and then "prove" that key with it).
 */
export function pickSample(messages: Pick<Message, "author" | "device_id" | "epoch" | "content" | "encrypted">[], epoch: number, sharer: string): KeySample | null {
  const usable = messages.filter((m) => m.encrypted && m.epoch === epoch && typeof m.content === "string" && !!m.device_id);
  const m = usable.find((x) => x.author !== sharer) ?? usable[0];
  return m ? { author: m.author, device_id: m.device_id!, epoch, content: m.content as string } : null;
}

// ---- Flows ---------------------------------------------------------------------------------------

/** The routes of the node hosting a conversation (bare conversation ids). */
export interface HistoryApi {
  share(conversationId: string, req: CreateHistoryShareRequest): Promise<unknown>;
  shares(conversationId: string): Promise<HistoryShareList>;
  ack(conversationId: string, shareId: string): Promise<unknown>;
  pending(conversationId: string): Promise<HistoryPendingList>;
  messages(conversationId: string, query: { limit?: number; after?: string; before?: string; epoch?: number }): Promise<Message[]>;
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
  /** Something went wrong with a share; never carries keys or payloads. */
  onLog?(event: "share_rejected" | "share_failed" | "keys_rejected", conversation: string): void;
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
  private readonly shared = new Set<string>();
  private readonly rejected = new Set<string>();
  private readonly timers = new Map<string, unknown>();
  private readonly preferred = new Map<string, Set<string>>();
  private readonly receiving = new Map<string, Promise<number>>();
  private disposed = false;

  constructor(private readonly deps: HistorySyncDeps) {}

  private api(q: string): { api: HistoryApi; id: string } {
    const { domain, id } = splitQualified(q);
    return { api: this.deps.api(domain), id };
  }

  /** This device committed the Add of these users (MlsEvent `added`): it shares at once when they are pending. */
  noteAdded(q: string, addresses: string[]): void {
    const set = this.preferred.get(q) ?? new Set<string>();
    for (const a of addresses) set.add(a);
    this.preferred.set(q, set);
  }

  /**
   * Members of `q` who wait for keys: share now when this device is elected, otherwise after the back-off
   * and only if they still wait.
   */
  async checkPending(q: string, policy: HistoryPolicy): Promise<void> {
    if (this.disposed || !grantsHistory(policy) || !this.deps.mls.hasGroup(q)) return;
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
          else await this.shareWith(q, entry.user, Date.parse(entry.since), policy);
        } catch {
          this.deps.onLog?.("share_failed", q);
        }
      };
      if (delay === 0) await go();
      else this.timers.set(key, (this.deps.setTimer ?? setTimeout)(() => void go(), delay));
    }
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
    const after = await api.messages(id, { after: ulidFloor(resetAtMs), limit: 20 });
    const since = after.filter((m) => m.encrypted && typeof m.epoch === "number").map((m) => m.epoch as number);
    let lower = minEpoch;
    if (lower === null) {
      const before = await api.messages(id, { before: ulidFloor(resetAtMs), limit: 1 });
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
      const page = await api.messages(id, { after: ulidFloor(channel.windowStart ?? 0), limit: 20 });
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

  /** Sends the keys of the policy's window to `to` (chunked); an empty share if there is nothing to send. */
  async shareWith(q: string, to: string, joinedAtMs: number, policy: HistoryPolicy): Promise<number> {
    const { api, id } = this.api(q);
    const mls = this.deps.mls;
    const current = mls.epoch(q);
    if (current === null) return 0;
    let fromEpoch: number | null = null;
    if (policy.kind === "days") {
      // The oldest epoch with a message in the window (ascending page after the window start).
      const start = historyWindowStart(policy, Number.isFinite(joinedAtMs) ? joinedAtMs : Date.now()) ?? 0;
      const page = await api.messages(id, { after: ulidFloor(start), limit: 20 });
      const epochs = page.filter((m) => m.encrypted && typeof m.epoch === "number").map((m) => m.epoch as number);
      fromEpoch = epochs.length ? Math.min(...epochs) : null;
    }
    const epochs = epochsToShare(policy, mls.knownEpochs(q), current, fromEpoch);
    return this.sendChunks(q, to, epochs);
  }

  /** Encrypts and posts `epochs` for `to` in chunks; one empty share when there are none (it clears a pending mark). */
  private async sendChunks(q: string, to: string, epochs: number[]): Promise<number> {
    const { api, id } = this.api(q);
    const mls = this.deps.mls;
    const chunks = epochs.length ? chunkEpochs(epochs) : [[]];
    let sent = 0;
    for (const chunk of chunks) {
      const keys = mls.exportEpochKeys(q, chunk);
      let json: string;
      try {
        json = encodeHistoryPayload(q, to, keys);
      } finally {
        for (const [, k] of keys) k.fill(0);
      }
      const { content, epoch } = await mls.encryptHistory(q, json);
      const from = chunk[0] ?? epoch;
      const last = chunk[chunk.length - 1] ?? epoch;
      await api.share(id, { to_user: to, epoch_from: from, epoch_to: last, ciphertext: content });
      sent += keys.length;
    }
    return sent;
  }

  /** Fetches, checks and stores the shares addressed to this user; returns the number of new keys. */
  receive(q: string): Promise<number> {
    const running = this.receiving.get(q);
    if (running) return running;
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
      const dec = await mls.decryptHistory(q, share.id, share.from_user, share.from_device, share.ciphertext);
      if (!dec.ok) {
        // A key that is still missing may arrive with the catch-up: try again later.
        if (dec.reason !== "missing_key") this.reject(q, share.id);
        continue;
      }
      const keys = parseHistoryPayload(dec.content, { conversation: q, to: this.deps.address, epochFrom: share.epoch_from, epochTo: share.epoch_to });
      if (!keys) {
        this.reject(q, share.id);
        continue;
      }
      const known = new Set(mls.knownEpochs(q));
      const accepted: [number, Uint8Array][] = [];
      let dropped = 0;
      try {
        for (const [epoch, key] of keys) {
          if (known.has(epoch)) continue;
          const sample = pickSample(await api.messages(id, { epoch, limit: 10 }).catch(() => []), epoch, share.from_user);
          if (sample && (await epochKeyOpens(key, q, sample)) && (await mls.sampleProvesKey(q, epoch, key, sample))) accepted.push([epoch, key]);
          else dropped++;
        }
        total += await mls.importHistoryKeys(q, accepted);
      } finally {
        for (const [, k] of keys) k.fill(0);
      }
      if (dropped) this.deps.onLog?.("keys_rejected", q);
      await api.ack(id, share.id).catch(() => undefined);
    }
    return total;
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
