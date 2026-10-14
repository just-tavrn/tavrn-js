// SPDX-License-Identifier: MPL-2.0
/**
 * Removal of ghost leaves (ENCRYPTION.md §4.7): leaves of deleted or unattested devices and of users who are no
 * longer members. A client only commits removals the node allows (§4.5 rule 4) and that it verified itself
 * (§4.6 ghost check):
 *
 * - any device of the same user removes that user's other ghost leaves (own-user rule);
 * - any member removes leaves whose device is deleted or not attested;
 * - leaves of users who are no longer members only by those who may manage the conversation; bot leaves in a
 *   conversation whose "no bots" flag is set count as such (the bot is not entitled there, APPLICATIONS.md §3.5).
 *
 * Before an own leaf goes, its device is attested again as retired when the node has no retired attestation for it
 * (devices deleted before nodes kept them, ENCRYPTION.md §5.2): the leaf's signature key is the device key, and
 * without it the history that device wrote could no longer be verified once the leaf is gone. Only a key the account
 * attested itself is signed again (its own-devices record, `MlsManager.knownOwnDevice`): a leaf the node planted under
 * the user's address goes without one, and the messages of a device the record does not know stay unverifiable.
 *
 * Leaves are removed by identity and signature key, so a leaf that names a genuine device with another key goes
 * while the genuine leaf stays.
 *
 * To avoid a storm of competing commits, the lowest online device id among the devices that may do the removal
 * tries first; every other device waits {@link CLEANUP_WAIT_MS} and tries only if the leaf is still there. One
 * cleanup runs per conversation at a time; an epoch conflict is retried after the missing commits (at most 3).
 *
 * The election counts only the valid leaves (no ghosts) of devices that may commit every removal of the run, by the
 * rules above: own ghost leaves only devices of the same user; departed members only devices of users who may manage
 * the conversation (`managers`, when the caller knows them); deleted or unattested devices any member. Of those, only
 * the devices known to be online count when the caller knows it: `online` (device identities, e.g. the voice
 * participants) and `onlineUsers` (user addresses, e.g. the presence list; every device of a user who is not in it is
 * offline). This device always counts. Without the lists every candidate counts, as before: a device that is offline
 * or not allowed would otherwise hold every other device back for the whole wait.
 *
 * A message waiting for the removal (the ghost check refuses to encrypt while a departed member's leaf is in the
 * group) cannot wait for the election: an `urgent` request skips the wait and cuts the wait of a running cleanup short.
 * A second commit of the same removal costs nothing but an epoch conflict, after which the leaf is gone.
 *
 * A voice join cannot wait either, but nothing waits for the removal there (the current epoch works for the fresh
 * voice key, ENCRYPTION.md §5a): a `noWait` request joins a running cleanup and cuts its wait short (as `urgent`), runs
 * at once when this device is elected, and otherwise returns `postponed` without committing anything; the caller runs
 * the cleanup again without `noWait` later (in the background, after connecting), where it waits for the election.
 */
import { TavrnApiError } from "@tavrn/sdk";
import { MlsError, splitIdentity, type GhostViolation, type MlsManager } from "./mls";

/** Delay of the devices that were not elected to go first. */
export const CLEANUP_WAIT_MS = 10_000;
/** Attempts per leaf and session (a node that refuses keeps refusing). */
export const CLEANUP_MAX_TRIES = 3;
/**
 * A cleanup looks every member's devices up again (`ghostCheck` `fresh`) unless the last fresh check of the
 * conversation found no ghost in the same roster (identities and signature keys) less than this ago and the node
 * lists no pending removal of a leaf in it. Device deletions reach clients as `devices.changed` (the key cache forgets
 * the user) and as pending removals, so an unchanged roster needs no new lookups; a voice join then costs no key
 * round trips. The epoch is not part of the key: every voice join's self update moves it without changing a leaf's
 * identity or signature key.
 */
export const FRESH_REUSE_MS = 10 * 60_000;

/** A pending removal as the hosting node lists it. */
export interface PendingRemovalLike {
  identity: string;
  reason: string;
}

export interface CleanupRequest {
  /** Qualified conversation id. */
  q: string;
  /** Addresses entitled to the conversation; null when unknown (membership is then not judged). */
  members: string[] | null;
  /** The user may remove leaves of users who are no longer members (DMs: every member; channels: moderators). */
  mayManage: boolean;
  /** Pending removals of the hosting node (labels deleted devices as `removed`). */
  pending?: PendingRemovalLike[] | null;
  /** Device identities known to be online (voice participants); null = unknown. */
  online?: Iterable<string> | null;
  /** Addresses of users known to be online (presence); devices of other users are offline. null = unknown. */
  onlineUsers?: Iterable<string> | null;
  /**
   * Addresses of the users who may remove leaves of departed members (DMs: every member, channels: moderators); only
   * their devices are elected for such removals. null = unknown (every member counts).
   */
  managers?: Iterable<string> | null;
  /** The conversation's effective "no bots" flag: bot leaves are ghosts (§4.6) and go like departed members. */
  noBots?: boolean;
  /**
   * Content is waiting for the removal: no election wait, and a running cleanup of the conversation that is waiting
   * for the elected device stops waiting.
   */
  urgent?: boolean;
  /**
   * The caller cannot wait for the election and nothing waits for the removal (a voice join): a running cleanup of the
   * conversation stops waiting and is shared (as with `urgent`); otherwise a device that is not elected gets
   * `postponed` at once and commits nothing (run the cleanup again without `noWait` later).
   */
  noWait?: boolean;
}

/** `postponed`: a `noWait` request of a device that was not elected; nothing was committed. */
export type CleanupOutcome = "clean" | "removed" | "deferred" | "not_allowed" | "failed" | "postponed";

export interface CleanupResult {
  outcome: CleanupOutcome;
  /** Leaves this device removed. */
  removed: string[];
  /** Ghost violations left afterwards, labelled with `removed` where the node reports a deleted device. */
  ghosts: GhostViolation[];
}

export interface CleanerDeps {
  mls: Pick<MlsManager, "ghostCheck" | "removeLeaves" | "roster" | "identity" | "address"> &
    Partial<Pick<MlsManager, "rosterEntries" | "retiredDevice" | "verifiedDevices" | "knownOwnDevice">>;
  /**
   * Attests an own deleted device again as retired (`POST /users/me/devices/retired`) from its leaf key; true when
   * the node has it now (or refused it for good), false to keep the leaf for a later try (e.g. offline). Called only
   * for keys `mls.knownOwnDevice` vouches for.
   */
  reattest?(deviceId: string, key: Uint8Array): Promise<boolean>;
  sleep?(ms: number): Promise<void>;
  /** Clock of {@link FRESH_REUSE_MS} (default `Date.now`). */
  now?(): number;
  waitMs?: number;
  /** Waits before the retries after an epoch conflict (default 500 ms, 1.5 s, 3 s). */
  backoffMs?: number[];
}

type Why = "own" | "device" | "membership";

/** A leaf to remove: its identity and signature key (null: every leaf of the identity). */
interface Leaf {
  identity: string;
  key: Uint8Array | null;
}

function sameKey(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function deviceIdOf(identity: string): string {
  return splitIdentity(identity).deviceId;
}

/** Labels unattested leaves whose device the node reports as deleted (`removed`: cleanup pending). */
export function labelGhosts(ghosts: GhostViolation[], pending: PendingRemovalLike[] | null | undefined): GhostViolation[] {
  if (!pending?.length) return ghosts;
  const deleted = new Set(pending.filter((p) => p.reason === "deleted").map((p) => p.identity));
  return ghosts.map((g) => (g.reason === "unattested" && deleted.has(g.identity) ? { ...g, reason: "removed" } : g));
}

/**
 * Whether this device goes first: the lowest device id among the devices that may commit the removal and are
 * online (this device always counts as online). `online` names devices, `onlineUsers` users (all their devices);
 * a list that is not given does not filter.
 */
export function electedFirst(self: string, eligible: Iterable<string>, online?: Iterable<string> | null, onlineUsers?: Iterable<string> | null): boolean {
  const on = online ? new Set(online) : null;
  const users = onlineUsers ? new Set(onlineUsers) : null;
  const candidates = [...new Set([...eligible, self])].filter((i) => i === self || ((!on || on.has(i)) && (!users || users.has(splitIdentity(i).address))));
  candidates.sort((a, b) => (deviceIdOf(a) < deviceIdOf(b) ? -1 : deviceIdOf(a) > deviceIdOf(b) ? 1 : a < b ? -1 : 1));
  return candidates[0] === self;
}

function isConflict(e: unknown): boolean {
  return (e instanceof MlsError && e.code === "conflict") || (e instanceof TavrnApiError && e.code === "mls.epoch_conflict");
}

export class LeafCleaner {
  /**
   * Own leaves without a retired attestation whose key the account attested itself: re-attested first; leaves whose
   * re-attestation failed stay. Any other own leaf goes without one.
   */
  private async keepHistory(leaves: Leaf[]): Promise<Leaf[]> {
    const { mls, reattest } = this.deps;
    const own = leaves.filter((l) => splitIdentity(l.identity).address === mls.address);
    if (!reattest || !own.length || !mls.retiredDevice || !mls.verifiedDevices || !mls.knownOwnDevice) return leaves;
    await mls.verifiedDevices(mls.address, true).catch(() => null);
    const keep = new Set<Leaf>();
    for (const leaf of own) {
      const { deviceId } = splitIdentity(leaf.identity);
      if (!leaf.key || mls.retiredDevice(mls.address, deviceId)) continue;
      if (!(await mls.knownOwnDevice(deviceId, leaf.key).catch(() => false))) continue;
      const ok = await reattest(deviceId, leaf.key).catch(() => false);
      if (!ok) keep.add(leaf);
    }
    return leaves.filter((l) => !keep.has(l));
  }

  /**
   * The leaves behind the target identities: with keys known (`rosterEntries`), every leaf of the identity except one
   * carrying the device's attested key (that one is genuine); otherwise the identity alone (all its leaves).
   */
  private async leavesOf(q: string, targets: Map<string, Why>): Promise<Leaf[]> {
    const { mls } = this.deps;
    if (!mls.rosterEntries) return [...targets.keys()].map((identity) => ({ identity, key: null }));
    const entries = mls.rosterEntries(q);
    const out: Leaf[] = [];
    for (const [identity, why] of targets) {
      const { address, deviceId } = splitIdentity(identity);
      const attested = mls.verifiedDevices ? (await mls.verifiedDevices(address).catch(() => null))?.get(deviceId) : undefined;
      for (const e of entries) {
        if (e.identity !== identity) continue;
        // Departed members go with every leaf; otherwise the leaf with the attested key is the genuine one.
        if (why !== "membership" && attested && sameKey(attested, e.key)) continue;
        out.push({ identity, key: e.key });
      }
    }
    return out;
  }

  private readonly running = new Map<string, Promise<CleanupResult>>();
  /** Ends the election wait of a running cleanup, per conversation. */
  private readonly waiting = new Map<string, () => void>();
  private readonly tries = new Map<string, number>();
  /** The roster of the last fresh ghost check that found nothing, per conversation, and when. */
  private readonly checked = new Map<string, { roster: string; at: number }>();

  constructor(private readonly deps: CleanerDeps) {}

  private sleep(ms: number): Promise<void> {
    return this.deps.sleep ? this.deps.sleep(ms) : new Promise((r) => setTimeout(r, ms));
  }

  /** The election wait of a cleanup; an urgent request for the same conversation ends it early. */
  private electionWait(q: string): Promise<void> {
    return new Promise((resolve) => {
      const done = () => {
        if (this.waiting.get(q) === done) this.waiting.delete(q);
        resolve();
      };
      this.waiting.set(q, done);
      void this.sleep(this.deps.waitMs ?? CLEANUP_WAIT_MS).then(done, done);
    });
  }

  /** Whether a cleanup of the conversation is running (possibly in its election wait). */
  isRunning(q: string): boolean {
    return this.running.has(q);
  }

  /** Cleans the conversation's group; concurrent calls for one conversation share the run. */
  clean(req: CleanupRequest): Promise<CleanupResult> {
    const running = this.running.get(req.q);
    if (running) {
      if (req.urgent || req.noWait) this.waiting.get(req.q)?.();
      return running;
    }
    const p = this.run(req).finally(() => this.running.delete(req.q));
    this.running.set(req.q, p);
    return p;
  }

  /** The roster's identities and signature keys (identities alone without `rosterEntries`). */
  private fingerprint(q: string): string {
    const { mls } = this.deps;
    const entries = mls.rosterEntries ? mls.rosterEntries(q).map((e) => `${e.identity}#${e.key.join(".")}`) : mls.roster(q);
    return entries.sort().join("|");
  }

  /** The ghosts this device may remove, by rule. */
  private async targets(req: CleanupRequest): Promise<{ ghosts: GhostViolation[]; targets: Map<string, Why> }> {
    const { mls } = this.deps;
    const roster = mls.roster(req.q);
    // Without a member list every leaf's user counts as a member: only attestation is judged.
    const members = req.members ?? roster.map((i) => splitIdentity(i).address);
    const fingerprint = this.fingerprint(req.q);
    const now = this.deps.now?.() ?? Date.now();
    const last = this.checked.get(req.q);
    const pendingHere = !!req.pending?.some((p) => roster.includes(p.identity));
    const fresh = !last || last.roster !== fingerprint || now - last.at >= FRESH_REUSE_MS || pendingHere;
    const ghosts = await mls.ghostCheck(req.q, members, { fresh, noBots: req.noBots });
    if (ghosts.length) this.checked.delete(req.q);
    else if (fresh) this.checked.set(req.q, { roster: fingerprint, at: now });
    const targets = new Map<string, Why>();
    for (const g of ghosts) {
      // Duplicates carry the attested key (removing one would hit the genuine leaf); this device's own leaf is never
      // reported, a leaf under its name with another key is.
      if (g.reason === "duplicate") continue;
      if ((this.tries.get(`${req.q}|${g.identity}`) ?? 0) >= CLEANUP_MAX_TRIES) continue;
      if (splitIdentity(g.identity).address === mls.address) targets.set(g.identity, "own");
      else if (g.reason === "unattested") targets.set(g.identity, "device");
      else if ((g.reason === "not_member" || g.reason === "bot") && req.mayManage) targets.set(g.identity, "membership");
    }
    return { ghosts, targets };
  }

  private async run(req: CleanupRequest): Promise<CleanupResult> {
    const { mls } = this.deps;
    let { ghosts, targets } = await this.targets(req);
    const result = (outcome: CleanupOutcome, removed: string[] = []): CleanupResult => ({ outcome, removed, ghosts: labelGhosts(ghosts, req.pending) });
    if (targets.size === 0) return result(ghosts.length ? "not_allowed" : "clean");

    // Election among the valid leaves of devices that may commit every one of these removals.
    const ghostIds = new Set(ghosts.map((g) => g.identity));
    const kinds = new Set(targets.values());
    const managers = req.managers ? new Set(req.managers) : null;
    const eligible = mls.roster(req.q).filter((i) => {
      if (ghostIds.has(i)) return false;
      const { address } = splitIdentity(i);
      if (address === mls.address) return true;
      if (kinds.has("own")) return false;
      return !kinds.has("membership") || !managers || managers.has(address);
    });
    if (!req.urgent && !electedFirst(mls.identity, eligible, req.online, req.onlineUsers)) {
      if (req.noWait) return result("postponed");
      await this.electionWait(req.q);
      ({ ghosts, targets } = await this.targets(req));
      if (targets.size === 0) return result(ghosts.length ? "deferred" : "clean");
    }

    const leaves = await this.keepHistory(await this.leavesOf(req.q, targets));
    if (leaves.length === 0) return result("deferred");
    const ids = [...new Set(leaves.map((l) => l.identity))];
    for (const id of ids) this.tries.set(`${req.q}|${id}`, (this.tries.get(`${req.q}|${id}`) ?? 0) + 1);
    const byKey = leaves.every((l) => l.key !== null);
    const backoff = this.deps.backoffMs ?? [500, 1500, 3000];
    for (let attempt = 0; ; attempt++) {
      try {
        const ok = byKey ? await mls.removeLeaves(req.q, leaves.map((l) => l.identity), leaves.map((l) => l.key!)) : await mls.removeLeaves(req.q, ids);
        if (!ok) {
          // The node refused (403 mls.forbidden) or the leaves are already gone.
          const after = await this.targets(req);
          ghosts = after.ghosts;
          const entries = byKey && mls.rosterEntries ? mls.rosterEntries(req.q) : null;
          const stillThere = entries ? leaves.some((l) => entries.some((e) => e.identity === l.identity && sameKey(e.key, l.key!))) : ids.some((i) => mls.roster(req.q).includes(i));
          if (after.targets.size === 0 && !stillThere) return result("clean");
          for (const id of ids) this.tries.set(`${req.q}|${id}`, CLEANUP_MAX_TRIES);
          return result("not_allowed");
        }
        ghosts = await mls.ghostCheck(req.q, req.members ?? mls.roster(req.q).map((i) => splitIdentity(i).address), { noBots: req.noBots });
        return result("removed", ids);
      } catch (e) {
        if (!isConflict(e) || attempt >= backoff.length - 1) return result("failed");
        await this.sleep(backoff[attempt] ?? 1000);
      }
    }
  }
}
