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
 * without it the history that device wrote could no longer be verified once the leaf is gone.
 *
 * To avoid a storm of competing commits, the lowest online device id among the devices that may do the removal
 * tries first; every other device waits {@link CLEANUP_WAIT_MS} and tries only if the leaf is still there. One
 * cleanup runs per conversation at a time; an epoch conflict is retried after the missing commits (at most 3).
 */
import { TavrnApiError } from "@tavrn/sdk";
import { MlsError, splitIdentity, type GhostViolation, type MlsManager } from "./mls";

/** Delay of the devices that were not elected to go first. */
export const CLEANUP_WAIT_MS = 10_000;
/** Attempts per leaf and session (a node that refuses keeps refusing). */
export const CLEANUP_MAX_TRIES = 3;

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
  /** The conversation's effective "no bots" flag: bot leaves are ghosts (§4.6) and go like departed members. */
  noBots?: boolean;
}

export type CleanupOutcome = "clean" | "removed" | "deferred" | "not_allowed" | "failed";

export interface CleanupResult {
  outcome: CleanupOutcome;
  /** Leaves this device removed. */
  removed: string[];
  /** Ghost violations left afterwards, labelled with `removed` where the node reports a deleted device. */
  ghosts: GhostViolation[];
}

export interface CleanerDeps {
  mls: Pick<MlsManager, "ghostCheck" | "removeLeaves" | "roster" | "identity" | "address"> &
    Partial<Pick<MlsManager, "rosterEntries" | "retiredDevice" | "verifiedDevices">>;
  /**
   * Attests an own deleted device again as retired (`POST /users/me/devices/retired`) from its leaf key; true when
   * the node has it now (or refused it for good), false to keep the leaf for a later try (e.g. offline).
   */
  reattest?(deviceId: string, key: Uint8Array): Promise<boolean>;
  sleep?(ms: number): Promise<void>;
  waitMs?: number;
  /** Waits before the retries after an epoch conflict (default 500 ms, 1.5 s, 3 s). */
  backoffMs?: number[];
}

type Why = "own" | "device" | "membership";

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
 * online (this device always counts as online).
 */
export function electedFirst(self: string, eligible: Iterable<string>, online?: Iterable<string> | null): boolean {
  const on = online ? new Set(online) : null;
  const candidates = [...new Set([...eligible, self])].filter((i) => i === self || !on || on.has(i));
  candidates.sort((a, b) => (deviceIdOf(a) < deviceIdOf(b) ? -1 : deviceIdOf(a) > deviceIdOf(b) ? 1 : a < b ? -1 : 1));
  return candidates[0] === self;
}

function isConflict(e: unknown): boolean {
  return (e instanceof MlsError && e.code === "conflict") || (e instanceof TavrnApiError && e.code === "mls.epoch_conflict");
}

export class LeafCleaner {
  /** Own leaves without a retired attestation: re-attested first; leaves whose re-attestation failed stay. */
  private async keepHistory(q: string, ids: string[]): Promise<string[]> {
    const { mls, reattest } = this.deps;
    const own = ids.filter((i) => splitIdentity(i).address === mls.address);
    if (!reattest || !own.length || !mls.rosterEntries || !mls.retiredDevice || !mls.verifiedDevices) return ids;
    await mls.verifiedDevices(mls.address, true).catch(() => null);
    const keys = new Map(mls.rosterEntries(q).map((e) => [e.identity, e.key]));
    const keep = new Set<string>();
    for (const id of own) {
      const { deviceId } = splitIdentity(id);
      const key = keys.get(id);
      if (!key || mls.retiredDevice(mls.address, deviceId)) continue;
      const ok = await reattest(deviceId, key).catch(() => false);
      if (!ok) keep.add(id);
    }
    return ids.filter((i) => !keep.has(i));
  }

  private readonly running = new Map<string, Promise<CleanupResult>>();
  private readonly tries = new Map<string, number>();

  constructor(private readonly deps: CleanerDeps) {}

  private sleep(ms: number): Promise<void> {
    return this.deps.sleep ? this.deps.sleep(ms) : new Promise((r) => setTimeout(r, ms));
  }

  /** Cleans the conversation's group; concurrent calls for one conversation share the run. */
  clean(req: CleanupRequest): Promise<CleanupResult> {
    const running = this.running.get(req.q);
    if (running) return running;
    const p = this.run(req).finally(() => this.running.delete(req.q));
    this.running.set(req.q, p);
    return p;
  }

  /** The ghosts this device may remove, by rule. */
  private async targets(req: CleanupRequest): Promise<{ ghosts: GhostViolation[]; targets: Map<string, Why> }> {
    const { mls } = this.deps;
    const roster = mls.roster(req.q);
    // Without a member list every leaf's user counts as a member: only attestation is judged.
    const members = req.members ?? roster.map((i) => splitIdentity(i).address);
    const ghosts = await mls.ghostCheck(req.q, members, { fresh: true, noBots: req.noBots });
    const targets = new Map<string, Why>();
    for (const g of ghosts) {
      if (g.reason === "duplicate" || g.identity === mls.identity) continue;
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

    // Election among the valid leaves that may commit these removals.
    const ghostIds = new Set(ghosts.map((g) => g.identity));
    const valid = mls.roster(req.q).filter((i) => !ghostIds.has(i));
    const anyMember = [...targets.values()].some((w) => w !== "own");
    const eligible = anyMember ? valid : valid.filter((i) => splitIdentity(i).address === mls.address);
    if (!electedFirst(mls.identity, eligible, req.online)) {
      await this.sleep(this.deps.waitMs ?? CLEANUP_WAIT_MS);
      ({ ghosts, targets } = await this.targets(req));
      if (targets.size === 0) return result(ghosts.length ? "deferred" : "clean");
    }

    const ids = await this.keepHistory(req.q, [...targets.keys()]);
    if (ids.length === 0) return result("deferred");
    for (const id of ids) this.tries.set(`${req.q}|${id}`, (this.tries.get(`${req.q}|${id}`) ?? 0) + 1);
    const backoff = this.deps.backoffMs ?? [500, 1500, 3000];
    for (let attempt = 0; ; attempt++) {
      try {
        const ok = await mls.removeLeaves(req.q, ids);
        if (!ok) {
          // The node refused (403 mls.forbidden) or the leaves are already gone.
          const after = await this.targets(req);
          ghosts = after.ghosts;
          if (after.targets.size === 0 && !ids.some((i) => mls.roster(req.q).includes(i))) return result("clean");
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
