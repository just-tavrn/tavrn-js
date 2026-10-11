// SPDX-License-Identifier: MPL-2.0
// Ghost leaf cleanup (ENCRYPTION.md §4.7): which leaves a device may remove, the election of the first device,
// single flight per conversation and the backoff after epoch conflicts. The session manager is a fake here; the
// commits themselves are covered by mls.test.ts.
import { describe, expect, it, vi } from "vitest";
import { TavrnApiError } from "@tavrn/sdk";
import { CLEANUP_WAIT_MS, LeafCleaner, electedFirst, labelGhosts, type CleanerDeps } from "../src/cleanup";
import { MlsError, type GhostViolation } from "../src/mls";

const Q = "t.local/01J9ZK3G5M8Q2W4E6R8T0Y2V00";
const me = "alice@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2VA2";
const myOld = "alice@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
const bob = "bob@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2VB1";
const bobGone = "bob@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2VB0";
const carol = "carol@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2VC1";
const early = "dave@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2V01";

/** A fake manager whose roster loses the leaves `removeLeaves` removes. */
function fake(roster: string[], ghosts: Record<string, GhostViolation["reason"]>, opts: { refuse?: boolean; conflicts?: number } = {}) {
  let conflicts = opts.conflicts ?? 0;
  const state = { roster: [...roster] };
  const mls = {
    identity: me,
    address: "alice@t.local",
    roster: vi.fn(() => [...state.roster]),
    ghostCheck: vi.fn(async (_q: string, members: Iterable<string>) => {
      const allowed = new Set(members);
      return state.roster
        .filter((i) => ghosts[i] || !allowed.has(i.split("/")[0]!))
        .map((identity) => ({ identity, reason: ghosts[identity] ?? ("not_member" as const) }));
    }),
    removeLeaves: vi.fn(async (_q: string, ids: string[]) => {
      if (conflicts > 0) {
        conflicts--;
        throw new MlsError("conflict");
      }
      if (opts.refuse) return false;
      state.roster = state.roster.filter((i) => !ids.includes(i));
      return true;
    }),
  };
  const sleeps: number[] = [];
  const deps: CleanerDeps = { mls: mls as unknown as CleanerDeps["mls"], sleep: async (ms) => void sleeps.push(ms) };
  return { mls, state, sleeps, cleaner: new LeafCleaner(deps) };
}

const members = ["alice@t.local", "bob@t.local", "carol@t.local", "dave@t.local"];

describe("electedFirst", () => {
  it("picks the lowest device id among online eligible devices", () => {
    expect(electedFirst(me, [me, bob, carol])).toBe(true);
    expect(electedFirst(me, [me, early])).toBe(false);
    // The lower device is offline: this one goes first.
    expect(electedFirst(me, [me, early], [me, bob])).toBe(true);
    // This device always counts, even when the online list does not name it.
    expect(electedFirst(me, [early], [])).toBe(true);
  });
});

describe("LeafCleaner", () => {
  it("removes the own user's ghost leaves right away (own-user rule)", async () => {
    const { cleaner, mls, state, sleeps } = fake([me, myOld, bob], { [myOld]: "unattested" });
    const r = await cleaner.clean({ q: Q, members, mayManage: false });
    expect(r.outcome).toBe("removed");
    expect(r.removed).toEqual([myOld]);
    expect(mls.removeLeaves).toHaveBeenCalledWith(Q, [myOld]);
    expect(state.roster).toEqual([me, bob]);
    expect(r.ghosts).toEqual([]);
    expect(sleeps).toEqual([]);
  });

  it("lets any member remove deleted devices but leaves departed users to managers", async () => {
    const { cleaner, mls } = fake([me, bob, bobGone, carol], { [bobGone]: "unattested" });
    const r = await cleaner.clean({ q: Q, members: ["alice@t.local", "bob@t.local"], mayManage: false });
    expect(mls.removeLeaves).toHaveBeenCalledWith(Q, [bobGone]);
    expect(r.ghosts.map((g) => g.identity)).toEqual([carol]);

    const managed = fake([me, carol], {});
    const m = await managed.cleaner.clean({ q: Q, members: ["alice@t.local"], mayManage: true });
    expect(m.removed).toEqual([carol]);
    const plain = fake([me, carol], {});
    const p = await plain.cleaner.clean({ q: Q, members: ["alice@t.local"], mayManage: false });
    expect(p.outcome).toBe("not_allowed");
    expect(plain.mls.removeLeaves).not.toHaveBeenCalled();
  });

  it("waits when a lower device id may do it and skips the removal once the leaf is gone", async () => {
    const { cleaner, mls, state, sleeps } = fake([early, me, bobGone], { [bobGone]: "unattested" });
    mls.ghostCheck.mockImplementationOnce(async () => [{ identity: bobGone, reason: "unattested" }]);
    // While this device waits, the elected one removes the leaf.
    const pending = cleaner.clean({ q: Q, members, mayManage: false });
    state.roster = [early, me];
    const r = await pending;
    expect(sleeps).toEqual([CLEANUP_WAIT_MS]);
    expect(mls.removeLeaves).not.toHaveBeenCalled();
    expect(r.outcome).toBe("clean");
  });

  it("takes over after the wait when the leaf is still there", async () => {
    const { cleaner, mls, sleeps } = fake([early, me, bobGone], { [bobGone]: "unattested" });
    const r = await cleaner.clean({ q: Q, members, mayManage: false });
    expect(sleeps).toEqual([CLEANUP_WAIT_MS]);
    expect(mls.removeLeaves).toHaveBeenCalledWith(Q, [bobGone]);
    expect(r.outcome).toBe("removed");
  });

  it("runs once per conversation at a time", async () => {
    const { cleaner, mls } = fake([me, myOld], { [myOld]: "unattested" });
    const [a, b] = await Promise.all([cleaner.clean({ q: Q, members, mayManage: false }), cleaner.clean({ q: Q, members, mayManage: false })]);
    expect(a).toBe(b);
    expect(mls.removeLeaves).toHaveBeenCalledTimes(1);
  });

  it("backs off after epoch conflicts and gives up after three attempts", async () => {
    const ok = fake([me, myOld], { [myOld]: "unattested" }, { conflicts: 2 });
    const r = await ok.cleaner.clean({ q: Q, members, mayManage: false });
    expect(r.outcome).toBe("removed");
    expect(ok.mls.removeLeaves).toHaveBeenCalledTimes(3);
    expect(ok.sleeps).toEqual([500, 1500]);

    const stuck = fake([me, myOld], { [myOld]: "unattested" }, { conflicts: 9 });
    expect((await stuck.cleaner.clean({ q: Q, members, mayManage: false })).outcome).toBe("failed");
    expect(stuck.mls.removeLeaves).toHaveBeenCalledTimes(3);

    const apiConflict = fake([me, myOld], { [myOld]: "unattested" });
    apiConflict.mls.removeLeaves.mockRejectedValueOnce(new TavrnApiError({ type: "about:blank", title: "", status: 409, detail: "", code: "mls.epoch_conflict" }));
    expect((await apiConflict.cleaner.clean({ q: Q, members, mayManage: false })).outcome).toBe("removed");
  });

  it("does not try again after the node refused", async () => {
    const { cleaner, mls } = fake([me, bobGone], { [bobGone]: "unattested" }, { refuse: true });
    expect((await cleaner.clean({ q: Q, members, mayManage: false })).outcome).toBe("not_allowed");
    expect((await cleaner.clean({ q: Q, members, mayManage: false })).outcome).toBe("not_allowed");
    expect(mls.removeLeaves).toHaveBeenCalledTimes(1);
  });

  it("judges only attestation without a member list", async () => {
    const { cleaner, mls } = fake([me, carol, bobGone], { [bobGone]: "unattested" });
    const r = await cleaner.clean({ q: Q, members: null, mayManage: true });
    expect(mls.removeLeaves).toHaveBeenCalledWith(Q, [bobGone]);
    expect(r.ghosts).toEqual([]);
  });
});

describe("re-attesting own deleted devices before their leaves go", () => {
  it("attests the leaf key as retired first and keeps the leaf when that fails", async () => {
    const key = new Uint8Array(32).fill(7);
    const f = fake([me, myOld], { [myOld]: "unattested" });
    const retired = new Map<string, unknown>();
    Object.assign(f.mls, {
      rosterEntries: () => f.state.roster.map((identity) => ({ identity, key })),
      retiredDevice: (_a: string, d: string) => retired.get(d),
      verifiedDevices: async () => new Map(),
      knownOwnDevice: async () => true,
    });
    const calls: string[] = [];
    let online = false;
    const cleaner = new LeafCleaner({
      mls: f.mls as unknown as CleanerDeps["mls"],
      sleep: async () => undefined,
      reattest: async (deviceId, k) => {
        calls.push(deviceId);
        expect(k).toBe(key);
        if (!online) return false;
        retired.set(deviceId, { key: k, deletedAt: 0 });
        return true;
      },
    });
    expect((await cleaner.clean({ q: Q, members, mayManage: false })).outcome).toBe("deferred");
    expect(f.mls.removeLeaves).not.toHaveBeenCalled();
    online = true;
    const r = await cleaner.clean({ q: Q, members, mayManage: false });
    expect(r.outcome).toBe("removed");
    expect(calls).toEqual(["01J9ZK3G5M8Q2W4E6R8T0Y2VA1", "01J9ZK3G5M8Q2W4E6R8T0Y2VA1"]);
    // Already retired: no second attestation.
    const g = fake([me, myOld], { [myOld]: "unattested" });
    const again = vi.fn(async () => true);
    Object.assign(g.mls, { rosterEntries: () => [{ identity: myOld, key }], retiredDevice: () => ({ key, deletedAt: 0 }), verifiedDevices: async () => new Map() });
    await new LeafCleaner({ mls: g.mls as unknown as CleanerDeps["mls"], reattest: again }).clean({ q: Q, members, mayManage: false });
    expect(again).not.toHaveBeenCalled();
    expect(g.mls.removeLeaves).toHaveBeenCalled();
  });

  it("never signs a leaf key the account's own-devices record does not know: the leaf goes without", async () => {
    const key = new Uint8Array(32).fill(9);
    const f = fake([me, myOld], { [myOld]: "unattested" });
    const known = vi.fn(async () => false);
    Object.assign(f.mls, { rosterEntries: () => f.state.roster.map((identity) => ({ identity, key })), retiredDevice: () => undefined, verifiedDevices: async () => new Map(), knownOwnDevice: known });
    const reattest = vi.fn(async () => true);
    const r = await new LeafCleaner({ mls: f.mls as unknown as CleanerDeps["mls"], reattest, sleep: async () => undefined }).clean({ q: Q, members, mayManage: false });
    expect(known).toHaveBeenCalledWith("01J9ZK3G5M8Q2W4E6R8T0Y2VA1", key);
    expect(reattest).not.toHaveBeenCalled();
    expect(r.outcome).toBe("removed");
    // Without the record (an older manager) nothing is signed either.
    const g = fake([me, myOld], { [myOld]: "unattested" });
    Object.assign(g.mls, { rosterEntries: () => g.state.roster.map((identity) => ({ identity, key })), retiredDevice: () => undefined, verifiedDevices: async () => new Map() });
    const again = vi.fn(async () => true);
    await new LeafCleaner({ mls: g.mls as unknown as CleanerDeps["mls"], reattest: again, sleep: async () => undefined }).clean({ q: Q, members, mayManage: false });
    expect(again).not.toHaveBeenCalled();
    expect(g.mls.removeLeaves).toHaveBeenCalled();
  });
});

describe("labelGhosts", () => {
  it("labels unattested leaves of deleted devices as removed", () => {
    const ghosts: GhostViolation[] = [
      { identity: myOld, reason: "unattested" },
      { identity: bob, reason: "unattested" },
      { identity: carol, reason: "not_member" },
    ];
    expect(labelGhosts(ghosts, [{ identity: myOld, reason: "deleted" }, { identity: carol, reason: "deleted" }]).map((g) => g.reason)).toEqual(["removed", "unattested", "not_member"]);
    expect(labelGhosts(ghosts, null)).toBe(ghosts);
  });
});
