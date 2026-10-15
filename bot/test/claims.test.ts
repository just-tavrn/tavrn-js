// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { ClaimGuard, type ClaimTarget } from "../src/claims";

const Q = "h.test/01J9ZK3G5M8Q2W4E6R8T0Y2C01";
const OWN = "bot@h.test/BOTDEVICE";

/**
 * A DM whose member alice has device A in the group and device B attested without KeyPackages: every claim returns
 * (and burns) a KeyPackage of A and none for B, so B stays missing.
 */
function dm() {
  const roster = new Set([OWN, "alice@h.test/A"]);
  const devices = new Map<string, Map<string, Uint8Array>>([["alice@h.test", new Map([["A", new Uint8Array(1)], ["B", new Uint8Array(1)]])]]);
  const claims: string[][] = [];
  let addOnClaim: string | null = null;
  const mls: ClaimTarget = {
    roster: () => [...roster],
    verifiedDevices: async (address) => devices.get(address) ?? null,
    addMissingDevices: async (_q, members) => {
      claims.push([...members]);
      if (addOnClaim) roster.add(addOnClaim);
      return [];
    },
  };
  return { mls, roster, devices, claims, kpOf: (identity: string) => (addOnClaim = identity) };
}

describe("KeyPackage claim guard", () => {
  it("claims once for a device without KeyPackages, then backs off with a doubling wait", async () => {
    let now = 0;
    const guard = new ClaimGuard({ now: () => now });
    const { mls, claims } = dm();
    for (let i = 0; i < 5; i++) await guard.addMissing(mls, Q, ["alice@h.test", "bot@h.test"], OWN);
    expect(claims).toEqual([["alice@h.test"]]);
    now += 61_000;
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    expect(claims).toHaveLength(2);
    // The wait doubled: one minute later is too early, two minutes are enough.
    now += 61_000;
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    expect(claims).toHaveLength(2);
    now += 60_000;
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    expect(claims).toHaveLength(3);
  });

  it("claims at once when the user's devices changed or a new device appears", async () => {
    let now = 0;
    const guard = new ClaimGuard({ now: () => now });
    const { mls, claims, devices } = dm();
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    expect(claims).toHaveLength(1);
    devices.get("alice@h.test")!.set("C", new Uint8Array(1));
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    expect(claims).toHaveLength(2);
    guard.forget("alice@h.test");
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    expect(claims).toHaveLength(3);
  });

  it("does not wait for a device that the claim added, and never claims when nothing is missing", async () => {
    const guard = new ClaimGuard({ now: () => 0 });
    const { mls, claims, kpOf, devices } = dm();
    kpOf("alice@h.test/B");
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    expect(claims).toHaveLength(1);
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    expect(claims).toHaveLength(1);
    expect(guard.due("alice@h.test/B")).toBe(true);
    devices.delete("alice@h.test");
    await guard.addMissing(mls, Q, ["alice@h.test"], OWN);
    expect(claims).toHaveLength(1);
  });
});
