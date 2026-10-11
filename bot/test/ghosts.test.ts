// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { MlsError, type GhostViolation } from "@tavrn/e2ee";
import { b64urlEncode } from "@tavrn/sdk";
import { BotError, sealUnderPolicy, silentLogger, type BotLogger } from "../src";

const Q = "t.local/01J9ZK3G5M8Q2W4E6R8T0Y2V00";
const retiredKey = new Uint8Array(32).fill(5);
const leaf = (identity: string, reason: GhostViolation["reason"], key = b64urlEncode(new Uint8Array(32).fill(1))): GhostViolation => ({ identity, reason, key });
const retired = leaf("alice@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2VA2", "unattested", b64urlEncode(retiredKey));
const neverAttested = leaf("bob@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2VB9", "unattested");
const changed = leaf("carol@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2VC1", "key_changed");

/** A session manager that refuses until every violation is acknowledged (by identity and key). */
function fakeMls(ghosts: GhostViolation[]) {
  const acked = new Set<string>();
  const open = () => ghosts.filter((g) => !acked.has(`${g.identity}|${g.key}`));
  const mls = {
    unacknowledgedGhosts: () => open(),
    acknowledgeGhosts: vi.fn(async (_q: string, refs: (string | { identity: string; key: string })[]) => {
      for (const r of refs) if (typeof r !== "string") acked.add(`${r.identity}|${r.key}`);
    }),
    retiredDevice: (address: string, deviceId: string) => (`${address}/${deviceId}` === retired.identity ? { key: retiredKey, deletedAt: 0 } : undefined),
  };
  const seal = vi.fn(async () => {
    if (open().length) throw new MlsError("ghost");
    return "sealed";
  });
  return { mls, seal };
}

describe("ghostPolicy: unknown devices for a bot (ENCRYPTION.md §4.6)", () => {
  it("strict accepts the leaf of a retired device awaiting cleanup and sends", async () => {
    const { mls, seal } = fakeMls([retired]);
    await expect(sealUnderPolicy(mls, Q, "strict", silentLogger, seal)).resolves.toBe("sealed");
    expect(mls.acknowledgeGhosts).toHaveBeenCalledWith(Q, [retired]);
  });

  it("strict refuses a key that was never attested and a changed identity key, naming the conversation and the leaves", async () => {
    for (const g of [neverAttested, changed]) {
      const { mls, seal } = fakeMls([retired, g]);
      const err = await sealUnderPolicy(mls, Q, "strict", silentLogger, seal).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(BotError);
      expect(err).toMatchObject({ code: "ghost" });
      expect((err as Error).message).toContain(Q);
      expect((err as Error).message).toContain(g.identity);
      expect(mls.acknowledgeGhosts).not.toHaveBeenCalled();
    }
  });

  it("accept sends anyway and logs every accepted leaf", async () => {
    const warn = vi.fn();
    const logger: BotLogger = { ...silentLogger, warn };
    const { mls, seal } = fakeMls([retired, neverAttested, changed]);
    await expect(sealUnderPolicy(mls, Q, "accept", logger, seal)).resolves.toBe("sealed");
    expect(warn).toHaveBeenCalledTimes(2);
    expect(warn.mock.calls.map((c) => (c[1] as { leaf: string }).leaf)).toEqual([neverAttested.identity, changed.identity]);
  });

  it("other errors pass through untouched", async () => {
    const { mls } = fakeMls([]);
    await expect(sealUnderPolicy(mls, Q, "strict", silentLogger, async () => Promise.reject(new MlsError("catch_up_failed")))).rejects.toMatchObject({ name: "MlsError", code: "catch_up_failed" });
  });
});
