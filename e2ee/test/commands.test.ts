// SPDX-License-Identifier: MPL-2.0
import { describe, expect, it } from "vitest";
import { COMMAND_ARGS_TYPE, CommandArgsVerifier, commandArgsContent, encryptCommandArgs } from "../src/commands";

const REF = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00/01J9ZK3G5M8Q2W4E6R8T0Y2V01";
const OTHER = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00/01J9ZK3G5M8Q2W4E6R8T0Y2V02";

describe("command arguments in encrypted conversations (APPLICATIONS.md §5.8)", () => {
  it("builds the command.args content with a fresh 16-byte nonce", () => {
    const now = new Date("2026-10-06T12:00:00Z");
    const a = commandArgsContent(REF, { city: "Rome" }, now);
    const b = commandArgsContent(REF, { city: "Rome" }, now);
    expect(a).toMatchObject({ type: COMMAND_ARGS_TYPE, command: REF, issued_at: "2026-10-06T12:00:00.000Z", args: { city: "Rome" } });
    expect(a.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it("encrypts through the session manager's encrypt", async () => {
    const seen: Array<{ q: string; content: Record<string, unknown> }> = [];
    const mls = { encrypt: async (q: string, content: Record<string, unknown>) => (seen.push({ q, content }), { content: "CIPHERTEXT", epoch: 7 }) };
    expect(await encryptCommandArgs(mls, "t.local/C", REF, { city: "Oslo" })).toEqual({ args_ciphertext: "CIPHERTEXT", epoch: 7 });
    expect(seen[0]!.q).toBe("t.local/C");
    expect(seen[0]!.content).toMatchObject({ type: "command.args", command: REF, args: { city: "Oslo" } });
  });

  it("the application refuses moved, stale, future, replayed and malformed arguments", () => {
    let now = Date.parse("2026-10-06T12:00:00Z");
    const v = new CommandArgsVerifier({ now: () => now });
    const fresh = commandArgsContent(REF, { city: "Rome" }, new Date(now));
    expect(v.check(fresh, OTHER)).toEqual({ ok: false, reason: "command" });
    expect(v.check(fresh, REF)).toEqual({ ok: true, args: { city: "Rome" } });
    expect(v.check(fresh, REF)).toEqual({ ok: false, reason: "replay" });
    expect(v.check(commandArgsContent(REF, {}, new Date(now - 5 * 60 * 1000 - 1)), REF)).toEqual({ ok: false, reason: "stale" });
    expect(v.check(commandArgsContent(REF, {}, new Date(now + 5 * 60 * 1000)), REF)).toEqual({ ok: false, reason: "future" });
    for (const bad of [null, "x", [], { ...fresh, type: "text" }, { ...fresh, nonce: "short" }, { ...fresh, args: [1] }, { ...fresh, issued_at: "yesterday" }]) {
      expect(v.check(bad, REF)).toMatchObject({ ok: false, reason: "invalid" });
    }
    // Nonces are kept 15 minutes; after that the arguments are refused as stale anyway.
    now += 16 * 60 * 1000;
    expect(v.check(fresh, REF)).toEqual({ ok: false, reason: "stale" });
  });
});
