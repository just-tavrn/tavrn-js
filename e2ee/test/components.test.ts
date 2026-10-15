// SPDX-License-Identifier: MPL-2.0
// Component values and modal input in encrypted conversations (APPLICATIONS.md §5.10): the content builders, the
// encryption through the session manager's `encrypt`, the application's checks, and the protocol's components.json
// vectors (encrypted by the vectors' device, decrypted and verified by a member).
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { MlsManager } from "../src/mls";
import {
  COMPONENT_VALUES_TYPE,
  ComponentValuesVerifier,
  MODAL_VALUES_TYPE,
  componentValuesContent,
  encryptComponentValues,
  encryptModalValues,
  modalValuesContent,
} from "../src/components";
import { Network } from "./fake-node";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const E: Record<string, any> = JSON.parse(readFileSync(new URL("../../protocol/testvectors/encryption.json", import.meta.url), "utf8"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const V: Record<string, any> = JSON.parse(readFileSync(new URL("../../protocol/testvectors/components.json", import.meta.url), "utf8"));

beforeAll(() => ensureCrypto());

/** Bob, a member of the vectors' conversation; Alice (the vectors' invoker) has the vectors' attested device. */
async function member(): Promise<MlsManager> {
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
  await mls.importHistoryKeys(V.component_values.conversation, [[42, b64urlDecode(V.component_values.content_key)]]);
  return mls;
}

describe("component values and modal input (APPLICATIONS.md §5.10.2, §5.10.4)", () => {
  it("builds the content objects with fresh 16-byte nonces", () => {
    const now = new Date("2026-10-15T18:00:00Z");
    const a = componentValuesContent("M1", "raid:class", ["healer"], now);
    expect(a).toMatchObject({ type: COMPONENT_VALUES_TYPE, message_id: "M1", custom_id: "raid:class", values: ["healer"], issued_at: "2026-10-15T18:00:00.000Z" });
    expect(a.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(componentValuesContent("M1", "b", null, now).nonce).not.toBe(a.nonce);
    expect(modalValuesContent("I1", "raid:note", { note: "x" }, now)).toMatchObject({ type: MODAL_VALUES_TYPE, interaction: "I1", custom_id: "raid:note", values: { note: "x" } });
  });

  it("encrypts through the session manager's encrypt", async () => {
    const seen: Record<string, unknown>[] = [];
    const mls = { encrypt: async (_q: string, content: Record<string, unknown>) => (seen.push(content), { content: "CT", epoch: 9 }) };
    expect(await encryptComponentValues(mls, "c.local/C", "M1", "signup", null)).toEqual({ values_ciphertext: "CT", epoch: 9 });
    expect(await encryptModalValues(mls, "c.local/C", "I1", "raid:note", { note: "late" })).toEqual({ values_ciphertext: "CT", epoch: 9 });
    expect(seen[0]).toMatchObject({ type: "component.values", message_id: "M1", custom_id: "signup", values: null });
    expect(seen[1]).toMatchObject({ type: "modal.values", interaction: "I1", values: { note: "late" } });
  });

  it("the application refuses moved, stale, future, replayed and malformed values", () => {
    let now = Date.parse("2026-10-15T18:00:00Z");
    const v = new ComponentValuesVerifier({ now: () => now });
    const fresh = componentValuesContent("M1", "class", ["tank"], new Date(now));
    expect(v.checkComponent(fresh, { messageId: "M2", customId: "class" })).toEqual({ ok: false, reason: "message" });
    expect(v.checkComponent(fresh, { messageId: "M1", customId: "other" })).toEqual({ ok: false, reason: "custom_id" });
    expect(v.checkComponent(fresh, { messageId: "M1", customId: "class" })).toEqual({ ok: true, values: ["tank"] });
    expect(v.checkComponent(fresh, { messageId: "M1", customId: "class" })).toEqual({ ok: false, reason: "replay" });
    const button = componentValuesContent("M1", "signup", null, new Date(now));
    expect(v.checkComponent(button, { messageId: "M1", customId: "signup" })).toEqual({ ok: true, values: null });
    expect(v.checkComponent(componentValuesContent("M1", "class", [], new Date(now - 5 * 60 * 1000 - 1)), { messageId: "M1", customId: "class" })).toEqual({ ok: false, reason: "stale" });
    expect(v.checkComponent(componentValuesContent("M1", "class", [], new Date(now + 5 * 60 * 1000)), { messageId: "M1", customId: "class" })).toEqual({ ok: false, reason: "future" });
    for (const bad of [null, "x", [], { ...fresh, type: "command.args" }, { ...fresh, nonce: "short" }, { ...fresh, values: [1] }, { ...fresh, values: "tank" }, { ...fresh, issued_at: "today" }]) {
      expect(v.checkComponent(bad, { messageId: "M1", customId: "class" })).toMatchObject({ ok: false, reason: "invalid" });
    }
    const form = modalValuesContent("I1", "raid:note", { note: "late" }, new Date(now));
    expect(v.checkModal(form, { interactionId: "I2", customId: "raid:note" })).toEqual({ ok: false, reason: "interaction" });
    expect(v.checkModal(form, { interactionId: "I1", customId: "x" })).toEqual({ ok: false, reason: "custom_id" });
    expect(v.checkModal(fresh, { interactionId: "I1", customId: "raid:note" })).toEqual({ ok: false, reason: "invalid" });
    expect(v.checkModal({ ...form, values: { note: 5 } }, { interactionId: "I1", customId: "raid:note" })).toEqual({ ok: false, reason: "invalid" });
    expect(v.checkModal(form, { interactionId: "I1", customId: "raid:note" })).toEqual({ ok: true, values: { note: "late" } });
    expect(v.checkModal(form, { interactionId: "I1", customId: "raid:note" })).toEqual({ ok: false, reason: "replay" });
    now += 16 * 60 * 1000;
    expect(v.checkModal(form, { interactionId: "I1", customId: "raid:note" })).toEqual({ ok: false, reason: "stale" });
  });

  it("decrypts and verifies the vectors of components.json", async () => {
    const mls = await member();
    for (const [key, check] of [
      ["component_values", (v: ComponentValuesVerifier, c: Record<string, unknown>) => v.checkComponent(c, { messageId: "01J9ZK3G5M8Q2W4E6R8T0Y2VM1", customId: "raid:class" })],
      ["modal_values", (v: ComponentValuesVerifier, c: Record<string, unknown>) => v.checkModal(c, { interactionId: "01J9ZK3G5M8Q2W4E6R8T0Y2VI1", customId: "raid:note" })],
    ] as const) {
      const vec = V[key];
      const d = await mls.decrypt(vec.conversation, { id: `interaction:${key}`, author: vec.author, device_id: vec.device_id, epoch: vec.epoch, content: vec.values_ciphertext });
      expect(d.ok, key).toBe(true);
      if (!d.ok) continue;
      expect(JSON.stringify(d.content)).toBe(vec.json);
      const issued = Date.parse(d.content.issued_at as string);
      expect(check(new ComponentValuesVerifier({ now: () => issued + 1000 }), d.content).ok, key).toBe(true);
    }
    // Served as somebody else's values: the AAD names the invoker.
    const vec = V.component_values;
    const other = await (await member()).decrypt(vec.conversation, { id: "x", author: "bob@node.example", device_id: vec.device_id, epoch: vec.epoch, content: vec.values_ciphertext });
    expect(other.ok).toBe(false);
  });
});
