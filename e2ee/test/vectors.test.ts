// SPDX-License-Identifier: MPL-2.0
// The new entries of the protocol's reference values (protocol/testvectors/encryption.json) through @tavrn/e2ee: the
// local storage key, a message with the signed context (ENCRYPTION.md §5.2) and a history share (§7b) read by the
// session manager against a node that publishes the vectors' identity and device, and the sealed unlock material.
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret, inboxPublicKey } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { localStorageKey } from "../src/keystore";
import { MlsManager } from "../src/mls";
import { Network } from "./fake-node";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const V: Record<string, any> = JSON.parse(readFileSync(new URL("../../protocol/testvectors/encryption.json", import.meta.url), "utf8"));

beforeAll(() => ensureCrypto());

/** Bob's session manager; Alice (the vectors' author) is a user of node.example with the vectors' attested device. */
async function reader(): Promise<MlsManager> {
  const net = new Network();
  const node = net.node("node.example");
  const att = V.device_attestation;
  const alice = MasterSecret.fromBytes(b64urlDecode(V.keys.master_secret));
  node.addUser("alice", alice);
  node.users.get("alice")!.devices.set(att.device_id, { pk: att.device_public_key, sig: att.signature });
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
  await mls.importHistoryKeys(V.content_context.conversation, [[42, b64urlDecode(V.content_context.content_key)]]);
  return mls;
}

describe("encryption.json in @tavrn/e2ee", () => {
  it("local storage key", async () => {
    const v = V.local_storage_key;
    expect(b64urlEncode(await localStorageKey(b64urlDecode(v.master_secret), v.device_id))).toBe(v.key);
  });

  it("content with the signed context: shown in its thread, refused anywhere else", async () => {
    const v = V.content_context;
    const mls = await reader();
    const m = { id: "m1", author: v.author, device_id: v.device_id, epoch: v.epoch, content: v.content, thread_id: v.thread_id, reply_to_id: v.reply_to };
    const { ctx: _ctx, ...shown } = JSON.parse(v.json);
    expect(await mls.decrypt(v.conversation, m)).toEqual({ ok: true, content: shown });
    expect(await mls.decrypt(v.conversation, { ...m, thread_id: null })).toEqual({ ok: false, reason: "envelope_mismatch" });
    expect(await mls.decrypt(v.conversation, { ...m, reply_to_id: null })).toEqual({ ok: false, reason: "envelope_mismatch" });
    // The plain content vector carries no context and is shown in any envelope.
    const plain = { id: "m2", author: V.content.author, device_id: V.content.device_id, epoch: 42, content: V.content.content, thread_id: v.thread_id, reply_to_id: null };
    expect(await mls.decrypt(V.content.conversation, plain)).toEqual({ ok: true, content: JSON.parse(V.content.json) });
  });

  it("history share: decrypted and verified like content, never as a message", async () => {
    const v = V.history_share;
    const mls = await reader();
    expect(await mls.decryptHistory(v.conversation, "s1", v.author, v.device_id, v.ciphertext)).toEqual({ ok: true, content: JSON.parse(v.payload) });
    // Served as a message (to a device that has not seen it as a share) it is refused for its purpose.
    expect(await (await reader()).decrypt(v.conversation, { id: "s1", author: v.author, device_id: v.device_id, epoch: v.epoch, content: v.ciphertext })).toEqual({ ok: false, reason: "invalid" });
  });

  it("sealed unlock material opens with the app's seed", () => {
    const u = V.sealed_unlock;
    expect(b64urlEncode(inboxPublicKey(b64urlDecode(u.app_seed)))).toBe(u.app_public_key);
    const opener = Client.create("unlock@app.invalid", "00000000000000000000000000");
    opener.importEpochKey("app.invalid/00000000000000000000000000", 0, b64urlDecode(u.app_seed));
    expect(opener.openSealed("app.invalid/00000000000000000000000000", 0, b64urlDecode(u.sealed))).toBe(u.payload);
    opener.free();
  });
});
