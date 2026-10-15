// SPDX-License-Identifier: MPL-2.0
// The session caches of the manager answer only for the exact envelope they checked: a node that re-serves a message
// under the same id with another author or device, or with a different body under the same signature, never gets the
// earlier verdict (ENCRYPTION.md §5.2, FEDERATION.md §10.3). Real WebAssembly crypto against the in-memory nodes.
import { beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret } from "@tavrn/crypto";
import { b64urlEncode, jcs } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { MlsManager, qualify, type MlsMeta, type Pin } from "../src/mls";
import { CommandArgsVerifier, encryptCommandArgs } from "../src/commands";
import { ComponentValuesVerifier, encryptComponentValues } from "../src/components";
import { fingerprint } from "../src/lru";
import { envelopeFields } from "../src/plaintext";
import { Network, domainOf } from "./fake-node";

const DOMAIN = "t.local";
const CONV = qualify(DOMAIN, "01J9ZK3G5M8Q2W4E6R8T0Y2V00");
const DEV = {
  a: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1",
  b: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1",
  c: "01J9ZK3G5M8Q2W4E6R8T0Y2VC1",
  d: "01J9ZK3G5M8Q2W4E6R8T0Y2VD1",
};

beforeAll(() => ensureCrypto());

function setup() {
  const net = new Network();
  net.node(DOMAIN);
  const device = (user: string, deviceId: string) => {
    const address = `${user}@${DOMAIN}`;
    const home = net.node(domainOf(address));
    const master = MasterSecret.generate();
    home.addUser(user, master);
    const record = home.users.get(user)!;
    const client = Client.create(address, deviceId);
    record.devices.set(deviceId, { pk: b64urlEncode(client.devicePublicKey), sig: b64urlEncode(master.attestDevice(address, deviceId, client.devicePublicKey)) });
    record.kps.set(deviceId, Array.from({ length: 3 }, () => b64urlEncode(client.createKeyPackage())));
    const pins: Record<string, Pin> = {};
    const meta: MlsMeta = { convs: {} };
    const mls = new MlsManager({
      api: net.api(address, deviceId),
      client,
      address,
      deviceId,
      homeDomain: domainOf(address),
      persist: async () => undefined,
      backupKey: () => master.backupKey(),
      ownIdentityKey: () => b64urlEncode(master.identityPublicKey()),
      pins,
      savePins: async () => undefined,
      meta,
      saveMeta: async () => undefined,
      onEvent: () => undefined,
      backupDelayMs: 60_000,
    });
    return { mls, address, deviceId };
  };
  return { device };
}

describe("decrypt cache is bound to the author, device and epoch of the envelope", () => {
  it("a message re-served under the same id with another author or device is decrypted again and refused", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const carol = device("carol", DEV.c);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await carol.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    await bob.mls.catchUp(CONV);
    const { content, epoch } = await alice.mls.encrypt(CONV, { type: "text", body: "I resign" });
    const m = { id: "x1", author: alice.address, device_id: DEV.a, epoch, content };
    expect(await carol.mls.decrypt(CONV, m)).toMatchObject({ ok: true, content: { body: "I resign" } });
    // The same id, now attributed to Bob (his device or Alice's), or to another device of Alice.
    for (const forged of [
      { ...m, author: bob.address, device_id: DEV.b },
      { ...m, author: bob.address },
      { ...m, device_id: DEV.d },
    ]) {
      expect(await carol.mls.decrypt(CONV, forged)).not.toMatchObject({ ok: true });
      expect(carol.mls.peek(CONV, forged)).not.toMatchObject({ ok: true });
    }
    // Another epoch in the envelope than in the ciphertext's header.
    expect(await carol.mls.decrypt(CONV, { ...m, epoch: epoch + 1 })).not.toMatchObject({ ok: true });
    // The genuine envelope still answers from the cache, also after the forgeries.
    expect(carol.mls.peek(CONV, m)).toMatchObject({ ok: true, content: { body: "I resign" } });
    expect(await carol.mls.decrypt(CONV, m)).toMatchObject({ ok: true, content: { body: "I resign" } });
  });

  it("a thread title re-served for another author is refused", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    const t = await alice.mls.encryptThreadTitle(CONV, "Plans", "T1");
    const thread = { id: "T1", title: t.title, title_epoch: t.title_epoch, title_author: alice.address, title_device_id: DEV.a };
    expect(await bob.mls.decryptThreadTitle(CONV, thread)).toEqual({ ok: true, title: "Plans" });
    expect(await bob.mls.decryptThreadTitle(CONV, { ...thread, title_author: bob.address, title_device_id: DEV.b })).toMatchObject({ ok: false });
  });

  it("command arguments refused once are refused again when the interaction is re-delivered for another invoker", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bot = device("bot", DEV.d);
    const carol = device("carol", DEV.c);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bot.mls.ensureJoined(CONV, { canCreate: true });
    await carol.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    await bot.mls.catchUp(CONV);
    const verifier = new CommandArgsVerifier();
    const sealed = await encryptCommandArgs(alice.mls, CONV, "app/kick", { user: "victim@t.local" });
    const env = { id: "interaction:I1", author: alice.address, device_id: DEV.a, epoch: sealed.epoch, content: sealed.args_ciphertext };
    // First delivery names another command: refused by the verifier.
    const d1 = await bot.mls.decrypt(CONV, env);
    expect(d1.ok).toBe(true);
    expect(verifier.check(d1.ok ? d1.content : null, "app/other")).toMatchObject({ ok: false, reason: "command" });
    // The same interaction id again, now naming Carol as the invoker: never Alice's arguments.
    for (const forged of [
      { ...env, author: carol.address, device_id: DEV.c },
      { ...env, author: carol.address },
    ]) {
      const d2 = await bot.mls.decrypt(CONV, forged);
      expect(d2.ok).toBe(false);
    }
  });

  it("component values are refused when the interaction is re-delivered for another user", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bot = device("bot", DEV.d);
    const carol = device("carol", DEV.c);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bot.mls.ensureJoined(CONV, { canCreate: true });
    await carol.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    await bot.mls.catchUp(CONV);
    const verifier = new ComponentValuesVerifier();
    const sealed = await encryptComponentValues(alice.mls, CONV, "M1", "approve", ["yes"]);
    const env = { id: "interaction:I2", author: alice.address, device_id: DEV.a, epoch: sealed.epoch, content: sealed.values_ciphertext };
    const d1 = await bot.mls.decrypt(CONV, env);
    expect(d1.ok).toBe(true);
    expect(verifier.checkComponent(d1.ok ? d1.content : null, { messageId: "M2", customId: "approve" })).toMatchObject({ ok: false });
    expect(await bot.mls.decrypt(CONV, { ...env, author: carol.address, device_id: DEV.c })).toMatchObject({ ok: false });
  });
});

/**
 * A second preimage of the earlier 53-bit session fingerprint (two 32-bit multiply-xor lanes, found by a bit-sliced
 * search over four UTF-16 code units at the end of the body): the forged body below has the same fingerprint as the
 * signed input of the genuine message. The plaintext signature cache must never take it for the checked message.
 */
const GENUINE_BODY = "Please send the 500 EUR to IBAN DE11 1111 1111 1111 1111 11 ....";
const FORGED_BODY = "Please send the 500 EUR to IBAN DE99 6666 6666 6666 6666 66 \u43bc\u73f1\u5ebd\ud670";

describe("plaintext signature cache is keyed by the exact signed input", () => {
  it("a forged body whose 53-bit fingerprint equals the genuine one is invalid in the session that saw the original", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const content = { type: "text", body: GENUINE_BODY };
    const fields = { reply_to: null, thread_id: null, mentions_everyone: false, mentions: [], attachments: [] };
    const signature = alice.mls.signPlaintext(CONV, fields, content)!;
    const envelope = { id: "p1", author: alice.address, device_id: DEV.a, reply_to_id: null, thread_id: null, mentions: [], mentions_everyone: false, attachments: [], content, signature };
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    const forgedEnvelope = { ...envelope, content: { type: "text", body: FORGED_BODY } };
    const input = (e: typeof envelope) => `${JSON.stringify(envelopeFields(CONV, e))}|${jcs(e.content)}`;
    // The precondition: a genuine collision of the old fingerprint, with a different signed input.
    expect(input(forgedEnvelope)).not.toBe(input(envelope));
    expect(fingerprint(input(forgedEnvelope))).toBe(fingerprint(input(envelope)));
    expect(await bob.mls.verifyPlaintext(CONV, forgedEnvelope)).toBe("invalid");
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
  });

  it("an envelope object changed in place after its check is checked again", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const content = { type: "text", body: "genuine" };
    const fields = { reply_to: null, thread_id: null, mentions_everyone: false, mentions: [], attachments: [] };
    const signature = alice.mls.signPlaintext(CONV, fields, content)!;
    const envelope = { id: "p1", author: alice.address, device_id: DEV.a, reply_to_id: null, thread_id: null, mentions: [] as string[], mentions_everyone: false, attachments: [], content: content as Record<string, unknown>, signature };
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    // A store that applies an update onto the same object: a new content object, a new body, another field.
    envelope.content = { type: "text", body: "changed" };
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("invalid");
    envelope.content = content;
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    content.body = "changed in place";
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("invalid");
    content.body = "genuine";
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    envelope.mentions_everyone = true;
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("invalid");
  });

  it("nested content changed in place (a GIF, an embed field) is checked again", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const content = { type: "text", body: "look", gif: { url: "https://media.example/a.gif", width: 200 }, embeds: [{ title: "Report", fields: [{ name: "IBAN", value: "DE11" }] }] };
    const fields = { reply_to: null, thread_id: null, mentions_everyone: false, mentions: [], attachments: [] };
    const signature = alice.mls.signPlaintext(CONV, fields, content)!;
    const envelope = { id: "p1", author: alice.address, device_id: DEV.a, reply_to_id: null, thread_id: null, mentions: [], mentions_everyone: false, attachments: [], content, signature };
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    content.gif.url = "https://evil.example/b.gif";
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("invalid");
    content.gif.url = "https://media.example/a.gif";
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    content.embeds[0]!.fields[0]!.value = "DE99";
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("invalid");
  });
});
