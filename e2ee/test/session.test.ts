// SPDX-License-Identifier: MPL-2.0
// Two parties end to end in Node.js, the way a bot will run: account setup through the account flows,
// the session manager opened from a KeyStore (in memory and file based), messages, ephemeral events,
// plaintext signatures, history backups on a new device and a restart from the state directory.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RecoveryKey } from "@tavrn/crypto";
import {
  KEY_PACKAGE_BATCH,
  MemoryKeyStore,
  PINS,
  VERIFIED,
  ensureCrypto,
  openMlsManager,
  qualify,
  readJsonSecret,
  setupAccount,
  signedAttachments,
  unlockWithRecoveryKey,
  type KeyStore,
  type MlsEvent,
  type MlsManager,
  type Pin,
} from "../src/index";
import { FileKeyStore } from "../src/node";
import { Network } from "./fake-node";

const DOMAIN = "t.local";
const CONV = qualify(DOMAIN, "01J9ZK3G5M8Q2W4E6R8T0Y2V00");
const DEV = { a: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1", a2: "01J9ZK3G5M8Q2W4E6R8T0Y2VA2", b: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1" };

const root = mkdtempSync(join(tmpdir(), "tavrn-e2ee-session-"));
let n = 0;
const freshDir = () => join(root, `d${++n}`);

beforeAll(() => ensureCrypto());
afterAll(() => rmSync(root, { recursive: true, force: true }));

interface Party {
  address: string;
  deviceId: string;
  store: KeyStore;
  mls: MlsManager;
  events: MlsEvent[];
  words: string;
}

async function open(net: Network, address: string, deviceId: string, store: KeyStore, events: MlsEvent[]): Promise<MlsManager> {
  const mls = await openMlsManager(store, { api: net.api(address, deviceId), address, deviceId, homeDomain: DOMAIN, onEvent: (e) => events.push(e), backupDelayMs: 60_000 });
  if (!mls) throw new Error("no MLS client");
  return mls;
}

/** A new account with one device: master secret, identity key, recovery entry, attested device, KeyPackages. */
async function party(net: Network, username: string, deviceId: string, store: KeyStore): Promise<Party> {
  const address = `${username}@${DOMAIN}`;
  const recovery = RecoveryKey.generate();
  const words = recovery.toWords();
  await setupAccount({ api: net.node(DOMAIN).accountApi(username), username, address, deviceId, store }, recovery);
  const events: MlsEvent[] = [];
  return { address, deviceId, store, events, words, mls: await open(net, address, deviceId, store, events) };
}

async function send(p: Party, body: string, id: string) {
  const { content, epoch } = await p.mls.encrypt(CONV, { type: "text", body });
  return { id, author: p.address, device_id: p.deviceId, epoch, content };
}

const kinds: [string, () => KeyStore][] = [
  ["memory", () => new MemoryKeyStore()],
  ["file", () => new FileKeyStore(freshDir())],
];

describe.each(kinds)("two parties (%s store)", (_kind, makeStore) => {
  async function pair() {
    const net = new Network();
    const alice = await party(net, "alice", DEV.a, makeStore());
    const bob = await party(net, "bob", DEV.b, makeStore());
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    return { net, alice, bob };
  }

  it("sets up both accounts, creates and joins the group, and both read each other", async () => {
    const { net, alice, bob } = await pair();
    const node = net.node(DOMAIN);
    expect(node.users.get("alice")!.kps.get(DEV.a)).toHaveLength(KEY_PACKAGE_BATCH);
    expect(alice.mls.epoch(CONV)).toBe(1);
    expect(bob.mls.epoch(CONV)).toBe(1);
    const m1 = await send(alice, "hallo bob", "m1");
    expect(await bob.mls.decrypt(CONV, m1)).toEqual({ ok: true, content: { type: "text", body: "hallo bob" } });
    const m2 = await send(bob, "hallo alice", "m2");
    expect(await alice.mls.decrypt(CONV, m2)).toEqual({ ok: true, content: { type: "text", body: "hallo alice" } });
    expect(await alice.mls.ghostCheck(CONV, [alice.address, bob.address])).toEqual([]);
    // Pins are stored in the key store.
    expect(Object.keys(await readJsonSecret<Record<string, Pin>>(bob.store, PINS, {}))).toEqual([alice.address]);
  });

  it("encrypts and decrypts ephemeral events and rejects their replay", async () => {
    const { alice, bob } = await pair();
    const content = await alice.mls.encryptEphemeral(CONV, { type: "cursor", x: 1, y: 2 });
    expect(await bob.mls.decryptEphemeral(CONV, alice.address, DEV.a, content)).toEqual({ ok: true, content: { type: "cursor", x: 1, y: 2 } });
    expect(await bob.mls.decryptEphemeral(CONV, alice.address, DEV.a, content)).toEqual({ ok: false, reason: "replay" });
    expect((await bob.mls.decryptEphemeral(CONV, bob.address, DEV.b, content)).ok).toBe(false);
  });

  it("signs plaintext messages and verifies them against the attested device", async () => {
    const { alice, bob } = await pair();
    const fields = { reply_to: null, thread_id: null, mentions_everyone: false, mentions: [], attachments: signedAttachments([]) };
    const content = { type: "text", body: "unverschlüsselt" };
    const signature = alice.mls.signPlaintext(CONV, fields, content);
    expect(signature).toBeTruthy();
    const envelope = { id: "p1", author: alice.address, device_id: DEV.a, content, signature };
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p2", content: { type: "text", body: "geändert" } })).toBe("invalid");
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p3" })).toBe("replay");
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p4", signature: null })).toBe("unsigned");
  });

  it("backs up epoch keys and restores the history on a new device unlocked with the recovery key", async () => {
    const { net, alice, bob } = await pair();
    const old = await send(bob, "vor dem neuen Gerät", "m1");
    expect(await alice.mls.decrypt(CONV, old)).toMatchObject({ ok: true });
    await alice.mls.flushBackups();
    expect(alice.mls.hasPendingBackups()).toBe(false);
    // The conversation's backup and the account's trust record (ENCRYPTION.md §7).
    expect([...net.node(DOMAIN).backups.keys()].filter((k) => !k.endsWith("/00000000000000000000000000"))).toHaveLength(1);

    // Alice's second device: empty store, unlocked with the recovery key, attested, history restored.
    const store = makeStore();
    await unlockWithRecoveryKey({ api: net.node(DOMAIN).accountApi("alice"), username: "alice", address: alice.address, deviceId: DEV.a2, store }, alice.words);
    expect(store.masterSecret()).toEqual(alice.store.masterSecret());
    expect(net.node(DOMAIN).users.get("alice")!.devices.has(DEV.a2)).toBe(true);
    const second = await open(net, alice.address, DEV.a2, store, []);
    expect(second.hasGroup(CONV)).toBe(false);
    expect(await second.restoreBackups()).toBe(2);
    expect(await second.decrypt(CONV, old)).toMatchObject({ ok: true, content: { body: "vor dem neuen Gerät" } });
  });
});

describe("restart from the file store", () => {
  it("a restarted process unlocks the state directory with the master secret and carries on", async () => {
    const net = new Network();
    const dir = freshDir();
    const alice = await party(net, "alice", DEV.a, new FileKeyStore(dir));
    const bob = await party(net, "bob", DEV.b, new MemoryKeyStore());
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    const before = await send(bob, "vor dem Neustart", "m1");
    expect(await alice.mls.decrypt(CONV, before)).toMatchObject({ ok: true });

    // Shutdown: the bot keeps only its key file (the master secret) and the state directory.
    const masterSecret = alice.store.masterSecret();
    alice.mls.dispose();
    await (alice.store as FileKeyStore).close();

    const store = new FileKeyStore(dir);
    expect(await store.status(alice.address)).toBe("locked");
    expect(await store.resume(alice.address)).toBe(false);
    await store.unlockWithMaster(alice.address, masterSecret);
    masterSecret.fill(0);
    const events: MlsEvent[] = [];
    const restarted = await open(net, alice.address, DEV.a, store, events);
    expect(restarted.epoch(CONV)).toBe(1);
    // Old keys, new messages in both directions, the pins survived (no "key changed" notice).
    expect(await restarted.decrypt(CONV, before)).toMatchObject({ ok: true, content: { body: "vor dem Neustart" } });
    const after = await send(bob, "nach dem Neustart", "m2");
    expect(await restarted.decrypt(CONV, after)).toMatchObject({ ok: true, content: { body: "nach dem Neustart" } });
    const reply = await restarted.encrypt(CONV, { type: "text", body: "wieder da" });
    expect(await bob.mls.decrypt(CONV, { id: "m3", author: alice.address, device_id: DEV.a, ...reply })).toMatchObject({ ok: true, content: { body: "wieder da" } });
    expect(restarted.changedKeys()).toEqual([]);
    expect(events.filter((e) => e.type === "key_changed")).toEqual([]);
    // The pending backup of the join survived the restart.
    expect(restarted.hasPendingBackups()).toBe(true);
    await restarted.flushBackups();
    expect([...net.node(DOMAIN).backups.keys()].filter((k) => !k.endsWith("/00000000000000000000000000"))).toHaveLength(1);
    restarted.dispose();
    await store.close();
  });

  it("refuses to start over silently when the pins or verified contacts cannot be read", async () => {
    for (const [, makeStore] of kinds) await refusesUnreadable(makeStore);
  });

  async function refusesUnreadable(makeStore: () => KeyStore) {
    const net = new Network();
    const alice = await party(net, "alice", DEV.a, makeStore());
    alice.mls.dispose();
    for (const name of [PINS, VERIFIED]) {
      const broken = new TextEncoder().encode("{not json");
      await alice.store.putSecret(name, broken.slice());
      // A reset would pin every contact again without a "key changed" warning: fail loudly and keep the blob.
      await expect(open(net, alice.address, alice.deviceId, alice.store, [])).rejects.toMatchObject({ name: "E2eeError", code: "state_unreadable" });
      expect(await alice.store.getSecret(name)).toEqual(broken);
      await alice.store.putSecret(name, new TextEncoder().encode("{}"));
    }
    const reopened = await open(net, alice.address, alice.deviceId, alice.store, []);
    reopened.dispose();
  }

  it("a wrong master secret does not open the state directory", async () => {
    const net = new Network();
    const dir = freshDir();
    const alice = await party(net, "alice", DEV.a, new FileKeyStore(dir));
    alice.mls.dispose();
    await (alice.store as FileKeyStore).close();
    await expect(new FileKeyStore(dir).unlockWithMaster(alice.address, new Uint8Array(32).fill(1))).rejects.toMatchObject({ name: "local_key_mismatch" });
  });
});
