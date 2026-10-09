// SPDX-License-Identifier: MPL-2.0
// The session manager with the real WebAssembly crypto: several devices talk to in-memory nodes whose
// delivery services follow the node's rules for epochs, the handshake log, Welcomes and backups. Users
// live on different nodes (FEDERATION.md §3.5, §6): conversations are hosted by one node, keys come
// from each user's home node, KeyPackages of other nodes' users are claimed through the hosting node.
import { beforeAll, describe, expect, it, vi } from "vitest";
import { Client, IdentityKey, MasterSecret, sealToInbox, signContinuity } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { MlsError, MlsManager, contentHeader, normalizeMeta, qualify, splitQualified, type MlsApi, type MlsEvent, type MlsMeta, type Pin } from "../src/mls";
import { Network, domainOf, problem } from "./fake-node";
import { LeafCleaner } from "../src/cleanup";
import { CommandArgsVerifier, encryptCommandArgs } from "../src/commands";

const DOMAIN = "t.local";
const A = "a.test";
const B = "b.test";
const ID = "01J9ZK3G5M8Q2W4E6R8T0Y2V00";
const ID2 = "01J9ZK3G5M8Q2W4E6R8T0Y2V01";
/** Conversations of the classic single-node tests (hosted on the users' home node). */
const CONV = qualify(DOMAIN, ID);
const CONV2 = qualify(DOMAIN, ID2);
const DEV = {
  a: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1",
  a2: "01J9ZK3G5M8Q2W4E6R8T0Y2VA2",
  a3: "01J9ZK3G5M8Q2W4E6R8T0Y2VA3",
  b: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1",
  c: "01J9ZK3G5M8Q2W4E6R8T0Y2VC1",
  d: "01J9ZK3G5M8Q2W4E6R8T0Y2VD1",
};

beforeAll(() => ensureCrypto());

interface Device {
  mls: MlsManager;
  client: () => Client;
  events: MlsEvent[];
  pins: Record<string, Pin>;
  meta: MlsMeta;
  address: string;
}

function setup() {
  const net = new Network();
  const node = net.node(DOMAIN);
  const masters = new Map<string, MasterSecret>();
  /** A device of `user` (`name` on t.local, or `name@domain`). */
  const device = (user: string, deviceId: string, opts: { kps?: number; forgedAttestation?: boolean; meta?: MlsMeta; kind?: string } = {}): Device => {
    const address = user.includes("@") ? user : `${user}@${DOMAIN}`;
    const username = address.slice(0, address.lastIndexOf("@"));
    const home = net.node(domainOf(address));
    let master = masters.get(address);
    if (!master) {
      master = MasterSecret.generate();
      masters.set(address, master);
      home.addUser(username, master);
    }
    const record = home.users.get(username)!;
    if (opts.kind) record.kind = opts.kind;
    let client = Client.create(address, deviceId);
    const signer = opts.forgedAttestation ? MasterSecret.generate() : master;
    record.devices.set(deviceId, { pk: b64urlEncode(client.devicePublicKey), sig: b64urlEncode(signer.attestDevice(address, deviceId, client.devicePublicKey)) });
    record.kps.set(deviceId, Array.from({ length: opts.kps ?? 3 }, () => b64urlEncode(client.createKeyPackage())));
    const events: MlsEvent[] = [];
    const pins: Record<string, Pin> = {};
    const meta: MlsMeta = opts.meta ?? { convs: {} };
    const m = master;
    const mls = new MlsManager({
      api: net.api(address, deviceId),
      client,
      address,
      deviceId,
      homeDomain: domainOf(address),
      persist: async (c) => {
        // Round trip through the exported state, as the store does (IndexedDB).
        client = c;
        Client.importState(c.exportState()).free();
      },
      backupKey: () => m.backupKey(),
      ownIdentityKey: () => b64urlEncode(m.identityPublicKey()),
      pins,
      savePins: async () => undefined,
      meta,
      saveMeta: async () => undefined,
      onEvent: (e) => events.push(e),
      backupDelayMs: 60_000,
    });
    return { mls, client: () => client, events, pins, meta, address };
  };
  return { net, node, device, masters };
}

async function send(dev: Device, conv: string, body: string, id: string) {
  const { content, epoch } = await dev.mls.encrypt(conv, { type: "text", body });
  return { id, author: dev.address, device_id: dev.client().deviceId, epoch, content };
}

const memberSet = (...devs: Device[]) => devs.map((d) => d.address);

describe("MlsManager", () => {
  it("creates the group, lets a second device join by external commit, and both read each other", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    expect(await bob.mls.ensureJoined(CONV, { canCreate: false })).toBe("no_group");
    expect(await alice.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    expect(node.groups.get(ID)!.epoch).toBe(0);
    const m1 = await send(alice, CONV, "hallo", "m1");

    expect(await bob.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    expect(node.groups.get(ID)!.epoch).toBe(1);
    await alice.mls.catchUp(CONV);
    expect(alice.mls.epoch(CONV)).toBe(1);
    // New members cannot read what was sent before their join (§5.4).
    expect(await bob.mls.decrypt(CONV, m1)).toEqual({ ok: false, reason: "missing_key" });
    const m2 = await send(bob, CONV, "hi alice", "m2");
    expect(await alice.mls.decrypt(CONV, m2)).toEqual({ ok: true, content: { type: "text", body: "hi alice" } });
    const m3 = await send(alice, CONV, "hi bob", "m3");
    expect(await bob.mls.decrypt(CONV, m3)).toEqual({ ok: true, content: { type: "text", body: "hi bob" } });
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, bob))).toEqual([]);
    expect(Object.keys(bob.pins)).toEqual([alice.address]);
  });

  it("encrypts ephemeral events like messages, verifies the sender and rejects replays", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    const calls = node.dsCalls;
    const content = await alice.mls.encryptEphemeral(CONV, { type: "whiteboard.update", elements: [] });
    expect(node.dsCalls).toBe(calls); // no catch-up, no rotation: nothing asked from the node
    expect(contentHeader(content)?.epoch).toBe(1);
    expect(await bob.mls.decryptEphemeral(CONV, alice.address, DEV.a, content)).toEqual({ ok: true, content: { type: "whiteboard.update", elements: [] } });
    // The same ciphertext again is a replay; another claimed sender fails the signature check.
    expect(await bob.mls.decryptEphemeral(CONV, alice.address, DEV.a, content)).toEqual({ ok: false, reason: "replay" });
    const other = await alice.mls.encryptEphemeral(CONV, { type: "cursor", x: 1, y: 2 });
    expect((await bob.mls.decryptEphemeral(CONV, bob.address, DEV.b, other)).ok).toBe(false);
    expect(await bob.mls.decryptEphemeral(CONV, alice.address, DEV.a, "garbage")).toEqual({ ok: false, reason: "invalid" });
    expect(await bob.mls.decryptEphemeral(CONV, alice.address, DEV.a, { not: "a string" })).toEqual({ ok: false, reason: "invalid" });
    // Ephemeral events never fill the message cache.
    expect(bob.mls.peek(CONV, { id: "x", author: alice.address, device_id: DEV.a, epoch: 1, content })).toBeUndefined();
    await expect(device("carol", DEV.c).mls.encryptEphemeral(CONV, { type: "cursor" })).rejects.toMatchObject({ code: "not_joined" });
  });

  it("adds the devices of DM members with a Welcome and reports members without a device", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    // carol does not exist on the node: skipped; own devices are never added again.
    const waiting = await alice.mls.addMissingDevices(CONV, [alice.address, bob.address, `carol@${DOMAIN}`]);
    expect(waiting).toEqual([]);
    expect(alice.mls.epoch(CONV)).toBe(1);
    const m1 = await send(alice, CONV, "willkommen", "m1");
    expect(await bob.mls.processWelcomes(DOMAIN)).toEqual([CONV]);
    expect(bob.mls.epoch(CONV)).toBe(1);
    expect(await bob.mls.decrypt(CONV, m1)).toMatchObject({ ok: true, content: { body: "willkommen" } });
    // Nothing left to add.
    expect(await alice.mls.addMissingDevices(CONV, [bob.address])).toEqual([]);
    expect(alice.mls.epoch(CONV)).toBe(1);
  });

  it("waits for members without an attested device", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    node.users.get("bob")!.devices.clear();
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    expect(await alice.mls.addMissingDevices(CONV, [bob.address])).toEqual([bob.address]);
  });

  it("rejects a Welcome that names another conversation and keeps the state unchanged", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.addMissingDevices(CONV, [bob.address]);
    // A malicious node delivers the Welcome as if it were for another conversation.
    const key = `${bob.address}/${DEV.b}`;
    node.welcomes.get(key)![0]!.conversation_id = ID2;
    expect(await bob.mls.processWelcomes(DOMAIN)).toEqual([]);
    expect(bob.mls.hasGroup(CONV)).toBe(false);
    expect(bob.mls.hasGroup(CONV2)).toBe(false);
    expect(node.welcomes.get(key)).toEqual([]);
  });

  it("retries a commit after an epoch conflict", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    // Alice rotates (epoch 2) while Bob still is at epoch 1 and has a rotation due.
    alice.meta.convs[CONV] = { rotatedAt: 0 };
    await send(alice, CONV, "x", "m0");
    expect(node.groups.get(ID)!.epoch).toBe(2);
    bob.meta.convs[CONV] = { rotatedAt: Date.now(), rotate: true };
    const m = await send(bob, CONV, "nach dem Konflikt", "m1");
    expect(node.groups.get(ID)!.epoch).toBe(3);
    expect(m.epoch).toBe(3);
    await alice.mls.catchUp(CONV);
    expect(await alice.mls.decrypt(CONV, m)).toMatchObject({ ok: true, content: { body: "nach dem Konflikt" } });
  });

  it("removes members; the removed device loses access, others rotate on their next message", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const carol = device("carol", DEV.c);
    for (const d of [alice, bob, carol]) {
      await d.mls.ensureJoined(CONV, { canCreate: true });
    }
    await alice.mls.catchUp(CONV);
    await bob.mls.catchUp(CONV);
    expect(await alice.mls.removeLeaves(CONV, [`${bob.address}/${DEV.b}`, "nobody@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2VZZ"])).toBe(true);
    expect(await alice.mls.removeLeaves(CONV, [`${bob.address}/${DEV.b}`])).toBe(false);
    await bob.mls.catchUp(CONV);
    expect(bob.events).toContainEqual({ type: "removed", conversationId: CONV });
    expect(bob.mls.hasGroup(CONV)).toBe(false);
    await carol.mls.catchUp(CONV);
    expect(carol.meta.convs[CONV]!.rotate).toBe(true);
    const before = node.groups.get(ID)!.epoch;
    const m = await send(carol, CONV, "geheim", "m1");
    expect(node.groups.get(ID)!.epoch).toBe(before + 1);
    expect(carol.meta.convs[CONV]!.rotate).toBeUndefined();
    expect((await bob.mls.decrypt(CONV, m)).ok).toBe(false);
    await alice.mls.catchUp(CONV);
    expect(await alice.mls.decrypt(CONV, m)).toMatchObject({ ok: true });
  });

  it("rejoins by external commit when a commit fails validation", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    // Alice is still at epoch 0, and the log holds a bogus "commit" for it.
    node.groups.get(ID)!.log.set(0, b64urlEncode(new Uint8Array([0, 1, 2, 3])));
    await alice.mls.catchUp(CONV);
    expect(alice.events).toContainEqual({ type: "rejoined", conversationId: CONV });
    expect(alice.mls.epoch(CONV)).toBe(2);
    await bob.mls.catchUp(CONV);
    const m = await send(alice, CONV, "wieder da", "m1");
    expect(await bob.mls.decrypt(CONV, m)).toMatchObject({ ok: true });
  });

  it("merges backups of two devices and restores the whole history on a new device", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const old = await send(alice, CONV, "epoche 0", "m0");
    await alice.mls.flushBackups();
    // A second device of Alice joins later; it knows only newer epochs.
    const laptop = device("alice", DEV.a2);
    await laptop.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await laptop.mls.catchUp(CONV);
    const recent = await send(bob, CONV, "epoche 2", "m1");
    node.failNextPut = true; // a concurrent upload: If-Match fails once, the client merges again
    await laptop.mls.flushBackups();
    const blob = node.backups.get(`${alice.address}|${CONV}`)!;
    expect(blob).toBeTruthy();

    const fresh = device("alice", DEV.a3);
    expect(await fresh.mls.restoreBackups()).toBe(3);
    expect(Array.from(fresh.client().knownEpochs(CONV))).toEqual([0, 1, 2]);
    expect(await fresh.mls.decrypt(CONV, old)).toMatchObject({ ok: true, content: { body: "epoche 0" } });
    expect(await fresh.mls.decrypt(CONV, recent)).toMatchObject({ ok: true, content: { body: "epoche 2" } });
    expect(await fresh.mls.restoreBackups()).toBe(0);
  });

  it("keeps pending backups across a restart of the manager", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    expect(alice.meta.pendingBackups).toEqual([CONV]);
    expect(node.backups.size).toBe(0);
    // The page reloads before the debounced upload: the new manager finds the pending entry.
    const restarted = new MlsManager({ ...(alice.mls as unknown as { deps: ConstructorParameters<typeof MlsManager>[0] }).deps, client: alice.client() });
    await restarted.flushBackups();
    expect(node.backups.size).toBe(1);
    expect(alice.meta.pendingBackups).toEqual([]);
  });

  it("fetches the backup once when a key is missing", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const m = await send(alice, CONV, "alt", "m0");
    await alice.mls.flushBackups();
    const laptop = device("alice", DEV.a2);
    expect(await laptop.mls.decrypt(CONV, m)).toMatchObject({ ok: true, content: { body: "alt" } });
  });

  it("detects replays, tampering, wrong envelopes and unknown devices", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    const m = await send(alice, CONV, "einmal", "m1");
    expect(await bob.mls.decrypt(CONV, m)).toMatchObject({ ok: true });
    expect(await bob.mls.decrypt(CONV, { ...m, id: "m2" })).toEqual({ ok: false, reason: "replay" });
    expect(await bob.mls.decrypt(CONV, { ...m, epoch: 0, id: "m3" })).toEqual({ ok: false, reason: "invalid" });
    const bytes = b64urlDecode(m.content);
    bytes[bytes.length - 1]! ^= 1;
    expect(await bob.mls.decrypt(CONV, { ...m, id: "m4", content: b64urlEncode(bytes) })).toEqual({ ok: false, reason: "invalid" });
    // Moved to another author: the AAD does not match.
    expect(await bob.mls.decrypt(CONV, { ...m, id: "m5", author: bob.address, device_id: DEV.b })).toEqual({ ok: false, reason: "invalid" });
    // A device the home node never attested (and has no retired attestation for) is unknown.
    expect(await bob.mls.decrypt(CONV, { ...m, id: "m6", device_id: DEV.a2 })).toEqual({ ok: false, reason: "unknown_device" });
    expect(await bob.mls.decrypt(CONV, { ...m, id: "m7", content: { type: "text" } })).toEqual({ ok: false, reason: "invalid" });
    // An attestation the node lies about is not accepted.
    node.users.get("alice")!.devices.get(DEV.a)!.sig = b64urlEncode(new Uint8Array(64));
    const dave = device("dave", DEV.c);
    expect(await dave.mls.decrypt(CONV, { ...m, id: "m8" })).toEqual({ ok: false, reason: "unknown_device" });
    expect(contentHeader("***")).toBeNull();
  });

  it("flags ghost devices: non-members, forged attestations and duplicates", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const mallory = device("mallory", DEV.d, { forgedAttestation: true });
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await mallory.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, bob, mallory))).toEqual([{ identity: `${mallory.address}/${DEV.d}`, reason: "unattested" }]);
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, mallory))).toEqual([
      { identity: `${bob.address}/${DEV.b}`, reason: "not_member" },
      { identity: `${mallory.address}/${DEV.d}`, reason: "unattested" },
    ]);
  });

  it("flags an identity that appears twice in the roster", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    // A second leaf claiming Bob's device identity with another key (a misbehaving member adds it).
    const twin = Client.create(bob.address, DEV.b);
    const kps = [b64urlDecode(node.users.get("bob")!.kps.get(DEV.b)![0]!), twin.createKeyPackage()];
    const out = alice.client().addMembers(CONV, kps);
    await node.ds(alice.address, DEV.a).postCommit(ID, { epoch: out.epoch, commit: b64urlEncode(out.commit), group_info: b64urlEncode(out.groupInfo), welcome: null });
    alice.client().mergePendingCommit(CONV);
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, bob))).toEqual([{ identity: `${bob.address}/${DEV.b}`, reason: "duplicate" }]);
    twin.free();
  });

  it("pins identity keys on first use and reports a changed key until acknowledged", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await bob.mls.verifiedDevices(alice.address);
    expect(bob.pins[alice.address]).toEqual({ key: node.users.get("alice")!.identity });
    // Alice resets her identity (§9) and re-attests her device.
    const fresh = MasterSecret.generate();
    const rec = node.users.get("alice")!;
    rec.identity = b64urlEncode(fresh.identityPublicKey());
    const dev = rec.devices.get(DEV.a)!;
    dev.sig = b64urlEncode(fresh.attestDevice(alice.address, DEV.a, b64urlDecode(dev.pk)));
    bob.mls.identityChanged(alice.address);
    const devices = await bob.mls.verifiedDevices(alice.address);
    expect(devices?.has(DEV.a)).toBe(true);
    expect(bob.events).toContainEqual({ type: "key_changed", address: alice.address });
    expect(bob.mls.changedKeys()).toEqual([alice.address]);
    await bob.mls.acknowledgeKeyChange(alice.address);
    expect(bob.mls.changedKeys()).toEqual([]);
    // Unknown users (of any node) have no devices; malformed addresses none either.
    await expect(bob.mls.verifiedDevices("eve@other.example")).rejects.toMatchObject({ code: "user.not_found" });
    expect(await bob.mls.verifiedDevices("no-domain")).toBeNull();
  });

  it("pins a key rotated with a valid continuity statement softly; verified contacts need a refresh (§9a)", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await bob.mls.verifiedDevices(alice.address);
    expect(await bob.mls.markVerified(alice.address, "numeric")).toBe(true);
    expect(bob.mls.verification(alice.address)).toBe("verified");
    // Alice rotates: statement signed by both keys, her device re-attested by the new key; a device deleted before
    // keeps its attestation under the old key.
    const rec = node.users.get("alice")!;
    const old = IdentityKey.fromMaster(masters.get(alice.address)!);
    const k1 = IdentityKey.generate();
    const pk = (k: IdentityKey) => b64urlEncode(k.publicKey());
    const retiredClient = Client.create(alice.address, DEV.a2);
    rec.retired = new Map([[DEV.a2, { pk: b64urlEncode(retiredClient.devicePublicKey), sig: b64urlEncode(old.attestDevice(alice.address, DEV.a2, retiredClient.devicePublicKey)), deletedAt: new Date().toISOString(), under: pk(old) }]]);
    rec.continuity = [JSON.parse(signContinuity(old, k1, "2026-10-06T12:00:00Z"))];
    rec.identity = pk(k1);
    const dev = rec.devices.get(DEV.a)!;
    dev.sig = b64urlEncode(k1.attestDevice(alice.address, DEV.a, b64urlDecode(dev.pk)));
    bob.mls.identityChanged(alice.address);
    expect((await bob.mls.verifiedDevices(alice.address))?.has(DEV.a)).toBe(true);
    expect(bob.events).toContainEqual({ type: "key_rotated", address: alice.address });
    expect(bob.events.some((e) => e.type === "key_changed")).toBe(false);
    expect(bob.pins[alice.address]).toEqual({ key: pk(k1), rotated: true });
    expect([bob.mls.changedKeys(), bob.mls.rotatedKeys()]).toEqual([[], [alice.address]]);
    expect(bob.mls.retiredDevice(alice.address, DEV.a2)).toBeDefined();
    // Verified → "needs a refresh": not blocking, dismissable, the safety number verifies again.
    expect(bob.mls.verification(alice.address)).toBe("refresh");
    expect(bob.mls.verificationStates()).toEqual({ [alice.address]: "refresh" });
    await bob.mls.dismissVerificationRefresh(alice.address);
    expect(bob.mls.verificationStates()).toEqual({});
    await bob.mls.acknowledgeKeyChange(alice.address);
    expect(bob.mls.rotatedKeys()).toEqual([]);
    await bob.mls.markVerified(alice.address, "qr");
    expect(bob.mls.verificationStates()).toEqual({ [alice.address]: "verified" });

    // A "rotation" whose statement the pinned key did not sign is a plain change: the blocking warning.
    const mallory = IdentityKey.generate();
    const k2 = IdentityKey.generate();
    rec.continuity.push(JSON.parse(signContinuity(mallory, k2, "2026-10-06T13:00:00Z")));
    rec.identity = pk(k2);
    dev.sig = b64urlEncode(k2.attestDevice(alice.address, DEV.a, b64urlDecode(dev.pk)));
    bob.mls.identityChanged(alice.address);
    await bob.mls.verifiedDevices(alice.address);
    expect(bob.events).toContainEqual({ type: "key_changed", address: alice.address });
    expect(bob.mls.changedKeys()).toEqual([alice.address]);
    expect(bob.mls.verification(alice.address)).toBe("broken");
    expect(bob.mls.retiredDevice(alice.address, DEV.a2)).toBeUndefined();
    [old, k1, k2, mallory].forEach((k) => k.free());
    retiredClient.free();
  });

  it("signs plaintext messages and verifies them against the author's attested devices", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const content = { type: "text", body: "Klartext", gif: { url: "https://media.giphy.com/x.gif", width: 1, height: 2 } };
    const fields = { reply_to: null, thread_id: null, mentions_everyone: false, mentions: [bob.address], attachments: [{ id: "01J9ZK3G5M8Q2W4E6R8T0Y2V09", size: 3, sha256: "abc" }] };
    const signature = alice.mls.signPlaintext(CONV, fields, content);
    expect(signature).toHaveLength(107);
    const envelope = { id: "p1", author: alice.address, device_id: DEV.a, reply_to_id: null, thread_id: null, mentions: [bob.address], mentions_everyone: false, attachments: fields.attachments, content: { gif: content.gif, body: content.body, type: "text" }, signature };
    expect(await bob.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    // Own messages verify against the own identity key.
    expect(await alice.mls.verifyPlaintext(CONV, envelope)).toBe("valid");
    // A node that changes content or covered fields, or moves the message, is caught.
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p2", content: { ...envelope.content, body: "gefälscht" } })).toBe("invalid");
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p3", mentions: [] })).toBe("invalid");
    expect(await bob.mls.verifyPlaintext(CONV2, { ...envelope, id: "p4" })).toBe("invalid");
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p5", author: bob.address, device_id: DEV.b })).toBe("invalid");
    // The same signature on another message is a replay; malformed signatures are invalid.
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p6" })).toBe("replay");
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p7", signature: "abc" })).toBe("invalid");
    // Unsigned (older clients, bots) and unknown devices are only "unverified".
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p8", signature: null })).toBe("unsigned");
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p9", device_id: DEV.a2 })).toBe("unverifiable");
    expect(await bob.mls.verifyPlaintext(CONV, { ...envelope, id: "p10", author: "eve@other.example" })).toBe("unverifiable");
    // An edit is signed anew (fresh nonce) and verifies for the same message id.
    const edited = { ...envelope, content: { type: "text", body: "bearbeitet" } };
    edited.signature = alice.mls.signPlaintext(CONV, fields, edited.content);
    expect(await bob.mls.verifyPlaintext(CONV, edited)).toBe("valid");
    // Content that has no JSON form cannot be signed (the message goes out unsigned).
    expect(alice.mls.signPlaintext(CONV, fields, { type: "text", body: "x", n: Number.NaN })).toBeNull();
  });

  it("verifies contacts by safety number and breaks the verification when the key changes", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const a = await alice.mls.safetyNumber(bob.address);
    const b = await bob.mls.safetyNumber(alice.address);
    expect(a?.number).toMatch(/^\d{60}$/);
    expect(a).toEqual(b);
    expect(await alice.mls.safetyNumber(alice.address)).toBeNull();
    expect(await alice.mls.safetyNumber("eve@other.example")).toBeNull();
    // Bob's payload (scanned or pasted) matches on Alice's side, a payload of someone else does not.
    expect(alice.mls.comparePayload(bob.address, b!.payload)).toBe(true);
    expect(alice.mls.comparePayload(bob.address, b!.payload.replace("v=1", "v=2"))).toBe(false);
    const carol = device("carol", DEV.c);
    const c = await carol.mls.safetyNumber(bob.address);
    expect(alice.mls.comparePayload(bob.address, c!.payload)).toBe(false);

    expect(alice.mls.verification(bob.address)).toBe("unverified");
    expect(await alice.mls.markVerified(bob.address, "qr")).toBe(true);
    expect(alice.mls.verification(bob.address)).toBe("verified");
    expect(alice.mls.verifiedContact(bob.address)).toMatchObject({ address: bob.address, method: "qr", identity_public_key: node.users.get("bob")!.identity });
    expect(alice.events).toContainEqual({ type: "verification", address: bob.address });
    expect(await alice.mls.markVerified("eve@other.example", "numeric")).toBe(false);

    // Bob resets his identity: the verification is broken until Alice verifies again or accepts.
    const resetBob = () => {
      const fresh = MasterSecret.generate();
      const rec = node.users.get("bob")!;
      rec.identity = b64urlEncode(fresh.identityPublicKey());
      const dev = rec.devices.get(DEV.b)!;
      dev.sig = b64urlEncode(fresh.attestDevice(bob.address, DEV.b, b64urlDecode(dev.pk)));
      alice.mls.identityChanged(bob.address);
    };
    resetBob();
    await alice.mls.verifiedDevices(bob.address);
    expect(alice.mls.verification(bob.address)).toBe("broken");
    expect(alice.mls.verificationStates()).toEqual({ [bob.address]: "broken" });
    expect(alice.mls.changedKeys()).toEqual([bob.address]);
    // Verifying again stores the new key and acknowledges the change.
    expect(await alice.mls.markVerified(bob.address, "numeric")).toBe(true);
    expect(alice.mls.verification(bob.address)).toBe("verified");
    expect(alice.mls.changedKeys()).toEqual([]);
    // Another reset; this time Alice accepts the new key without verification.
    resetBob();
    await alice.mls.verifiedDevices(bob.address);
    expect(alice.mls.verification(bob.address)).toBe("broken");
    await alice.mls.acceptNewKey(bob.address);
    expect(alice.mls.verification(bob.address)).toBe("unverified");
    expect(alice.mls.changedKeys()).toEqual([]);
    expect(alice.mls.verificationStates()).toEqual({});
    await alice.mls.markVerified(bob.address, "qr");
    await alice.mls.removeVerification(bob.address);
    expect(alice.mls.verification(bob.address)).toBe("unverified");
  });

  it("does not create a group twice when another device was first", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    // Bob's view of the node: no group yet, but Alice creates it before Bob's upload arrives.
    const bobApi = (bob.mls as unknown as { deps: { api: MlsApi } }).deps.api;
    const bobDs = bobApi.node(DOMAIN);
    let first = true;
    bobApi.node = () => ({
      ...bobDs,
      groupInfo: async (c: string) => {
        if (first) {
          first = false;
          await alice.mls.ensureJoined(CONV, { canCreate: true });
          throw problem(404, "mls.no_group");
        }
        return bobDs.groupInfo(c);
      },
    });
    expect(await bob.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    expect(node.groups.get(ID)!.epoch).toBe(1);
    await alice.mls.catchUp(CONV);
    const m = await send(alice, CONV, "eine Gruppe", "m1");
    expect(await bob.mls.decrypt(CONV, m)).toMatchObject({ ok: true });
    // Bob kept no stray key for epoch 0 of a group that never existed.
    expect(Array.from(bob.client().knownEpochs(CONV))).toEqual([1]);
  });

  it("cleans up the leaf of an own deleted device with the leaf cleaner (ENCRYPTION.md §4.7)", async () => {
    const { net, device } = setup();
    const alice = device("alice", DEV.a);
    const phone = device("alice", DEV.a2);
    const bob = device("bob", DEV.b);
    for (const d of [alice, phone, bob]) await d.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    await phone.mls.catchUp(CONV);
    // The phone was deleted in the settings: its home node no longer lists it.
    net.node(DOMAIN).users.get("alice")!.devices.delete(DEV.a2);
    alice.mls.forgetDevices(alice.address);
    const ghost = `${alice.address}/${DEV.a2}`;
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, bob))).toEqual([{ identity: ghost, reason: "unattested" }]);
    const cleaner = new LeafCleaner({ mls: alice.mls, sleep: async () => undefined });
    const r = await cleaner.clean({ q: CONV, members: memberSet(alice, bob), mayManage: false, pending: [{ identity: ghost, reason: "deleted" }] });
    expect(r).toEqual({ outcome: "removed", removed: [ghost], ghosts: [] });
    expect(alice.mls.roster(CONV)).not.toContain(ghost);
    await bob.mls.catchUp(CONV);
    expect(await bob.mls.ghostCheck(CONV, memberSet(alice, bob))).toEqual([]);
  });

  it("treats a bot leaf in a \"no bots\" conversation as a ghost, with kind from the bot's home node (APPLICATIONS.md §3.5)", async () => {
    const { net, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const bot = device("weatherbot", DEV.c, { kind: "bot" });
    for (const d of [alice, bob, bot]) await d.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    const members = memberSet(alice, bob, bot);
    const botLeaf = `${bot.address}/${DEV.c}`;
    // Without the flag a bot is a member like any other.
    expect(await alice.mls.ghostCheck(CONV, members)).toEqual([]);
    // With the flag it is a ghost even though the node lists it as a member; users are not affected.
    expect(await alice.mls.ghostCheck(CONV, members, { noBots: true })).toEqual([{ identity: botLeaf, reason: "bot" }]);
    // A kind this client does not know counts like a bot (§1.5).
    net.node(DOMAIN).users.get("bob")!.kind = "robot";
    alice.mls.forgetDevices(bob.address);
    expect(await alice.mls.ghostCheck(CONV, members, { noBots: true })).toEqual([
      { identity: `${bob.address}/${DEV.b}`, reason: "bot" },
      { identity: botLeaf, reason: "bot" },
    ]);
    net.node(DOMAIN).users.get("bob")!.kind = "user";
    alice.mls.forgetDevices(bob.address);

    // Removal follows rule 3 of §4.7: only members who may manage the conversation commit it.
    const cleaner = new LeafCleaner({ mls: alice.mls, sleep: async () => undefined });
    const refused = await cleaner.clean({ q: CONV, members, mayManage: false, noBots: true });
    expect(refused).toEqual({ outcome: "not_allowed", removed: [], ghosts: [{ identity: botLeaf, reason: "bot" }] });
    expect(alice.mls.roster(CONV)).toContain(botLeaf);
    // Without the flag the cleaner leaves the bot alone.
    expect((await cleaner.clean({ q: CONV, members, mayManage: true })).outcome).toBe("clean");
    const removed = await cleaner.clean({ q: CONV, members, mayManage: true, noBots: true });
    expect(removed).toEqual({ outcome: "removed", removed: [botLeaf], ghosts: [] });
    expect(alice.mls.roster(CONV)).not.toContain(botLeaf);
    await bob.mls.catchUp(CONV);
    expect(await bob.mls.ghostCheck(CONV, memberSet(alice, bob), { noBots: true })).toEqual([]);
  });

  it("reads the history of a deleted device with its retired attestation, only from before the deletion (§5.2)", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const phone = device("alice", DEV.a2);
    const bob = device("bob", DEV.b);
    for (const d of [alice, phone, bob]) await d.mls.ensureJoined(CONV, { canCreate: true });
    await phone.mls.catchUp(CONV);
    const m = { ...(await send(phone, CONV, "vom Handy", "m1")), created_at: "2026-10-05T10:00:00.000Z" };
    await bob.mls.catchUp(CONV);
    // The phone is deleted: no longer active, but retired with its attestation.
    const record = node.users.get("alice")!;
    const att = record.devices.get(DEV.a2)!;
    record.devices.delete(DEV.a2);
    record.retired = new Map([[DEV.a2, { ...att, deletedAt: "2026-10-05T12:00:00.000Z" }]]);
    bob.mls.forgetDevices(alice.address);
    expect(await bob.mls.decrypt(CONV, m)).toEqual({ ok: true, content: { type: "text", body: "vom Handy" }, retired: true });
    // Sent after the deletion (beyond the 5 minutes of slack): refused.
    const late = { ...m, id: "m2", created_at: "2026-10-05T12:06:00.000Z" };
    expect(await bob.mls.decrypt(CONV, late)).toEqual({ ok: false, reason: "unknown_device" });
    const slack = { ...m, id: "m3", created_at: "2026-10-05T12:04:00.000Z" };
    expect((await device("carol", DEV.c).mls.decrypt(CONV, slack)).ok).toBe(false); // carol is no member (no key)
    // Without a time (ephemeral events) a retired device never counts.
    const eph = await phone.mls.encryptEphemeral(CONV, { type: "cursor" });
    expect(await bob.mls.decryptEphemeral(CONV, alice.address, DEV.a2, eph)).toEqual({ ok: false, reason: "unknown_device" });
    // A retired attestation the node forged is not accepted.
    record.retired = new Map([[DEV.a2, { ...att, sig: b64urlEncode(new Uint8Array(64)), deletedAt: "2026-10-05T12:00:00.000Z" }]]);
    const dave = device("dave", DEV.d);
    expect(await dave.mls.decrypt(CONV, { ...m, id: "m4" })).toMatchObject({ ok: false });
    bob.mls.forgetDevices(alice.address);
    expect(await bob.mls.decrypt(CONV, { ...m, id: "m5" })).toEqual({ ok: false, reason: "unknown_device" });
  });
});

describe("MlsManager across nodes (FEDERATION.md §3.5, §3.6, §6)", () => {
  it("joins a channel hosted on another node there, and verifies authors with keys of their home nodes", async () => {
    const { net, device } = setup();
    const bob = device(`bob@${B}`, DEV.b);
    const alice = device(`alice@${A}`, DEV.a);
    const channel = qualify(B, ID);
    expect(await bob.mls.ensureJoined(channel, { canCreate: true })).toBe("joined");
    // Alice (home a.test) joins the group on b.test by external commit with her session there.
    expect(await alice.mls.ensureJoined(channel, { canCreate: true })).toBe("joined");
    expect(net.node(B).groups.get(ID)!.epoch).toBe(1);
    expect(net.node(A).groups.size).toBe(0);
    await bob.mls.catchUp(channel);
    const m1 = await send(alice, channel, "Grüße von A", "m1");
    expect(await bob.mls.decrypt(channel, m1)).toEqual({ ok: true, content: { type: "text", body: "Grüße von A" } });
    const m2 = await send(bob, channel, "Grüße von B", "m2");
    expect(await alice.mls.decrypt(channel, m2)).toMatchObject({ ok: true, content: { body: "Grüße von B" } });
    expect(await bob.mls.ghostCheck(channel, [alice.address, bob.address])).toEqual([]);
    // Keys always came from the users' home nodes; nothing was asked of the hosting node.
    expect(net.keyLookups).toContain(`${alice.address}→${A}`);
    expect(net.keyLookups).toContain(`${bob.address}→${B}`);
    expect(net.keyLookups.every((l) => l.split("→")[0]!.endsWith(`@${l.split("→")[1]}`))).toBe(true);
    // The same ULID on another node is another group.
    expect(alice.mls.hasGroup(qualify(A, ID))).toBe(false);
  });

  it("DM hosted on the initiator's node: KeyPackages of the other node's user via the claim proxy, Welcome on the hosting node", async () => {
    const { net, device } = setup();
    const alice = device(`alice@${A}`, DEV.a);
    const bob = device(`bob@${B}`, DEV.b);
    const dm = qualify(A, ID);
    await alice.mls.ensureJoined(dm, { canCreate: true });
    const kpsBefore = net.node(B).users.get("bob")!.kps.get(DEV.b)!.length;
    expect(await alice.mls.addMissingDevices(dm, [alice.address, bob.address])).toEqual([]);
    expect(net.node(A).proxied).toEqual([bob.address]);
    expect(net.node(B).users.get("bob")!.kps.get(DEV.b)!.length).toBe(kpsBefore - 1);
    const m1 = await send(alice, dm, "Hallo Bob", "m1");
    // The Welcome waits on a.test; Bob's own node has none.
    expect(await bob.mls.processWelcomes(B)).toEqual([]);
    expect(await bob.mls.processWelcomes(A)).toEqual([dm]);
    expect(await bob.mls.decrypt(dm, m1)).toMatchObject({ ok: true, content: { body: "Hallo Bob" } });
    const m2 = await send(bob, dm, "Hallo Alice", "m2");
    expect(await alice.mls.decrypt(dm, m2)).toMatchObject({ ok: true, content: { body: "Hallo Alice" } });
    // ensureJoined of a DM looks for Welcomes on the hosting node.
    const laptop = device(`bob@${B}`, DEV.b.replace("B1", "B2"));
    alice.mls.forgetDevices(bob.address);
    await alice.mls.addMissingDevices(dm, [bob.address]);
    expect(await laptop.mls.ensureJoined(dm, { canCreate: false })).toBe("joined");
  });

  it("refuses a Welcome that another node delivers for a conversation it does not host", async () => {
    const { net, device } = setup();
    const alice = device(`alice@${A}`, DEV.a);
    const bob = device(`bob@${B}`, DEV.b);
    const dm = qualify(A, ID);
    await alice.mls.ensureJoined(dm, { canCreate: true });
    await alice.mls.addMissingDevices(dm, [bob.address]);
    // b.test copies the Welcome of a.test's conversation into its own delivery service.
    const key = `${bob.address}/${DEV.b}`;
    net.node(B).welcomes.set(key, [...net.node(A).welcomes.get(key)!]);
    expect(await bob.mls.processWelcomes(B)).toEqual([]);
    expect(bob.mls.hasGroup(dm)).toBe(false);
    expect(bob.mls.hasGroup(qualify(B, ID))).toBe(false);
    // The genuine one on a.test still works.
    expect(await bob.mls.processWelcomes(A)).toEqual([dm]);
  });

  it("group DM with members of two nodes: everyone reads everyone", async () => {
    const { device } = setup();
    const alice = device(`alice@${A}`, DEV.a);
    const carol = device(`carol@${A}`, DEV.c);
    const bob = device(`bob@${B}`, DEV.b);
    const group = qualify(A, ID2);
    await alice.mls.ensureJoined(group, { canCreate: true });
    await alice.mls.addMissingDevices(group, [alice.address, bob.address, carol.address]);
    expect(await bob.mls.processWelcomes(A)).toEqual([group]);
    expect(await carol.mls.processWelcomes(A)).toEqual([group]);
    const m = await send(bob, group, "Hallo Gruppe", "m1");
    await alice.mls.catchUp(group);
    await carol.mls.catchUp(group);
    expect(await alice.mls.decrypt(group, m)).toMatchObject({ ok: true });
    expect(await carol.mls.decrypt(group, m)).toMatchObject({ ok: true });
    expect(await carol.mls.ghostCheck(group, [alice.address, bob.address, carol.address])).toEqual([]);
  });

  it("a forged attestation of a remote user is caught: the home node's key decides", async () => {
    const { net, device } = setup();
    const bob = device(`bob@${B}`, DEV.b);
    const mallory = device(`mallory@${A}`, DEV.d, { forgedAttestation: true });
    const channel = qualify(B, ID);
    await bob.mls.ensureJoined(channel, { canCreate: true });
    await mallory.mls.ensureJoined(channel, { canCreate: true });
    await bob.mls.catchUp(channel);
    expect(await bob.mls.ghostCheck(channel, [bob.address, mallory.address])).toEqual([{ identity: `${mallory.address}/${DEV.d}`, reason: "unattested" }]);
    const m = await send(mallory, channel, "vertrau mir", "m1");
    expect(await bob.mls.decrypt(channel, m)).toEqual({ ok: false, reason: "unknown_device" });
    expect(net.keyLookups).toContain(`${mallory.address}→${A}`);
  });

  it("backs up keys of a remote conversation on the home node and restores them on a new device", async () => {
    const { net, device } = setup();
    const bob = device(`bob@${B}`, DEV.b);
    const alice = device(`alice@${A}`, DEV.a);
    const channel = qualify(B, ID);
    await bob.mls.ensureJoined(channel, { canCreate: true });
    await alice.mls.ensureJoined(channel, { canCreate: true });
    const m = await send(alice, channel, "für später", "m1");
    await alice.mls.flushBackups();
    expect([...net.node(A).backups.keys()]).toEqual([`${alice.address}|${channel}`]);
    expect(net.node(B).backups.size).toBe(0);
    const fresh = device(`alice@${A}`, DEV.a2);
    expect(await fresh.mls.restoreBackups()).toBe(1);
    expect(await fresh.mls.decrypt(channel, m)).toMatchObject({ ok: true, content: { body: "für später" } });
  });

  it("removes leaves of a departed remote member through the hosting node", async () => {
    const { net, device } = setup();
    const alice = device(`alice@${A}`, DEV.a);
    const bob = device(`bob@${B}`, DEV.b);
    const group = qualify(A, ID);
    await alice.mls.ensureJoined(group, { canCreate: true });
    await alice.mls.addMissingDevices(group, [bob.address]);
    await bob.mls.processWelcomes(A);
    expect(await alice.mls.removeLeaves(group, [`${bob.address}/${DEV.b}`])).toBe(true);
    expect(net.node(A).groups.get(ID)!.epoch).toBe(2);
    await bob.mls.catchUp(group);
    expect(bob.mls.hasGroup(group)).toBe(false);
  });
});

describe("threads (PROTOCOL.md §7e)", () => {
  it("thread messages and titles use the channel's group: no new group, no new keys", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    const groups = node.groups.size;
    const epoch = node.groups.get(ID)!.epoch;
    // A thread reply is an ordinary message of the channel (the envelope's thread_id is not part of the encryption).
    const reply = { ...(await send(bob, CONV, "in the thread", "t1")), thread_id: "01J9ZK3G5M8Q2W4E6R8T0Y2VT1" };
    expect(await alice.mls.decrypt(CONV, reply)).toEqual({ ok: true, content: { type: "text", body: "in the thread" } });
    const title = await alice.mls.encryptThreadTitle(CONV, "  Release plan ");
    expect(title.title_epoch).toBe(alice.mls.epoch(CONV));
    const thread = { id: "01J9ZK3G5M8Q2W4E6R8T0Y2VT1", title: title.title, title_epoch: title.title_epoch, title_author: alice.address, title_device_id: DEV.a };
    expect(await bob.mls.decryptThreadTitle(CONV, thread)).toEqual({ ok: true, title: "Release plan" });
    expect(node.groups.size).toBe(groups);
    expect(node.groups.get(ID)!.epoch).toBe(epoch);
  });

  it("refuses message content as a title, replays, wrong authors and overlong titles", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    const message = await send(alice, CONV, "not a title", "m1");
    const asTitle = { id: "T1", title: message.content, title_epoch: message.epoch, title_author: alice.address, title_device_id: DEV.a };
    expect(await bob.mls.decryptThreadTitle(CONV, asTitle)).toEqual({ ok: false, reason: "invalid" });
    const t = await alice.mls.encryptThreadTitle(CONV, "Plans");
    const thread = { id: "T2", title: t.title, title_epoch: t.title_epoch, title_author: alice.address, title_device_id: DEV.a };
    expect((await bob.mls.decryptThreadTitle(CONV, thread)).ok).toBe(true);
    expect(await bob.mls.decryptThreadTitle(CONV, { ...thread, id: "T3" })).toEqual({ ok: false, reason: "replay" });
    expect((await bob.mls.decryptThreadTitle(CONV, { ...thread, id: "T4", title_author: bob.address, title_device_id: DEV.b })).ok).toBe(false);
    await expect(alice.mls.encryptThreadTitle(CONV, "x".repeat(101))).rejects.toThrow(RangeError);
    await expect(alice.mls.encryptThreadTitle(CONV, "   ")).rejects.toThrow(RangeError);
  });
});

describe("content of one purpose is never accepted for another (ENCRYPTION.md §5.2, §7b)", () => {
  it("a thread title or a history share served as a message or an ephemeral event is invalid", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    // A thread title has the same format and AAD as a message of its author: a node could post it as a message.
    const t = await alice.mls.encryptThreadTitle(CONV, "Plans");
    expect(await bob.mls.decrypt(CONV, { id: "m-title", author: alice.address, device_id: DEV.a, epoch: t.title_epoch, content: t.title })).toEqual({ ok: false, reason: "invalid" });
    // A history share (keys of past epochs for another member) must never become message content either.
    const share = await alice.mls.encryptHistory(CONV, JSON.stringify({ type: "history_keys", v: 1, conversation: CONV, to: "carol@t.local", epochs: [[0, b64urlEncode(new Uint8Array(32))]] }));
    expect(await bob.mls.decrypt(CONV, { id: "m-share", author: alice.address, device_id: DEV.a, epoch: share.epoch, content: share.content })).toEqual({ ok: false, reason: "invalid" });
    expect(await bob.mls.decryptEphemeral(CONV, alice.address, DEV.a, share.content)).toEqual({ ok: false, reason: "invalid" });
    // The genuine paths still work.
    expect((await bob.mls.decryptThreadTitle(CONV, { id: "T9", title: t.title, title_epoch: t.title_epoch, title_author: alice.address, title_device_id: DEV.a })).ok).toBe(true);
    expect((await bob.mls.decryptHistory(CONV, "S1", alice.address, DEV.a, share.content)).ok).toBe(true);
    const m = await send(alice, CONV, "hello", "m-ok");
    expect((await bob.mls.decrypt(CONV, m)).ok).toBe(true);
  });
});

describe("signed context of messages (ENCRYPTION.md §5.2)", () => {
  const T1 = "01J9ZK3G5M8Q2W4E6R8T0Y2VT1";
  const T2 = "01J9ZK3G5M8Q2W4E6R8T0Y2VT2";
  const R1 = "01J9ZK3G5M8Q2W4E6R8T0Y2VR1";

  async function pair() {
    const { device, node } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    return { alice, bob, node };
  }

  it("a reply moved into another thread by the node is not shown as part of it", async () => {
    const { alice, bob } = await pair();
    const sealed = await bob.mls.encrypt(CONV, { type: "text", body: "only for thread 1" }, { ctx: { thread_id: T1, reply_to: null } });
    const reply = { id: "t1", author: bob.address, device_id: DEV.b, ...sealed, thread_id: T1, reply_to_id: null };
    // Shown where it was sent, without the context in the content.
    expect(await alice.mls.decrypt(CONV, reply)).toEqual({ ok: true, content: { type: "text", body: "only for thread 1" } });
    // The node serves the same message (same id) under another thread, in the main channel or as a reply.
    expect(await alice.mls.decrypt(CONV, { ...reply, thread_id: T2 })).toEqual({ ok: false, reason: "envelope_mismatch" });
    expect(await alice.mls.decrypt(CONV, { ...reply, thread_id: null })).toEqual({ ok: false, reason: "envelope_mismatch" });
    expect(await alice.mls.decrypt(CONV, { ...reply, reply_to_id: R1 })).toEqual({ ok: false, reason: "envelope_mismatch" });
    // A caller that does not know the envelope fields (undefined) does not compare them.
    const { thread_id: _t, reply_to_id: _r, ...bare } = reply;
    expect((await alice.mls.decrypt(CONV, bare)).ok).toBe(true);
    // The genuine envelope still decrypts after the mismatches (no replay, no cached failure).
    expect((await alice.mls.decrypt(CONV, reply)).ok).toBe(true);
    expect(alice.mls.peek(CONV, reply)).toEqual({ ok: true, content: { type: "text", body: "only for thread 1" } });
  });

  it("a reply keeps its target; content of older clients without ctx is accepted anywhere", async () => {
    const { alice, bob } = await pair();
    const sealed = await bob.mls.encrypt(CONV, { type: "text", body: "answer" }, { ctx: { thread_id: null, reply_to: R1 } });
    const m = { id: "r1", author: bob.address, device_id: DEV.b, ...sealed, thread_id: null, reply_to_id: R1 };
    expect((await alice.mls.decrypt(CONV, m)).ok).toBe(true);
    expect(await alice.mls.decrypt(CONV, { ...m, reply_to_id: null })).toEqual({ ok: false, reason: "envelope_mismatch" });
    const old = await send(bob, CONV, "from an older client", "o1");
    expect(await alice.mls.decrypt(CONV, { ...old, thread_id: T2, reply_to_id: R1 })).toEqual({ ok: true, content: { type: "text", body: "from an older client" } });
  });

  it("a malformed context is a mismatch, never content", async () => {
    const { alice, bob } = await pair();
    for (const [i, ctx] of ([{ thread_id: 5, reply_to: null }, { thread_id: T1 }, { thread_id: T1, reply_to: null, extra: 1 }, "T1", null] as unknown[]).entries()) {
      const { content, epoch } = await bob.mls.encrypt(CONV, { type: "text", body: "x", ctx } as Record<string, unknown>);
      expect(await alice.mls.decrypt(CONV, { id: `bad${i}`, author: bob.address, device_id: DEV.b, epoch, content, thread_id: T1, reply_to_id: null }), JSON.stringify(ctx)).toEqual({ ok: false, reason: "envelope_mismatch" });
    }
  });
});

describe("changed identity keys hold back the new devices until acknowledged (ENCRYPTION.md §3.3, §4.6)", () => {
  /** Bob's home node swaps his identity key and publishes a device of its own (`DEV.d`). */
  function swapKey(env: ReturnType<typeof setup>, address: string) {
    const fake = MasterSecret.generate();
    env.masters.set(address, fake);
    env.node.users.get(address.split("@")[0]!)!.identity = b64urlEncode(fake.identityPublicKey());
    return env.device(address, DEV.d);
  }

  it("devices under an unacknowledged changed key are not added to a DM; acknowledging adds them", async () => {
    const env = setup();
    const alice = env.device("alice", DEV.a);
    const bob = env.device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    expect(await alice.mls.addMissingDevices(CONV, [alice.address, bob.address])).toEqual([]);
    expect(alice.mls.roster(CONV)).toContain(`${bob.address}/${DEV.b}`);
    swapKey(env, bob.address);
    alice.mls.identityChanged(bob.address);
    await alice.mls.addMissingDevices(CONV, [alice.address, bob.address]);
    expect(alice.mls.roster(CONV)).not.toContain(`${bob.address}/${DEV.d}`);
    expect(alice.mls.changedKeys()).toEqual([bob.address]);
    await alice.mls.acknowledgeKeyChange(bob.address);
    await alice.mls.addMissingDevices(CONV, [alice.address, bob.address]);
    expect(alice.mls.roster(CONV)).toContain(`${bob.address}/${DEV.d}`);
  });

  it("a leaf under an unacknowledged changed key is a ghost with the reason key_changed", async () => {
    const env = setup();
    const alice = env.device("alice", DEV.a);
    const bob = env.device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, bob))).toEqual([]);
    const ghost = swapKey(env, bob.address);
    await ghost.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    alice.mls.identityChanged(bob.address);
    const ghosts = await alice.mls.ghostCheck(CONV, memberSet(alice, bob));
    expect(ghosts).toContainEqual({ identity: `${bob.address}/${DEV.d}`, reason: "key_changed" });
    // Bob's old device is not attested under the new key either.
    expect(ghosts).toContainEqual({ identity: `${bob.address}/${DEV.b}`, reason: "unattested" });
    await alice.mls.acknowledgeKeyChange(bob.address);
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, bob))).toEqual([{ identity: `${bob.address}/${DEV.b}`, reason: "unattested" }]);
  });

  it("a rotation with a valid continuity statement is not held back", async () => {
    const env = setup();
    const alice = env.device("alice", DEV.a);
    const bob = env.device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.addMissingDevices(CONV, [alice.address, bob.address]);
    // First contact: pinned without a warning, so the device counts at once.
    expect(alice.mls.changedKeys()).toEqual([]);
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, bob))).toEqual([]);
  });
});

describe("encrypt() catches up first and refuses to send otherwise (ENCRYPTION.md §5.2)", () => {
  it("fails with catch_up_failed when the handshake log cannot be read, and sends on the retry", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.encrypt(CONV, { type: "text", body: "first" });
    node.failLog = 1;
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "second" })).rejects.toMatchObject({ name: "MlsError", code: "catch_up_failed" });
    expect((await alice.mls.encrypt(CONV, { type: "text", body: "second" })).epoch).toBe(alice.mls.epoch(CONV));
    node.failLog = 1;
    await expect(alice.mls.encryptHistory(CONV, "{}")).rejects.toMatchObject({ code: "catch_up_failed" });
  });

  it("checks the roster again after commits it processed: a new ghost stops the message", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const mallory = device("mallory", DEV.c);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, bob))).toEqual([]);
    // A device of a non-member joins while Alice types (the node let it in).
    await mallory.mls.ensureJoined(CONV, { canCreate: false });
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "secret" })).rejects.toMatchObject({ name: "MlsError", code: "ghost" });
    // A retry is refused as well until the violation was shown (a ghost check of the caller) or the caller names it.
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "secret" })).rejects.toMatchObject({ code: "ghost" });
    const guard = { members: memberSet(alice, bob), noBots: false };
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "secret" }, { ...guard, knownGhosts: [] })).rejects.toMatchObject({ code: "ghost" });
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "after the warning" }, { ...guard, knownGhosts: [`${mallory.address}/${DEV.c}`] })).resolves.toBeTruthy();
    // Shown by the caller's ghost check: known from then on, also after further commits.
    expect(await alice.mls.ghostCheck(CONV, memberSet(alice, bob))).toEqual([{ identity: `${mallory.address}/${DEV.c}`, reason: "not_member" }]);
    await bob.mls.selfUpdate(CONV);
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "after the warning" })).resolves.toBeTruthy();
  });
});

describe("qualified ids and stored meta data", () => {
  it("checks embeds: the sender refuses invalid ones, receivers drop invalid ones (APPLICATIONS.md §6.4)", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    expect(await alice.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    expect(await bob.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    await alice.mls.catchUp(CONV);
    const card = { title: "Build", color: 255, fields: [{ name: "Branch", value: "main" }] };
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "", embeds: [{ title: "x", url: "http://insecure.example" }] })).rejects.toMatchObject({ code: "message.embeds_invalid" });
    const good = await alice.mls.encrypt(CONV, { type: "text", body: "", embeds: [card] });
    const m1 = { id: "e1", author: alice.address, device_id: DEV.a, ...good };
    expect(await bob.mls.decrypt(CONV, m1)).toEqual({ ok: true, content: { type: "text", body: "", embeds: [card] } });
    // A member that bypasses the check: the receiver never sees the invalid embeds.
    const raw = alice.client().encryptContent(CONV, JSON.stringify({ type: "text", body: "hi", embeds: [{ title: 5 }] }));
    const m2 = { id: "e2", author: alice.address, device_id: DEV.a, epoch: alice.client().currentEpoch(CONV), content: raw };
    expect(await bob.mls.decrypt(CONV, m2)).toEqual({ ok: true, content: { type: "text", body: "hi" } });
  });

  it("carries command arguments for a bot member: decrypted, verified and checked (APPLICATIONS.md §5.8)", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bot = device("weatherbot", DEV.b);
    expect(await alice.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    expect(await bot.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    await alice.mls.catchUp(CONV);
    const ref = `${DOMAIN}/${ID}/${ID2}`;
    const sealed = await encryptCommandArgs(alice.mls, CONV, ref, { city: "Rome" });
    // What the bot receives in `command.invoke`: the opaque payload, the epoch and the invoker's device.
    const envelope = { id: "inv1", author: alice.address, device_id: DEV.a, epoch: sealed.epoch, content: sealed.args_ciphertext };
    const opened = await bot.mls.decrypt(CONV, envelope);
    expect(opened.ok).toBe(true);
    const verifier = new CommandArgsVerifier();
    const content = (opened as { content: Record<string, unknown> }).content;
    expect(verifier.check(content, ref)).toEqual({ ok: true, args: { city: "Rome" } });
    // A node that replays the payload, or moves it to another command, is caught.
    expect(verifier.check(content, ref)).toEqual({ ok: false, reason: "replay" });
    expect(new CommandArgsVerifier().check(content, `${DOMAIN}/${ID}/${ID}`)).toEqual({ ok: false, reason: "command" });
    // Arguments signed by another device than the one the node names are refused by the decryption.
    expect(await bot.mls.decrypt(CONV, { ...envelope, id: "inv2", device_id: DEV.a2 })).toMatchObject({ ok: false });
  });

  it("splits qualified ids and rejects malformed ones", () => {
    expect(splitQualified(qualify(B, ID))).toEqual({ domain: B, id: ID });
    for (const bad of [ID, `/${ID}`, `${B}/x`, `B.TEST/${ID}`, `b.test/${ID}/x`, `evil.example:8080/${ID}`]) {
      expect(() => splitQualified(bad)).toThrow(MlsError);
    }
  });

  it("rejects operations on malformed conversation ids", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    await expect(alice.mls.ensureJoined(ID, { canCreate: true })).rejects.toMatchObject({ code: "invalid_id" });
  });

  it("qualifies bare ids that older versions stored for the home node", () => {
    const meta = normalizeMeta({ convs: { [ID]: { rotatedAt: 5 }, [qualify(B, ID2)]: { rotatedAt: 7, rotate: true } }, pendingBackups: [ID, qualify(DOMAIN, ID)] }, DOMAIN);
    expect(meta).toEqual({ convs: { [qualify(DOMAIN, ID)]: { rotatedAt: 5 }, [qualify(B, ID2)]: { rotatedAt: 7, rotate: true } }, pendingBackups: [qualify(DOMAIN, ID)] });
  });
});

describe("voice frame keys (ENCRYPTION.md §5a)", () => {
  it("a self update starts a fresh epoch whose frame key both members derive alike", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    expect(alice.mls.voiceKey(CONV)).toBeNull();
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.catchUp(CONV);
    const before = alice.mls.voiceKey(CONV)!;
    expect(before.epoch).toBe(1);
    expect(before.key).toHaveLength(32);
    expect(await bob.mls.selfUpdate(CONV)).toBe(true);
    expect(node.groups.get(ID)!.epoch).toBe(2);
    await alice.mls.catchUp(CONV);
    const a = alice.mls.voiceKey(CONV)!;
    const b = bob.mls.voiceKey(CONV)!;
    expect(a.epoch).toBe(2);
    expect(b.epoch).toBe(2);
    expect(a.key).toEqual(b.key);
    expect(a.key).not.toEqual(before.key);
    // Without a group there is nothing to update.
    expect(await device("carol", DEV.c).mls.selfUpdate(CONV)).toBe(false);
  });
});

describe("write-only webhooks (APPLICATIONS.md §6.1a, ENCRYPTION.md §5b)", () => {
  /** A message as the node stores a sealed webhook post. */
  function sealedMessage(id: string, epoch: number, publicKey: string, payload: unknown, sealedBy = "sender") {
    const sealed = b64urlEncode(sealToInbox(b64urlDecode(publicKey), new TextEncoder().encode(JSON.stringify(payload))));
    return { id, author: `wh.x@${DOMAIN}`, device_id: null, epoch, content: { type: "webhook.sealed", epoch, sealed, sealed_by: sealedBy }, webhook: { id: "W", name: "CI" } };
  }

  it("publishes inbox keys only where wanted, after own commits; members open sealed posts, later members cannot", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    // A channel without webhooks costs nothing.
    expect(await alice.mls.selfUpdate(CONV)).toBe(true);
    expect(node.inboxPublications).toEqual([]);
    // Webhooks appear: the current key is published once, then after every own commit.
    alice.mls.setInboxWanted(CONV, true);
    alice.mls.setInboxWanted(CONV, true);
    await vi.waitFor(() => expect(node.inboxKeys.get(ID)?.epoch).toBe(1));
    expect(node.inboxPublications).toHaveLength(1);
    bob.mls.setInboxWanted(CONV, true);
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await vi.waitFor(() => expect(node.inboxKeys.get(ID)?.epoch).toBe(2));
    expect(node.inboxPublications.at(-1)!.by).toBe(`bob@${DOMAIN}/${DEV.b}`);
    await alice.mls.catchUp(CONV);
    // Every member derives the same pair: Alice publishing epoch 2 again is accepted as the same key.
    expect(await alice.mls.publishInboxKey(CONV)).toBe(true);
    expect(node.inboxKeys.get(ID)!.epoch).toBe(2);

    const key = node.inboxKeys.get(ID)!;
    const payload = { content: { type: "text", body: "Deployed", embeds: [{ title: "Build #1" }], attachments: [{ id: "x" }] }, username: "CI Bot" };
    const m = sealedMessage("m1", 2, key.public_key, payload, "node");
    const expected = { ok: true, content: { type: "text", body: "Deployed", embeds: [{ title: "Build #1" }] }, sealedBy: "node", webhookName: "CI Bot" };
    expect(await alice.mls.decrypt(CONV, m)).toEqual(expected);
    expect(await bob.mls.decrypt(CONV, m)).toEqual(expected);
    expect(alice.mls.peek(CONV, m)).toEqual(expected);

    // Wrong envelopes, broken boxes and payloads that are not webhook text are shown as such.
    expect(await bob.mls.decrypt(CONV, { ...m, id: "m2", epoch: 1 })).toEqual({ ok: false, reason: "invalid" });
    expect(await bob.mls.decrypt(CONV, { ...m, id: "m3", webhook: undefined })).toEqual({ ok: false, reason: "invalid" });
    const broken = { ...m, id: "m4", content: { ...m.content, sealed: m.content.sealed.slice(0, -4) + "AAAA" } };
    expect(await bob.mls.decrypt(CONV, broken)).toEqual({ ok: false, reason: "invalid" });
    expect(await bob.mls.decrypt(CONV, sealedMessage("m5", 2, key.public_key, { content: { type: "image", body: "x" } }))).toEqual({ ok: false, reason: "invalid" });
    const badName = await bob.mls.decrypt(CONV, sealedMessage("m6", 2, key.public_key, { content: { type: "text", body: "hi" }, username: "@everyone" }));
    expect(badName).toEqual({ ok: true, content: { type: "text", body: "hi" }, sealedBy: "sender" });

    // Carol joins later: the epoch 2 key is not hers, the message shows as undecryptable.
    const carol = device("carol", DEV.c);
    await carol.mls.ensureJoined(CONV, { canCreate: true });
    expect(await carol.mls.decrypt(CONV, m)).toEqual({ ok: false, reason: "missing_key" });
    // Without webhooks again, nothing is published after commits.
    alice.mls.setInboxWanted(CONV, false);
    await alice.mls.catchUp(CONV);
    const before = node.inboxPublications.length;
    expect(await alice.mls.selfUpdate(CONV)).toBe(true);
    expect(node.inboxPublications).toHaveLength(before);
  });

  it("reads sealed posts of earlier epochs from the history backup", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    alice.mls.setInboxWanted(CONV, true);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await vi.waitFor(() => expect(node.inboxKeys.get(ID)?.epoch).toBe(0));
    const m = sealedMessage("m1", 0, node.inboxKeys.get(ID)!.public_key, { content: { type: "text", body: "old" } });
    await alice.mls.flushBackups();
    const laptop = device("alice", DEV.a2);
    await laptop.mls.ensureJoined(CONV, { canCreate: true });
    expect(await laptop.mls.decrypt(CONV, m)).toEqual({ ok: true, content: { type: "text", body: "old" }, sealedBy: "sender" });
  });
});
