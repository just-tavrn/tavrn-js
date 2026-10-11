// SPDX-License-Identifier: MPL-2.0
// Leaves of the account's own devices and of claimed KeyPackages are vouched for only with evidence the client holds
// itself (ENCRYPTION.md §3.3, §4.7): a claimed KeyPackage must carry the attested key of its device, and the ghost
// cleanup attests a leaf key again as retired only when the account's own-devices record knows it. The session manager with the real WebAssembly crypto: several devices talk to in-memory nodes whose
// delivery services follow the node's rules for epochs, the handshake log, Welcomes and backups. Users
// live on different nodes (FEDERATION.md §3.5, §6): conversations are hosted by one node, keys come
// from each user's home node, KeyPackages of other nodes' users are claimed through the hosting node.
import { beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { MlsManager, keyPackageLeaf, qualify, type MlsEvent, type MlsMeta, type Pin } from "../src/mls";
import { Network, domainOf } from "./fake-node";
import { LeafCleaner } from "../src/cleanup";

const DOMAIN = "t.local";
const ID = "01J9ZK3G5M8Q2W4E6R8T0Y2V00";
/** The conversation of these tests (hosted on the users' home node). */
const CONV = qualify(DOMAIN, ID);
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




describe("claimed KeyPackages are held against the attested device before an Add (§3.3)", () => {
  it("reads the identity and signature key of a KeyPackage's leaf", () => {
    const c = Client.create(`alice@${DOMAIN}`, DEV.a);
    const leaf = keyPackageLeaf(c.createKeyPackage());
    expect(leaf?.identity).toBe(`alice@${DOMAIN}/${DEV.a}`);
    expect(b64urlEncode(leaf!.signatureKey)).toBe(b64urlEncode(c.devicePublicKey));
    expect(keyPackageLeaf(new Uint8Array([0, 1, 0, 5]))).toBeNull();
    c.free();
  });

  it("does not add a node-substituted KeyPackage under a verified device id", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    // The hosting node replaces Bob's KeyPackages: same identity bob@t.local/<DEV.b>, a device key of its own.
    const ghost = Client.create(bob.address, DEV.b);
    node.users.get("bob")!.kps.set(DEV.b, [b64urlEncode(ghost.createKeyPackage())]);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    expect(await alice.mls.addMissingDevices(CONV, [alice.address, bob.address])).toEqual([]);
    expect(alice.mls.roster(CONV)).toEqual([`${alice.address}/${DEV.a}`]);
    expect(node.welcomes.get(`${bob.address}/${DEV.b}`) ?? []).toEqual([]);
    // Bob's genuine KeyPackage is added on the next try.
    node.users.get("bob")!.kps.set(DEV.b, [b64urlEncode(bob.client().createKeyPackage())]);
    await alice.mls.addMissingDevices(CONV, [alice.address, bob.address]);
    const leaf = alice.mls.rosterEntries(CONV).find((e) => e.identity === `${bob.address}/${DEV.b}`)!;
    expect(b64urlEncode(leaf.key)).toBe(b64urlEncode(bob.client().devicePublicKey));
  });

  it("does not add a KeyPackage whose key is attested but whose leaf names another device", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    // Bob's key is (also) attested under a second device id; the node serves his DEV.b KeyPackage as that device's.
    const other = "01J9ZK3G5M8Q2W4E6R8T0Y2VB2";
    const record = node.users.get("bob")!;
    const pk = bob.client().devicePublicKey;
    record.devices.set(other, { pk: b64urlEncode(pk), sig: b64urlEncode(masters.get(bob.address)!.attestDevice(bob.address, other, pk)) });
    record.kps.set(other, [record.kps.get(DEV.b)![0]!]);
    record.kps.set(DEV.b, []);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.addMissingDevices(CONV, [alice.address, bob.address]);
    expect(alice.mls.roster(CONV)).toEqual([`${alice.address}/${DEV.a}`]);
  });

  it("does not add a KeyPackage of another identity labelled with a verified device id", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const mallory = Client.create(`mallory@${DOMAIN}`, DEV.d);
    node.users.get("bob")!.kps.set(DEV.b, [b64urlEncode(mallory.createKeyPackage())]);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.addMissingDevices(CONV, [alice.address, bob.address]);
    expect(alice.mls.roster(CONV)).not.toContain(`mallory@${DOMAIN}/${DEV.d}`);
    expect(alice.mls.roster(CONV)).toEqual([`${alice.address}/${DEV.a}`]);
  });
});

describe("the check before encrypting does not mistake a device attested a moment ago for a ghost", () => {
  it("looks the user up again before refusing a new, unknown leaf", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.addMissingDevices(CONV, [alice.address, bob.address]);
    await bob.mls.processWelcomes(DOMAIN);
    await alice.mls.encrypt(CONV, { type: "text", body: "first" });
    // Bob's new device is attested and joins right after Alice's lookup of his devices.
    const phone = device("bob", DEV.c);
    expect(await phone.mls.ensureJoined(CONV, { canCreate: false })).toBe("joined");
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "to both of Bob's devices" })).resolves.toBeTruthy();
  });
});

describe("the ghost cleanup attests only the account's own device keys again (§4.7)", () => {
  /** A cleaner that signs with the master secret, as tavrn-web's lib/leafCleanup.ts does. */
  const cleanerOf = (dev: Device, master: MasterSecret, signed: { deviceId: string; key: Uint8Array }[]) =>
    new LeafCleaner({
      mls: dev.mls,
      reattest: async (deviceId, key) => {
        master.attestDevice(dev.address, deviceId, key);
        signed.push({ deviceId, key });
        return true;
      },
      sleep: async () => undefined,
    });

  it("removes a leaf the home node planted under the user's address without signing its key", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    // The (malicious) home node makes a device key of its own and joins the group by external commit as alice/<DEV.d>.
    const ghost = Client.create(alice.address, DEV.d);
    const ds = node.ds(alice.address, DEV.d);
    const gi = await ds.groupInfo(ID);
    const out = ghost.joinByExternalCommit(CONV, b64urlDecode(gi.group_info));
    await ds.postCommit(ID, { epoch: out.epoch, commit: b64urlEncode(out.commit), group_info: b64urlEncode(out.groupInfo), welcome: null });
    out.free();
    ghost.mergePendingCommit(CONV);
    await alice.mls.catchUp(CONV);
    expect(await alice.mls.knownOwnDevice(DEV.d, ghost.devicePublicKey)).toBe(false);
    const signed: { deviceId: string; key: Uint8Array }[] = [];
    const r = await cleanerOf(alice, masters.get(alice.address)!, signed).clean({ q: CONV, members: [alice.address], mayManage: false });
    // Nothing was signed: the node holds no attestation of its key under Alice's identity key.
    expect(signed).toEqual([]);
    expect(r.outcome).toBe("removed");
    expect(alice.mls.roster(CONV)).toEqual([`${alice.address}/${DEV.a}`]);
  });

  it("removes a leaf that names this very device with another key, and keeps its own leaf", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const twin = Client.create(alice.address, DEV.a);
    const ds = node.ds(alice.address, DEV.a);
    const out = twin.joinByExternalCommit(CONV, b64urlDecode((await ds.groupInfo(ID)).group_info));
    await ds.postCommit(ID, { epoch: out.epoch, commit: b64urlEncode(out.commit), group_info: b64urlEncode(out.groupInfo), welcome: null });
    out.free();
    await alice.mls.catchUp(CONV);
    expect(await alice.mls.ghostCheck(CONV, [alice.address])).toMatchObject([{ identity: `${alice.address}/${DEV.a}`, reason: "unattested" }]);
    const signed: { deviceId: string; key: Uint8Array }[] = [];
    const r = await cleanerOf(alice, masters.get(alice.address)!, signed).clean({ q: CONV, members: [alice.address], mayManage: false });
    expect(signed).toEqual([]);
    expect(r.outcome).toBe("removed");
    const entries = alice.mls.rosterEntries(CONV);
    expect(entries).toHaveLength(1);
    expect(b64urlEncode(entries[0]!.key)).toBe(b64urlEncode(alice.client().devicePublicKey));
  });

  it("attests a deleted own device again when the account recorded it, also from another device's record", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    const phone = device("alice", DEV.a2);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await alice.mls.addMissingDevices(CONV, [alice.address]);
    await phone.mls.processWelcomes(DOMAIN);
    // The phone's manager recorded its own device and uploads the trust record (sign-out flushes it).
    await phone.mls.flushBackups();
    await phone.mls.syncTrust();
    // The phone is deleted before nodes kept retired attestations: no retired entry, the leaf stays as a ghost.
    node.users.get("alice")!.devices.delete(DEV.a2);
    alice.mls.forgetDevices(alice.address);
    const signed: { deviceId: string; key: Uint8Array }[] = [];
    const r = await cleanerOf(alice, masters.get(alice.address)!, signed).clean({ q: CONV, members: [alice.address], mayManage: false });
    expect(signed.map((s) => [s.deviceId, b64urlEncode(s.key)])).toEqual([[DEV.a2, b64urlEncode(phone.client().devicePublicKey)]]);
    expect(r.outcome).toBe("removed");
  });
});

describe("the trust record survives a sign-out (ENCRYPTION.md §7)", () => {
  it("brings pins, verified contacts and own devices to a new device of the account", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.verifiedDevices(bob.address);
    expect(alice.pins[bob.address]).toBeTruthy();
    expect(await alice.mls.markVerified(bob.address, "qr")).toBe(true);
    await alice.mls.flushBackups();
    // Signed out and in again: a new device, empty local data.
    const again = device("alice", DEV.a3);
    expect(again.pins).toEqual({});
    await again.mls.restoreBackups();
    expect(again.pins[bob.address]).toEqual(alice.pins[bob.address]);
    expect(again.mls.verification(bob.address)).toBe("verified");
    expect(await again.mls.knownOwnDevice(DEV.a, alice.client().devicePublicKey)).toBe(true);
  });

  it("warns about a key that changed while the user was signed out", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.verifiedDevices(bob.address);
    await alice.mls.flushBackups();
    // Bob's home node swaps his identity key while Alice is signed out.
    const fake = MasterSecret.generate();
    node.users.get("bob")!.identity = b64urlEncode(fake.identityPublicKey());
    masters.set(bob.address, fake);
    const again = device("alice", DEV.a3);
    await again.mls.restoreBackups();
    await again.mls.verifiedDevices(bob.address);
    expect(again.mls.changedKeys()).toEqual([bob.address]);
  });

  it("a key pinned on first use while the record was unreachable is a changed key once the record arrives", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.verifiedDevices(bob.address);
    await alice.mls.flushBackups();
    await alice.mls.syncTrust();
    const fake = MasterSecret.generate();
    node.users.get("bob")!.identity = b64urlEncode(fake.identityPublicKey());
    masters.set(bob.address, fake);
    // The record cannot be fetched at first: Bob's swapped key is pinned on first use, the restore is not done.
    const again = device("alice", DEV.a3);
    const get = node.backups.get.bind(node.backups);
    node.backups.get = () => {
      throw new Error("offline");
    };
    await again.mls.verifiedDevices(bob.address);
    await again.mls.restoreBackups();
    expect(again.meta.restored).toBeFalsy();
    expect(again.mls.changedKeys()).toEqual([]);
    // Reachable again: the retried restore brings the stored pin, which conflicts without a continuity chain.
    node.backups.get = get;
    await again.mls.restoreBackups();
    expect(again.meta.restored).toBe(true);
    expect(again.mls.changedKeys()).toEqual([bob.address]);
  });

  it("a new key the user accepted is not flagged again by the older stored record", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.verifiedDevices(bob.address);
    await alice.mls.syncTrust();
    const fresh = MasterSecret.generate();
    node.users.get("bob")!.identity = b64urlEncode(fresh.identityPublicKey());
    masters.set(bob.address, fresh);
    alice.mls.identityChanged(bob.address);
    await alice.mls.verifiedDevices(bob.address);
    expect(alice.mls.changedKeys()).toEqual([bob.address]);
    await alice.mls.acceptNewKey(bob.address);
    await alice.mls.syncTrust();
    expect(alice.mls.changedKeys()).toEqual([]);
    expect(alice.pins[bob.address]!.key).toBe(b64urlEncode(fresh.identityPublicKey()));
  });

  it("is sealed: a record the node edits or moves to another account does not open", async () => {
    const { node, device } = setup();
    const alice = device("alice", DEV.a);
    await alice.mls.flushBackups();
    await alice.mls.syncTrust();
    const key = `${alice.address}|${DOMAIN}/00000000000000000000000000`;
    const stored = node.backups.get(key)!;
    stored.blob[stored.blob.length - 1]! ^= 1;
    const again = device("alice", DEV.a3);
    await again.mls.restoreBackups();
    expect(await again.mls.knownOwnDevice(DEV.a, alice.client().devicePublicKey)).toBe(false);
  });
});
