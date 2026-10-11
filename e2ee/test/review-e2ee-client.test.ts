// SPDX-License-Identifier: MPL-2.0
// Review tests of the e2ee-client wave: the trust record restored after a sign-out must still warn about a key that
// changed while the user was signed out, whatever lookups ran before the restore finished.
// cleanup attests a leaf key again as retired only when the account's own-devices record knows it. The session manager with the real WebAssembly crypto: several devices talk to in-memory nodes whose
// delivery services follow the node's rules for epochs, the handshake log, Welcomes and backups. Users
// live on different nodes (FEDERATION.md §3.5, §6): conversations are hosted by one node, keys come
// from each user's home node, KeyPackages of other nodes' users are claimed through the hosting node.
import { beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret } from "@tavrn/crypto";
import { b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { MlsManager, qualify, type MlsEvent, type MlsMeta, type Pin } from "../src/mls";
import { Network, domainOf } from "./fake-node";

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





describe("review: trust record vs. early lookups after a sign-in", () => {
  it("warns about a key that changed while signed out even when the contact was looked up before the restore", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.verifiedDevices(bob.address);
    await alice.mls.flushBackups();
    await alice.mls.syncTrust();
    // Bob's home node swaps his identity key while Alice is signed out.
    const fake = MasterSecret.generate();
    node.users.get("bob")!.identity = b64urlEncode(fake.identityPublicKey());
    masters.set(bob.address, fake);
    const again = device("alice", DEV.a3);
    // A plaintext channel (or any view) looks Bob up while restoreBackups is still running.
    await again.mls.verifiedDevices(bob.address);
    await again.mls.restoreBackups();
    await again.mls.verifiedDevices(bob.address, true);
    expect(again.mls.changedKeys()).toEqual([bob.address]);
  });

  it("a verified contact restored after an early lookup of a swapped key is not shown as verified", async () => {
    const { node, device, masters } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.verifiedDevices(bob.address);
    expect(await alice.mls.markVerified(bob.address, "qr")).toBe(true);
    await alice.mls.flushBackups();
    await alice.mls.syncTrust();
    const fake = MasterSecret.generate();
    node.users.get("bob")!.identity = b64urlEncode(fake.identityPublicKey());
    masters.set(bob.address, fake);
    const again = device("alice", DEV.a3);
    await again.mls.verifiedDevices(bob.address);
    await again.mls.restoreBackups();
    expect(again.mls.verification(bob.address)).not.toBe("verified");
  });
});

describe("review: a ghost acknowledgement covers that leaf, not a later one under the same name (ENCRYPTION.md §4.6)", () => {
  it("refuses again when another unattested leaf with the acknowledged identity but a new key appears", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const forged = device("bob", DEV.d, { forgedAttestation: true });
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await forged.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    await alice.mls.acknowledgeGhosts(CONV, [`${bob.address}/${DEV.d}`]);
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "ok after ack" })).resolves.toBeTruthy();
    const firstKey = b64urlEncode(forged.client().devicePublicKey);
    // The node brings another leaf under the same device id with a key of its own.
    const forged2 = device("bob", DEV.d, { forgedAttestation: true });
    await forged2.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    const keys = alice.mls.rosterEntries(CONV).filter((e) => e.identity === `${bob.address}/${DEV.d}`).map((e) => b64urlEncode(e.key));
    expect(keys.some((k) => k !== firstKey)).toBe(true);
    await expect(alice.mls.encrypt(CONV, { type: "text", body: "to the new ghost" })).rejects.toMatchObject({ code: "ghost" });
  });
});


describe("review: callers without a ghost UI (bots, @tavrn/bot uses encrypt without members or acknowledgement)", () => {
  it("a member whose key change was never acknowledged blocks every message of a caller that cannot acknowledge", async () => {
    const { device } = setup();
    const botLike = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await botLike.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: true });
    await botLike.mls.catchUp(CONV);
    await botLike.mls.verifiedDevices(bob.address);
    // Bob's key changed once (e.g. an identity reset): the pin carries `changed` until a person acknowledges it.
    botLike.pins[bob.address] = { ...botLike.pins[bob.address]!, changed: true };
    // Documenting the behaviour change: before the wave this resolved (no ghost check had run).
    await expect(botLike.mls.encrypt(CONV, { type: "text", body: "bot reply" })).rejects.toMatchObject({ code: "ghost" });
  });
});
