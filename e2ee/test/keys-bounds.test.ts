// SPDX-License-Identifier: MPL-2.0
// A keys document beyond the client's bounds (devices, retired devices, continuity statements) is refused as a whole
// before any signature in it is checked, and the refusal is kept like a lookup: a hostile home node cannot make every
// message cost thousands of signature checks.
import { beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret } from "@tavrn/crypto";
import { b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { KEYS_MAX_CONTINUITY, KEYS_MAX_DEVICES, KEYS_MAX_RETIRED, KeysDocumentError, MlsManager, qualify, type MlsMeta, type Pin } from "../src/mls";
import { Network, domainOf } from "./fake-node";

const DOMAIN = "t.local";
const CONV = qualify(DOMAIN, "01J9ZK3G5M8Q2W4E6R8T0Y2V00");
const DEV = { a: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1", b: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1" };

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
    const api = net.api(address, deviceId);
    let keyLookups = 0;
    const counted = { ...api, keys: (a: string) => (keyLookups++, api.keys(a)) };
    const pins: Record<string, Pin> = {};
    const meta: MlsMeta = { convs: {} };
    const mls = new MlsManager({
      api: counted,
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
    return { mls, address, record, pins, lookups: () => keyLookups };
  };
  return { device };
}

const filler = (n: number) => Array.from({ length: n }, (_, i) => [`01J9ZK3G5M8Q2W4E6R8T0Y${String(i).padStart(4, "0")}`, { pk: "AAAA", sig: "AAAA" }] as const);

describe("keys documents beyond the client's bounds", () => {
  it("are refused before anything is checked or pinned, and the refusal is kept", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    for (const [id, d] of filler(KEYS_MAX_DEVICES)) alice.record.devices.set(id, d);
    const err = await bob.mls.verifiedDevices(alice.address).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KeysDocumentError);
    expect((err as KeysDocumentError).message).toContain(`at most ${KEYS_MAX_DEVICES}`);
    expect(bob.pins[alice.address]).toBeUndefined();
    // A message of the author is not readable, and the document is not fetched again for it.
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const { content, epoch } = await alice.mls.encrypt(CONV, { type: "text", body: "hi" });
    const before = bob.lookups();
    for (let i = 0; i < 3; i++) expect(await bob.mls.decrypt(CONV, { id: `m${i}`, author: alice.address, device_id: DEV.a, epoch, content })).toMatchObject({ ok: false });
    expect(bob.lookups()).toBe(before);
  });

  it("covers retired devices and continuity statements; documents at the bounds are accepted", async () => {
    const { device } = setup();
    const alice = device("alice", DEV.a);
    const carol = device("carol", "01J9ZK3G5M8Q2W4E6R8T0Y2VC1");
    const bob = device("bob", DEV.b);
    alice.record.retired = new Map(filler(KEYS_MAX_RETIRED + 1).map(([id, d]) => [id, { ...d, deletedAt: "2026-10-01T00:00:00Z" }]));
    await expect(bob.mls.verifiedDevices(alice.address)).rejects.toBeInstanceOf(KeysDocumentError);
    const statement = { old_key: "a", new_key: "b", at: "2026-10-01T00:00:00Z", sig_old: "x", sig_new: "y" };
    carol.record.continuity = Array.from({ length: KEYS_MAX_CONTINUITY + 1 }, () => statement);
    await expect(bob.mls.verifiedDevices(carol.address)).rejects.toBeInstanceOf(KeysDocumentError);
    // At the bounds: checked as usual (the filler entries are simply not verified). Another reader: Bob keeps his
    // refusal for the lookup's lifetime.
    carol.record.continuity = Array.from({ length: KEYS_MAX_CONTINUITY }, () => statement);
    for (const [id, d] of filler(KEYS_MAX_DEVICES - 1)) carol.record.devices.set(id, d);
    await expect(bob.mls.verifiedDevices(carol.address)).rejects.toBeInstanceOf(KeysDocumentError);
    const dave = device("dave", "01J9ZK3G5M8Q2W4E6R8T0Y2VD1");
    const devices = await dave.mls.verifiedDevices(carol.address);
    expect([...(devices?.keys() ?? [])]).toEqual(["01J9ZK3G5M8Q2W4E6R8T0Y2VC1"]);
  });
});
