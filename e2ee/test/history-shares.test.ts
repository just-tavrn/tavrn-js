// SPDX-License-Identifier: MPL-2.0
// History shares and a hosting node that lies (ENCRYPTION.md §7b): shares are sealed to the recipient's attested
// devices only (format 2; format 1 is never sent), and the window of an automatic share does not reach further back
// than this device's own knowledge of the member allows, whatever `since` the node reports.
import { beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret } from "@tavrn/crypto";
import { b64urlEncode, type HistoryShare, type Message } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { MlsManager, qualify, type MlsEvent } from "../src/mls";
import { HistorySync, MAX_JOIN_GAP_MS, boundedJoin, ulidFloor, type HistoryApi, type HistorySyncDeps } from "../src/history";
import { Network, domainOf } from "./fake-node";

const DOMAIN = "t.local";
const ID = "01J9ZK3G5M8Q2W4E6R8T0Y2V00";
const CONV = qualify(DOMAIN, ID);
const DEV = { a: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1", b: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1", c: "01J9ZK3G5M8Q2W4E6R8T0Y2VC1", m: "01J9ZK3G5M8Q2W4E6R8T0Y2VM1" };

beforeAll(() => ensureCrypto());

interface Device {
  mls: MlsManager;
  address: string;
  deviceId: string;
  events: MlsEvent[];
}

/** A small node: delivery service from the fake network, plus messages, history shares and pending marks. */
function setup() {
  const net = new Network();
  const masters = new Map<string, MasterSecret>();
  const messages: Message[] = [];
  // Shares as the node keeps them (`v` is absent on shares of older nodes; `boxes` per recipient device).
  const shares: (Omit<HistoryShare, "v" | "box"> & { v?: number; to: string; boxes?: Record<string, string> })[] = [];
  const pending: { user: string; since: string; key_reset_at?: string | null; min_epoch?: number | null }[] = [];
  let counter = 0;
  /** `shareKey`: the device published its share key (default), did not (`none`) or a forged one (`forged`). */
  const device = (user: string, deviceId: string, opts: { shareKey?: "none" | "forged" } = {}): Device => {
    const address = `${user}@${DOMAIN}`;
    const home = net.node(domainOf(address));
    let master = masters.get(address);
    if (!master) {
      master = MasterSecret.generate();
      masters.set(address, master);
      home.addUser(user, master);
    }
    const client = Client.create(address, deviceId);
    const share = opts.shareKey === "none" ? null : opts.shareKey === "forged" ? Client.create(address, deviceId).shareKey() : client.shareKey();
    const forgedKey = opts.shareKey === "forged" ? client.shareKey().publicKey : null;
    home.users.get(user)!.devices.set(deviceId, {
      pk: b64urlEncode(client.devicePublicKey),
      sig: b64urlEncode(master.attestDevice(address, deviceId, client.devicePublicKey)),
      ...(share ? { spk: b64urlEncode(forgedKey ?? share.publicKey), ssig: b64urlEncode(share.signature) } : {}),
    });
    home.users.get(user)!.kps.set(deviceId, [b64urlEncode(client.createKeyPackage())]);
    const events: MlsEvent[] = [];
    const m = master;
    const mls = new MlsManager({
      api: net.api(address, deviceId),
      client,
      address,
      deviceId,
      homeDomain: DOMAIN,
      persist: async () => undefined,
      backupKey: () => m.backupKey(),
      ownIdentityKey: () => b64urlEncode(m.identityPublicKey()),
      pins: {},
      savePins: async () => undefined,
      meta: { convs: {} },
      saveMeta: async () => undefined,
      onEvent: (e) => events.push(e),
      backupDelayMs: 60_000,
    });
    return { mls, address, deviceId, events };
  };
  /** The history routes as one user sees them (the node's rules: only the addressed user reads). */
  const api = (dev: Device): HistoryApi => ({
    share: async (_c, req) => {
      const v2 = req.v === 2 ? { v: 2, boxes: req.boxes ?? {} } : {};
      shares.push({ id: `s${++counter}`, to: req.to_user, from_user: dev.address, from_device: dev.deviceId, epoch_from: req.epoch_from, epoch_to: req.epoch_to, ciphertext: req.ciphertext, created_at: "", ...v2 } as (typeof shares)[number]);
      return {};
    },
    // The node's rule (ENCRYPTION.md §7b): format 2 shares only to devices with a box, each with its own box.
    shares: async () => ({
      items: shares
        .filter((s) => s.to === dev.address && (s.v !== 2 || s.boxes?.[dev.deviceId]))
        .map(({ boxes, ...s }) => (s.v === 2 ? { ...s, box: boxes![dev.deviceId]! } : s)) as HistoryShare[],
    }),
    ack: async (_c, id) => {
      const i = shares.findIndex((s) => s.id === id && s.to === dev.address);
      if (i >= 0) {
        shares.splice(i, 1);
        const p = pending.findIndex((x) => x.user === dev.address);
        if (p >= 0) pending.splice(p, 1);
      }
    },
    pending: async () => ({ items: [...pending] }),
    // The node's listing: without `threads=all` (or `epoch`) the channel's own messages only, thread messages left out.
    messages: async (_c, q) => {
      const listed = messages.filter((m) => q.epoch !== undefined || q.threads === "all" || !m.thread_id);
      return q.before
        ? listed.filter((m) => m.id < q.before!).sort((a, b) => (a.id < b.id ? 1 : -1)).slice(0, q.limit ?? 50)
        : listed.filter((m) => (q.epoch === undefined || (m.encrypted && m.epoch === q.epoch)) && (!q.after || m.id > q.after)).slice(0, q.limit ?? 50);
    },
  });
  const sync = (dev: Device, online: (a: string) => boolean = () => true, log: string[] = [], extra: Partial<HistorySyncDeps> = {}) =>
    new HistorySync({ mls: dev.mls, address: dev.address, deviceId: dev.deviceId, api: () => api(dev), isOnline: online, onLog: (e) => log.push(e), backoffMs: 50, ...extra });
  const post = async (dev: Device, body: string) => {
    const { content, epoch } = await dev.mls.encrypt(CONV, { type: "text", body });
    const m = { id: ulidFloor(Date.now()).slice(0, 10) + String(++counter).padStart(16, "0"), author: dev.address, device_id: dev.deviceId, epoch, content, encrypted: true } as unknown as Message;
    messages.push(m);
    return m;
  };
  return { device, sync, post, messages, shares, pending, api, net };
}


describe("history shares do not trust the hosting node", () => {
  /** Alice posts a message a year ago, Bob joins, the node lets a device of its own in under Bob's address. */
  async function scenario() {
    const env = setup();
    const { device, post, messages, net } = env;
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const old = await post(alice, "old secret");
    (old as { id: string }).id = ulidFloor(Date.now() - 365 * 24 * 3_600_000);
    messages.sort((a, b) => (a.id < b.id ? -1 : 1));
    await alice.mls.selfUpdate(CONV);
    const recent = await post(alice, "since the join");
    await alice.mls.selfUpdate(CONV);
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    const ghost = device("bob", DEV.m);
    net.node(DOMAIN).users.get("bob")!.devices.delete(DEV.m);
    await ghost.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    // The node marks Bob pending since 1970.
    env.pending.push({ user: bob.address, since: "1970-01-01T00:00:00.000Z" });
    return { ...env, alice, bob, ghost, old, recent };
  }

  it("sends nothing without history.shares2: format 1 would reach the unattested leaf", async () => {
    const { sync, shares, alice, ghost, old } = await scenario();
    const log: string[] = [];
    await sync(alice, undefined, log).checkPending(CONV, { kind: "since_join" });
    expect(shares).toEqual([]);
    expect(log).toContain("share_skipped");
    expect(await sync(ghost).receive(CONV)).toBe(0);
    expect(await ghost.mls.decrypt(CONV, old)).toMatchObject({ ok: false });
  });

  it("seals the share to Bob's attested device only and bounds the window by its own knowledge of Bob", async () => {
    const { sync, shares, alice, bob, ghost, old, recent } = await scenario();
    await sync(alice, undefined, [], { shares2: () => true }).checkPending(CONV, { kind: "since_join" });
    expect(shares).toHaveLength(1);
    expect(shares[0]!.v).toBe(2);
    expect(Object.keys(shares[0]!.boxes!)).toEqual([DEV.b]);
    // The year-old epoch is outside the window: the node's `since` is moved up to 30 days before Alice saw Bob.
    expect(shares[0]!.epoch_from).toBe(recent.epoch);
    expect(await sync(ghost).receive(CONV)).toBe(0);
    expect(await sync(bob).receive(CONV)).toBeGreaterThan(0);
    expect(await bob.mls.decrypt(CONV, recent)).toMatchObject({ ok: true, content: { body: "since the join" } });
    expect(await bob.mls.decrypt(CONV, old)).toMatchObject({ ok: false });
  });

  it("bounds a reported join by the time the member was first seen", () => {
    const seen = Date.parse("2026-10-01T00:00:00Z");
    expect(boundedJoin(Date.parse("1970-01-01T00:00:00Z"), seen)).toBe(seen - MAX_JOIN_GAP_MS);
    expect(boundedJoin(seen - 3_600_000, seen)).toBe(seen - 3_600_000);
    expect(boundedJoin(Number.NaN, seen)).toBe(seen);
  });
});
