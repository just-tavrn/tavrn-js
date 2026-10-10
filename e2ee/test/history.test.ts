// SPDX-License-Identifier: MPL-2.0
// History for new members (ENCRYPTION.md §7b): the pure parts (policy, windows, chunking, election, payload
// codec, key check) and the flows of HistorySync between real session managers on an in-memory node.
import { beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret } from "@tavrn/crypto";
import { b64urlEncode, jcs, type HistoryShare, type Message } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { MlsManager, qualify, type MlsEvent } from "../src/mls";
import {
  HISTORY_KEYS_TYPE,
  HistorySync,
  MAX_EPOCHS_PER_SHARE,
  chunkEpochs,
  encodeHistoryPayload,
  epochKeyOpens,
  epochsToShare,
  grantsHistory,
  historyWindowStart,
  parseHistoryPayload,
  parseHistoryPolicy,
  pickSample,
  pickSamples,
  sharerDelay,
  ulidFloor,
  epochsSinceReset,
  type HistoryApi,
  type HistorySyncDeps,
} from "../src/history";
import { Network, domainOf } from "./fake-node";

const DOMAIN = "t.local";
const ID = "01J9ZK3G5M8Q2W4E6R8T0Y2V00";
const CONV = qualify(DOMAIN, ID);
const DEV = { a: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1", b: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1", c: "01J9ZK3G5M8Q2W4E6R8T0Y2VC1", m: "01J9ZK3G5M8Q2W4E6R8T0Y2VM1" };

beforeAll(() => ensureCrypto());

describe("policy and windows", () => {
  it("parses the channel setting strictly, unknown values are since_join", () => {
    expect(parseHistoryPolicy("all")).toEqual({ kind: "all" });
    expect(parseHistoryPolicy("days:30")).toEqual({ kind: "days", days: 30 });
    expect(parseHistoryPolicy("days:3650")).toEqual({ kind: "days", days: 3650 });
    for (const v of ["since_join", "", null, undefined, "days:0", "days:3651", "days:07", "ALL", "days:1.5"]) expect(parseHistoryPolicy(v)).toEqual({ kind: "since_join" });
    expect(grantsHistory({ kind: "since_join" })).toBe(false);
    expect(grantsHistory({ kind: "days", days: 1 })).toBe(true);
  });

  it("computes the window like the node and the ULID floor of a time", () => {
    const join = Date.parse("2026-10-05T12:00:00.000Z");
    expect(historyWindowStart({ kind: "since_join" }, join)).toBe(join);
    expect(historyWindowStart({ kind: "all" }, join)).toBeNull();
    expect(historyWindowStart({ kind: "days", days: 1 }, join)).toBe(Date.parse("2026-10-04T12:00:00.000Z"));
    // Same encoding as the Rust ulid crate (Crockford base32 of the milliseconds, zero randomness).
    expect(ulidFloor(0)).toBe("00000000000000000000000000");
    expect(ulidFloor(1_469_918_176_385)).toBe("01ARYZ6S410000000000000000");
  });

  it("selects the epochs to share per policy", () => {
    const known = [0, 1, 2, 3, 5, 7];
    // since_join: the epochs of the messages since the member's join (posted before its device entered the group).
    expect(epochsToShare({ kind: "since_join" }, known, 7, 3)).toEqual([3, 5]);
    expect(epochsToShare({ kind: "since_join" }, known, 7, null)).toEqual([]);
    expect(epochsToShare({ kind: "all" }, known, 7, null)).toEqual([0, 1, 2, 3, 5]);
    expect(epochsToShare({ kind: "days", days: 1 }, known, 7, 3)).toEqual([3, 5]);
    // No message in the window: nothing.
    expect(epochsToShare({ kind: "days", days: 1 }, known, 7, null)).toEqual([]);
  });

  it("chunks by count and by range", () => {
    expect(chunkEpochs([])).toEqual([]);
    expect(chunkEpochs([3, 1, 2, 2])).toEqual([[1, 2, 3]]);
    const many = Array.from({ length: 1200 }, (_, i) => i);
    const chunks = chunkEpochs(many);
    expect(chunks.map((c) => c.length)).toEqual([500, 500, 200]);
    // Sparse epochs: a share never spans more than 1000 epochs.
    const sparse = chunkEpochs([0, 10, 999, 1000, 1500], 500);
    expect(sparse).toEqual([[0, 10, 999], [1000, 1500]]);
    for (const c of chunkEpochs(Array.from({ length: 300 }, (_, i) => i * 7))) expect(c[c.length - 1]! - c[0]!).toBeLessThan(MAX_EPOCHS_PER_SHARE);
  });

  it("elects the lowest device, the others back off by rank, the Add committer goes first", () => {
    const me = "bob@t.local/01B";
    expect(sharerDelay(me, ["carol@t.local/01C", "dave@t.local/01D"])).toBe(0);
    expect(sharerDelay(me, ["alice@t.local/01A", "carol@t.local/01C"])).toBe(60_000);
    expect(sharerDelay(me, ["alice@t.local/01A", "aaron@t.local/01Z"], false, 1000)).toBe(2000);
    expect(sharerDelay(me, ["alice@t.local/01A"], true)).toBe(0);
    expect(sharerDelay(me, [])).toBe(0);
  });
});

describe("payload codec", () => {
  const key = new Uint8Array(32).fill(7);
  const expected = { conversation: CONV, to: "bob@t.local", epochFrom: 0, epochTo: 5 };
  const parse = (json: string, e = expected) => parseHistoryPayload(JSON.parse(json) as Record<string, unknown>, e);

  it("round-trips canonical JSON", () => {
    const json = encodeHistoryPayload(CONV, "bob@t.local", [[1, key], [3, key]]);
    expect(json).toBe(jcs(JSON.parse(json)));
    expect(JSON.parse(json).type).toBe(HISTORY_KEYS_TYPE);
    const keys = parse(json)!;
    expect(keys.map(([e]) => e)).toEqual([1, 3]);
    expect(keys[0]![1]).toEqual(key);
  });

  it("rejects anything that does not match the share", () => {
    const ok = JSON.parse(encodeHistoryPayload(CONV, "bob@t.local", [[1, key]]));
    const variants: unknown[] = [
      { ...ok, type: "text" },
      { ...ok, v: 2 },
      { ...ok, conversation: qualify("evil.test", ID) },
      { ...ok, to: "mallory@t.local" },
      { ...ok, epochs: [[9, b64urlEncode(key)]] },
      { ...ok, epochs: [[1, b64urlEncode(key)], [1, b64urlEncode(key)]] },
      { ...ok, epochs: [[1, b64urlEncode(key.slice(0, 31))]] },
      { ...ok, epochs: [[1.5, b64urlEncode(key)]] },
      { ...ok, epochs: [["1", b64urlEncode(key)]] },
      { ...ok, epochs: "nope" },
      { ...ok, extra: true },
    ];
    for (const v of variants) expect(parseHistoryPayload(v as Record<string, unknown>, expected)).toBeNull();
  });
});

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

describe("HistorySync", () => {
  it("shares the history with a new member who then reads it; the keys live only in the client state", async () => {
    const { device, sync, post, shares, pending } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const old = await post(alice, "vor Bobs Beitritt");
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    expect(await bob.mls.decrypt(CONV, old)).toEqual({ ok: false, reason: "missing_key" });

    pending.push({ user: bob.address, since: new Date().toISOString() });
    await sync(alice).checkPending(CONV, { kind: "all" });
    expect(shares).toHaveLength(1);
    expect(shares[0]).toMatchObject({ to: bob.address, epoch_from: 0, epoch_to: 0 });
    // The node sees only ciphertext.
    expect(JSON.stringify(shares)).not.toContain("history_keys");

    const log: string[] = [];
    expect(await sync(bob, undefined, log).receive(CONV)).toBe(1);
    expect(log).toEqual([]);
    expect(bob.mls.knownEpochs(CONV)).toEqual([0, 1]);
    expect(await bob.mls.decrypt(CONV, old)).toEqual({ ok: true, content: { type: "text", body: "vor Bobs Beitritt" } });
    expect(bob.events.some((e) => e.type === "epoch")).toBe(true);
    // Acknowledged: nothing left, Bob no longer pending.
    expect(shares).toHaveLength(0);
    expect(pending).toHaveLength(0);
    // The share never entered the decrypted-message cache.
    expect(bob.mls.peek(CONV, { id: "history:s1", author: alice.address, device_id: DEV.a, epoch: 1, content: "" })).toBeUndefined();
  });

  it("does not lose a share announced while a fetch is running: one more pass follows it", async () => {
    const { device, sync, post, shares, pending, api } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const old = await post(alice, "vor Bobs Beitritt");
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    pending.push({ user: bob.address, since: new Date().toISOString() });

    // Bob opens the channel: his first fetch reads the (still empty) list and is slow to finish.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let calls = 0;
    const slow = (): HistoryApi => {
      const base = api(bob);
      return {
        ...base,
        shares: async (c) => {
          const list = await base.shares(c);
          if (++calls === 1) await gate;
          return list;
        },
      };
    };
    const bobSync = sync(bob, undefined, [], { api: slow });
    const opening = bobSync.receive(CONV);
    await Promise.resolve();
    // Meanwhile Alice shares and the node announces it (`history.keys_available`): Bob asks again.
    await sync(alice).checkPending(CONV, { kind: "all" });
    expect(shares).toHaveLength(1);
    const announced = bobSync.receive(CONV);
    const again = bobSync.receive(CONV);
    release();
    expect(await opening).toBe(0);
    expect(await announced).toBe(1);
    // Several triggers during one run share the one extra pass.
    expect(await again).toBe(1);
    expect(calls).toBe(2);
    expect(await bob.mls.decrypt(CONV, old)).toEqual({ ok: true, content: { type: "text", body: "vor Bobs Beitritt" } });
    expect(shares).toHaveLength(0);
  });

  it("drops poisoned keys, rejects shares from devices outside the group and for others", async () => {
    const { device, sync, post, shares } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const mallory = device("mallory", DEV.m);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const old = await post(alice, "geheim");
    await mallory.mls.ensureJoined(CONV, { canCreate: false });
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    await mallory.mls.catchUp(CONV);

    // A member shares a forged key for epoch 0: it does not open Alice's message, Bob drops it.
    const forged = encodeHistoryPayload(CONV, bob.address, [[0, new Uint8Array(32).fill(9)]]);
    const enc = await mallory.mls.encryptHistory(CONV, forged);
    shares.push({ id: "p1", to: bob.address, from_user: mallory.address, from_device: DEV.m, epoch_from: 0, epoch_to: 0, ciphertext: enc.content, created_at: "" });
    // A share meant for someone else (re-addressed by the node) is rejected as a whole.
    const other = await alice.mls.encryptHistory(CONV, encodeHistoryPayload(CONV, mallory.address, alice.mls.exportEpochKeys(CONV, [0])));
    shares.push({ id: "p2", to: bob.address, from_user: alice.address, from_device: DEV.a, epoch_from: 0, epoch_to: 0, ciphertext: other.content, created_at: "" });
    // A share claiming a device that is not in the group.
    shares.push({ id: "p3", to: bob.address, from_user: "carol@t.local", from_device: DEV.c, epoch_from: 0, epoch_to: 0, ciphertext: enc.content, created_at: "" });
    // The node swaps the claimed sender: the signature does not match.
    shares.push({ id: "p4", to: bob.address, from_user: alice.address, from_device: DEV.a, epoch_from: 0, epoch_to: 0, ciphertext: enc.content, created_at: "" });

    const log: string[] = [];
    expect(await sync(bob, undefined, log).receive(CONV)).toBe(0);
    expect(bob.mls.knownEpochs(CONV)).not.toContain(0);
    expect(await bob.mls.decrypt(CONV, old)).toEqual({ ok: false, reason: "missing_key" });
    expect(log.filter((l) => l === "keys_rejected")).toHaveLength(1);
    expect(log.filter((l) => l === "share_rejected")).toHaveLength(3);
    // The forged share was acknowledged (it decrypted), the rejected ones stay unacknowledged.
    expect(shares.map((s) => s.id).sort()).toEqual(["p2", "p3", "p4"]);
  });

  it("drops a planted key whose sample message is not signed by the claimed author's device (node and sharer collude)", async () => {
    const { device, sync, post, shares, messages } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    const mallory = device("mallory", DEV.m);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const old = await post(alice, "geheim");
    await mallory.mls.ensureJoined(CONV, { canCreate: false });
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    await mallory.mls.catchUp(CONV);

    // Mallory shares a key of her choice for epoch 0; the node serves a "message of Alice" made under that key.
    // Anyone who knows the key can produce the AES-GCM tag; only Alice's device can produce the signature inside.
    const planted = new Uint8Array(32).fill(7);
    const json = new TextEncoder().encode('{"type":"text","body":"fake"}');
    const str16 = (x: string) => {
      const b = new TextEncoder().encode(x);
      return [b.length >> 8, b.length & 0xff, ...b];
    };
    const aad = new Uint8Array([1, ...str16(CONV), 0, 0, 0, 0, 0, 0, 0, 0, ...str16(alice.address), ...str16(DEV.a)]);
    const nonce = new Uint8Array(12).fill(3);
    const k = await crypto.subtle.importKey("raw", planted, "AES-GCM", false, ["encrypt"]);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, k, new Uint8Array([...new Uint8Array(64).fill(1), ...json])));
    const forgedContent = b64urlEncode(new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0, ...nonce, ...ct]));
    messages.unshift({ ...old, id: "01J9ZK3G5M8Q2W4E6R8T0Y2VF0", content: forgedContent } as Message);
    const enc = await mallory.mls.encryptHistory(CONV, encodeHistoryPayload(CONV, bob.address, [[0, planted]]));
    shares.push({ id: "q1", to: bob.address, from_user: mallory.address, from_device: DEV.m, epoch_from: 0, epoch_to: 0, ciphertext: enc.content, created_at: "" });

    const log: string[] = [];
    expect(await sync(bob, undefined, log).receive(CONV)).toBe(0);
    expect(bob.mls.knownEpochs(CONV)).not.toContain(0);
    expect(log).toContain("keys_rejected");
    // The real key still gets in later (a planted one would have blocked it for good: keys are never overwritten).
    const real = await alice.mls.encryptHistory(CONV, encodeHistoryPayload(CONV, bob.address, alice.mls.exportEpochKeys(CONV, [0])));
    messages.shift();
    shares.push({ id: "q2", to: bob.address, from_user: alice.address, from_device: DEV.a, epoch_from: 0, epoch_to: 0, ciphertext: real.content, created_at: "" });
    expect(await sync(bob).receive(CONV)).toBe(1);
    expect(await bob.mls.decrypt(CONV, old)).toEqual({ ok: true, content: { type: "text", body: "geheim" } });
  });

  it("checks keys against messages of other authors first", () => {
    const msgs = [
      { author: "mallory@t.local", device_id: "D1", epoch: 4, content: "x", encrypted: true },
      { author: "alice@t.local", device_id: "D2", epoch: 4, content: "y", encrypted: true },
      { author: "alice@t.local", device_id: "D2", epoch: 5, content: "z", encrypted: true },
    ] as Message[];
    expect(pickSample(msgs, 4, "mallory@t.local")).toEqual({ author: "alice@t.local", device_id: "D2", epoch: 4, content: "y" });
    expect(pickSample(msgs.slice(0, 1), 4, "mallory@t.local")?.author).toBe("mallory@t.local");
    expect(pickSample(msgs, 6, "x")).toBeNull();
  });

  it("validates a key with the message's AEAD tag only", async () => {
    const { device, post } = setup();
    const alice = device("alice", DEV.a);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const m = await post(alice, "probe");
    const [[, key]] = alice.mls.exportEpochKeys(CONV, [0]) as [[number, Uint8Array]];
    const sample = { author: alice.address, device_id: DEV.a, epoch: 0, content: m.content as string };
    expect(await epochKeyOpens(key, CONV, sample)).toBe(true);
    expect(await epochKeyOpens(new Uint8Array(32), CONV, sample)).toBe(false);
    expect(await epochKeyOpens(key, qualify(DOMAIN, "01J9ZK3G5M8Q2W4E6R8T0Y2V01"), sample)).toBe(false);
    expect(await epochKeyOpens(key, CONV, { ...sample, author: "bob@t.local" })).toBe(false);
    expect(await epochKeyOpens(key, CONV, { ...sample, epoch: 1 })).toBe(false);
    expect(await epochKeyOpens(key, CONV, { ...sample, content: "AAAA" })).toBe(false);
  });

  it("with days:n shares only epochs from the window, and an empty share when nothing is in it", async () => {
    const { device, sync, post, shares, messages } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const old = await post(alice, "alt");
    // Epoch 0's message is three days old (its ULID says so).
    (old as { id: string }).id = ulidFloor(Date.now() - 3 * 86_400_000);
    messages.sort((a, b) => (a.id < b.id ? -1 : 1));
    await alice.mls.selfUpdate(CONV);
    await post(alice, "neu");
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    const s = sync(alice);
    expect(await s.shareWith(CONV, bob.address, Date.now(), { kind: "days", days: 1 })).toBe(1);
    expect(shares[0]).toMatchObject({ epoch_from: 1, epoch_to: 1 });
    // A window after every message: nothing to send.
    expect(await s.shareWith(CONV, bob.address, Date.now() + 5 * 86_400_000, { kind: "days", days: 1 })).toBe(0);
    expect(shares[1]).toMatchObject({ epoch_from: 2, epoch_to: 2 }); // empty share under the current epoch
    expect(await s.shareWith(CONV, bob.address, Date.now(), { kind: "since_join" })).toBe(0);
  });

  it("lets the elected device share and the others wait while the member is pending", async () => {
    const { device, sync, post, shares, pending } = setup();
    const alice = device("alice", DEV.a);
    const carol = device("carol", DEV.c);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await post(alice, "x");
    await carol.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    // Not pending yet without a device of Bob in the group: nobody shares.
    pending.push({ user: bob.address, since: new Date().toISOString() });
    await sync(alice).checkPending(CONV, { kind: "all" });
    expect(shares).toHaveLength(0);
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    await carol.mls.catchUp(CONV);
    // Alice's device id sorts first: Carol waits and finds Bob still pending only if Alice did not share.
    const carolSync = sync(carol);
    await carolSync.checkPending(CONV, { kind: "all" });
    expect(shares).toHaveLength(0);
    await sync(alice).checkPending(CONV, { kind: "all" });
    expect(shares).toHaveLength(1);
    await sync(bob).receive(CONV);
    expect(pending).toHaveLength(0);
    await new Promise((r) => setTimeout(r, 120));
    expect(shares).toHaveLength(0); // Carol saw that Bob no longer waits
    carolSync.dispose();
    // Offline members do not count: Carol alone online shares at once.
    pending.push({ user: bob.address, since: "2026-10-05T00:00:00.000Z" });
    await sync(carol, (a) => a !== alice.address).checkPending(CONV, { kind: "all" });
    expect(shares).toHaveLength(1);
    // since_join: members wait too (for the messages since their join), and the elected device shares.
    await sync(alice).checkPending(CONV, { kind: "since_join" });
    expect(shares).toHaveLength(2);
  });

  it("since_join: shares the epochs of the messages since the member's join, never older ones", async () => {
    const { device, sync, post, shares, pending, messages } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const joinedAt = Date.now() - 3_600_000;
    // Epoch 0: a message from before Bob's room join; epoch 1: one after it, before his device entered the group.
    const before = await post(alice, "vor Bobs Beitritt");
    (before as { id: string }).id = ulidFloor(joinedAt - 3_600_000);
    messages.sort((a, b) => (a.id < b.id ? -1 : 1));
    await alice.mls.selfUpdate(CONV);
    const gap = await post(alice, "nach Bobs Beitritt");
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    expect(await bob.mls.decrypt(CONV, gap)).toEqual({ ok: false, reason: "missing_key" });

    pending.push({ user: bob.address, since: new Date(joinedAt).toISOString() });
    await sync(alice).checkPending(CONV, { kind: "since_join" });
    expect(shares).toHaveLength(1);
    expect(shares[0]).toMatchObject({ to: bob.address, epoch_from: 1, epoch_to: 1 });
    expect(await sync(bob).receive(CONV)).toBe(1);
    expect(bob.mls.knownEpochs(CONV)).toEqual([1, 2]);
    expect(await bob.mls.decrypt(CONV, gap)).toEqual({ ok: true, content: { type: "text", body: "nach Bobs Beitritt" } });
    expect(await bob.mls.decrypt(CONV, before)).toEqual({ ok: false, reason: "missing_key" });
    expect(pending).toHaveLength(0);
  });

  it("counts the messages of threads (forum posts) when it looks for the window's oldest epoch", async () => {
    const { device, sync, post, shares, pending } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const joinedAt = Date.now() - 1000;
    // The only content since Bob's join is a forum post: a thread message, not part of the channel's own list.
    const first = await post(alice, "Beitrag im Forum");
    (first as { thread_id?: string }).thread_id = "01J9ZK3G5M8Q2W4E6R8T0Y2VT1";
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    pending.push({ user: bob.address, since: new Date(joinedAt).toISOString() });
    await sync(alice).checkPending(CONV, { kind: "since_join" });
    expect(shares[0]).toMatchObject({ epoch_from: 0, epoch_to: 0 });
    expect(await sync(bob).receive(CONV)).toBe(1);
    expect(await bob.mls.decrypt(CONV, first)).toEqual({ ok: true, content: { type: "text", body: "Beitrag im Forum" } });
  });
});

describe("history shares v2 (ENCRYPTION.md §7b \"Format v2\")", () => {
  const PHONE = "01J9ZK3G5M8Q2W4E6R8T0Y2VB2";

  /** Alice writes in epoch 0; Bob joins with his laptop and his phone; Carol is another member. */
  async function scenario(phone: { shareKey?: "none" | "forged" } = {}) {
    const env = setup();
    const { device, post } = env;
    const alice = device("alice", DEV.a);
    const carol = device("carol", DEV.c);
    const bob = device("bob", DEV.b);
    const bobPhone = device("bob", PHONE, phone);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const old = await post(alice, "vor Bobs Beitritt");
    await carol.mls.ensureJoined(CONV, { canCreate: false });
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await bobPhone.mls.ensureJoined(CONV, { canCreate: false });
    for (const d of [alice, carol, bob]) await d.mls.catchUp(CONV);
    env.pending.push({ user: bob.address, since: new Date().toISOString() });
    return { ...env, alice, carol, bob, bobPhone, old };
  }

  it("seals the share to every device of the recipient; each opens only its own box, other members nothing", async () => {
    const { sync, shares, alice, carol, bob, bobPhone, old } = await scenario();
    await sync(alice, undefined, [], { shares2: () => true }).checkPending(CONV, { kind: "all" });
    expect(shares).toHaveLength(1);
    const share = shares[0]!;
    expect(share.v).toBe(2);
    expect(Object.keys(share.boxes!).sort()).toEqual([DEV.b, PHONE].sort());
    // Carol knows the epoch's content key but cannot read the share, with or without a box of Bob's.
    expect((await carol.mls.decryptHistory(CONV, share.id, alice.address, DEV.a, share.ciphertext)).ok).toBe(false);
    expect((await carol.mls.decryptHistory(CONV, share.id, alice.address, DEV.a, share.ciphertext, share.boxes![DEV.b])).ok).toBe(false);
    // Bob's phone opens its own box (not the laptop's) and reads the keys.
    expect((await bobPhone.mls.decryptHistory(CONV, share.id, alice.address, DEV.a, share.ciphertext, share.boxes![DEV.b])).ok).toBe(false);
    const log: string[] = [];
    expect(await sync(bobPhone, undefined, log).receive(CONV)).toBe(1);
    // Epochs 1 and 2 have no message to check their keys against (dropped as always); the share itself is accepted.
    expect(log).not.toContain("share_rejected");
    expect(await bobPhone.mls.decrypt(CONV, old)).toEqual({ ok: true, content: { type: "text", body: "vor Bobs Beitritt" } });
    expect(shares).toHaveLength(0);
    void bob;
  });

  it("looks the recipient's devices up again when a device in the group is not in the cached lookup", async () => {
    const { device, post, sync, shares, pending } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await post(alice, "vorher");
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    await alice.mls.verifiedDevices(bob.address); // cached before the phone existed
    const phone = device("bob", PHONE);
    await phone.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    pending.push({ user: bob.address, since: new Date().toISOString() });
    await sync(alice, undefined, [], { shares2: async () => true }).checkPending(CONV, { kind: "all" });
    expect(Object.keys(shares[0]!.boxes ?? {}).sort()).toEqual([DEV.b, PHONE].sort());
  });

  it("falls back to format 1 without the capability or a verified share key on every device of the recipient", async () => {
    for (const [phone, shares2] of [[{}, false], [{ shareKey: "none" as const }, true], [{ shareKey: "forged" as const }, true]] as const) {
      const { sync, shares, alice, bob, old } = await scenario(phone);
      await sync(alice, undefined, [], { shares2: () => shares2 }).checkPending(CONV, { kind: "all" });
      expect(shares, JSON.stringify(phone)).toHaveLength(1);
      expect(shares[0]!.v ?? 1).toBe(1);
      expect(shares[0]!.boxes).toBeUndefined();
      expect(await sync(bob).receive(CONV)).toBe(1);
      expect((await bob.mls.decrypt(CONV, old)).ok).toBe(true);
    }
  });

  it("rejects a v2 share without its box, with a box that does not open, or whose payload says another version", async () => {
    const { sync, shares, alice, bob, bobPhone, old } = await scenario();
    const keys = () => alice.mls.exportEpochKeys(CONV, [0]);
    const shareKeys = { [DEV.b]: bob.mls.ownShareKey(), [PHONE]: bobPhone.mls.ownShareKey() };
    // A box of the phone served to the laptop, and a share whose payload claims format 1.
    const good = await alice.mls.encryptHistory(CONV, encodeHistoryPayload(CONV, bob.address, keys(), 2), shareKeys);
    shares.push({ id: "w1", to: bob.address, from_user: alice.address, from_device: DEV.a, epoch_from: 0, epoch_to: 0, ciphertext: good.content, created_at: "", v: 2, boxes: { [DEV.b]: good.boxes![PHONE]! } } as never);
    const v1Payload = await alice.mls.encryptHistory(CONV, encodeHistoryPayload(CONV, bob.address, keys()), shareKeys);
    shares.push({ id: "w2", to: bob.address, from_user: alice.address, from_device: DEV.a, epoch_from: 0, epoch_to: 0, ciphertext: v1Payload.content, created_at: "", v: 2, boxes: v1Payload.boxes } as never);
    // A v2 ciphertext presented as format 1 (no box): not the epoch key, rejected.
    shares.push({ id: "w3", to: bob.address, from_user: alice.address, from_device: DEV.a, epoch_from: 0, epoch_to: 0, ciphertext: good.content, created_at: "" });
    const log: string[] = [];
    expect(await sync(bob, undefined, log).receive(CONV)).toBe(0);
    expect(log.filter((l) => l === "share_rejected")).toHaveLength(3);
    expect(await bob.mls.decrypt(CONV, old)).toEqual({ ok: false, reason: "missing_key" });
    // The genuine share with the laptop's own box works.
    shares.push({ id: "w4", to: bob.address, from_user: alice.address, from_device: DEV.a, epoch_from: 0, epoch_to: 0, ciphertext: good.content, created_at: "", v: 2, boxes: { [DEV.b]: good.boxes![DEV.b]! } } as never);
    expect(await sync(bob).receive(CONV)).toBe(1);
  });

  it("restore shares follow the same rule", async () => {
    const { sync, shares, alice, bob } = await scenario();
    const result = await sync(alice, undefined, [], { shares2: () => true }).restore(CONV, bob.address, { kind: "text", windowStart: null });
    expect(result).toMatchObject({ sent: 3, skipped: false });
    expect(shares[0]).toMatchObject({ v: 2, to: bob.address });
    expect(await sync(bob).receive(CONV)).toBe(1);
  });
});

describe("after a key reset (ENCRYPTION.md §7b)", () => {
  it("shares automatically only epochs after the reset epoch", () => {
    const known = [0, 1, 2, 3, 4, 5, 6];
    expect(epochsSinceReset(known, 7, 3, 5)).toEqual([5, 6]);
    expect(epochsSinceReset(known, 7, 3, null)).toEqual([3, 4, 5, 6]);
    expect(epochsSinceReset(known, 7, 6, 2)).toEqual([6]);
    expect(epochsSinceReset(known, 7, null, 2)).toEqual([]);
  });

  /**
   * Alice writes in epoch 0, Bob joins (epoch 1) and reads along, Bob resets his key; Alice writes once more in epoch
   * 1, updates (epoch 2) and writes again; Bob's new device joins (epoch 3).
   */
  async function resetScenario() {
    const env = setup();
    const { device, post } = env;
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    const before = await post(alice, "vor Bob");
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    const there = await post(alice, "Bob liest mit");
    await new Promise((r) => setTimeout(r, 5));
    const resetAt = Date.now();
    await new Promise((r) => setTimeout(r, 5));
    const boundary = await post(alice, "nach dem Reset, gleiche Epoche");
    await alice.mls.selfUpdate(CONV);
    const after = await post(alice, "nach dem Reset");
    const bob2 = device("bob", "01J9ZK3G5M8Q2W4E6R8T0Y2VB2");
    await bob2.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    return { ...env, alice, bob2, resetAt, msgs: { before, there, boundary, after } };
  }

  it("with key_reset_at and min_epoch from the node: nothing before the reset reaches the reset member", async () => {
    const { sync, shares, pending, alice, bob2, resetAt, msgs } = await resetScenario();
    const iso = new Date(resetAt).toISOString();
    pending.push({ user: bob2.address, since: iso, key_reset_at: iso, min_epoch: 2 });
    await sync(alice).checkPending(CONV, { kind: "all" });
    expect(shares).toHaveLength(1);
    expect(shares[0]).toMatchObject({ to: bob2.address, epoch_from: 2, epoch_to: 2 });
    expect(await sync(bob2).receive(CONV)).toBe(1);
    expect((await bob2.mls.decrypt(CONV, msgs.after)).ok).toBe(true);
    for (const m of [msgs.before, msgs.there, msgs.boundary]) expect(await bob2.mls.decrypt(CONV, m)).toEqual({ ok: false, reason: "missing_key" });
  });

  it("with an older node: the keys document's reset and the newest message before it decide", async () => {
    const { sync, shares, pending, alice, bob2, resetAt } = await resetScenario();
    // The node reports the join as `since` and nothing about the reset.
    pending.push({ user: bob2.address, since: new Date(resetAt - 60_000).toISOString() });
    await sync(alice, undefined, [], { resetAt: async (a) => (a === bob2.address ? resetAt : null) }).checkPending(CONV, { kind: "all" });
    expect(shares).toHaveLength(1);
    expect(shares[0]).toMatchObject({ epoch_from: 2, epoch_to: 2 });
    // A reset from before the join is no reset of this membership: the policy applies.
    shares.length = 0;
    const s = sync(alice, undefined, [], { resetAt: async () => resetAt - 120_000 });
    pending.length = 0;
    pending.push({ user: bob2.address, since: new Date(resetAt - 60_000).toISOString() });
    await s.checkPending(CONV, { kind: "all" });
    expect(shares[0]).toMatchObject({ epoch_from: 0, epoch_to: 2 });
  });

  it("restores the requester's window after an approval and reports what this device lacks", async () => {
    const { device, sync, shares, alice, bob2, msgs } = await resetScenario();
    const s = sync(alice);
    // Policy `all`: everything from the first message's epoch.
    expect(await s.restorePlan(CONV, { kind: "text", windowStart: null })).toEqual({ epochs: [0, 1, 2], missing: 0, unknown: false });
    // since_join: from the oldest message after the join.
    const joined = Date.parse(new Date(Date.now() - 1).toISOString());
    expect((await s.restorePlan(CONV, { kind: "text", windowStart: joined + 60_000 })).epochs).toEqual([]);
    const result = await s.restore(CONV, bob2.address, { kind: "text", windowStart: null });
    expect(result).toMatchObject({ sent: 3, missing: 0, skipped: false });
    expect(shares[0]).toMatchObject({ to: bob2.address, epoch_from: 0, epoch_to: 2 });
    expect(await sync(bob2).receive(CONV)).toBe(3);
    for (const m of Object.values(msgs)) expect((await bob2.mls.decrypt(CONV, m)).ok).toBe(true);
    // A device that joined later lacks the older epochs: partial.
    const carol = device("carol", DEV.c);
    await carol.mls.ensureJoined(CONV, { canCreate: false });
    const plan = await sync(carol).restorePlan(CONV, { kind: "text", windowStart: null });
    expect(plan.missing).toBeGreaterThan(0);
    // Files channels: everything without a window start; with one only through their own listing.
    expect((await s.restorePlan(CONV, { kind: "files", windowStart: null })).epochs).toEqual([0, 1, 2]);
    expect(await s.restorePlan(CONV, { kind: "files", windowStart: 1 })).toEqual({ epochs: [], missing: 0, unknown: true });
    const withRecords = sync(alice, undefined, [], { firstEpoch: async () => 1 });
    expect((await withRecords.restorePlan(CONV, { kind: "files", windowStart: 1 })).epochs).toEqual([1, 2]);
    // Nothing is sent while no device of the requester is in the group.
    expect(await s.restore(CONV, "nobody@t.local", { kind: "text", windowStart: null })).toMatchObject({ sent: 0, skipped: true });
  });

  it("passes over a sample whose author device is gone with the old key and proves the key with the next message", async () => {
    const { device, sync, post, shares, net } = setup();
    const alice = device("alice", DEV.a);
    const bob = device("bob", DEV.b);
    await alice.mls.ensureJoined(CONV, { canCreate: true });
    await bob.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    // In the same epoch: Bob's greeting (preferred as a sample: not the sharer's) and Alice's message.
    const greeting = await post(bob, "Hallo von Bob");
    const forBob = await post(alice, "Für Bob vor dem Reset");
    expect(greeting.epoch).toBe(forBob.epoch);
    // Bob resets his key: the old device's attestation is gone, his new device cannot verify the greeting any more.
    net.node(DOMAIN).users.get("bob")!.devices.delete(DEV.b);
    const bob2 = device("bob", "01J9ZK3G5M8Q2W4E6R8T0Y2VB2");
    await bob2.mls.ensureJoined(CONV, { canCreate: false });
    await alice.mls.catchUp(CONV);
    expect((await sync(alice).restore(CONV, bob2.address, { kind: "text", windowStart: null })).sent).toBeGreaterThan(0);
    expect(shares).toHaveLength(1);
    const log: string[] = [];
    expect(await sync(bob2, undefined, log).receive(CONV)).toBeGreaterThan(0);
    expect(log).toEqual([]);
    expect(await bob2.mls.decrypt(CONV, forBob)).toEqual({ ok: true, content: { type: "text", body: "Für Bob vor dem Reset" } });
  });

  it("orders the samples of an epoch: other authors first, then the sharer's", () => {
    const msgs = [
      { author: "mallory@t.local", device_id: "D1", epoch: 4, content: "x", encrypted: true },
      { author: "alice@t.local", device_id: "D2", epoch: 4, content: "y", encrypted: true },
      { author: "bob@t.local", device_id: "D3", epoch: 4, content: "w", encrypted: true },
      { author: "alice@t.local", device_id: "D2", epoch: 5, content: "z", encrypted: true },
    ] as Message[];
    expect(pickSamples(msgs, 4, "mallory@t.local").map((m) => m.content)).toEqual(["y", "w", "x"]);
    expect(pickSamples(msgs, 6, "x")).toEqual([]);
  });
});
