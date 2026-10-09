// SPDX-License-Identifier: MPL-2.0
// Several tabs of one browser profile on one MLS state: every tab opens the session manager on the same key store
// (one IndexedDB), one tab owns the state (Web Locks), the others forward their state-changing calls to it
// (BroadcastChannel) and read from a copy that follows the owner's writes. In-memory nodes, lock manager and channel.
import { beforeAll, describe, expect, it } from "vitest";
import { RecoveryKey } from "@tavrn/crypto";
import {
  CLIENT_STATE,
  META,
  KEY_PACKAGE_BATCH,
  MemoryKeyStore,
  ensureCrypto,
  ensureDevice,
  openMlsManager,
  qualify,
  setupAccount,
  type KeyStore,
  type MlsEvent,
  type MlsManager,
} from "../src/index";
import { Network } from "./fake-node";
import { FakeBroadcast, FakeLocks, settle } from "./fake-tabs";

const DOMAIN = "t.local";
const CONV = qualify(DOMAIN, "01J9ZK3G5M8Q2W4E6R8T0Y2V00");
const DEV = { a: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1", b: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1" };

beforeAll(() => ensureCrypto());

interface Account {
  address: string;
  deviceId: string;
  /** The browser profile's storage, shared by all tabs. */
  store: KeyStore;
}

interface Tab {
  mls: MlsManager;
  events: MlsEvent[];
  /** Names of the secrets this tab wrote. */
  writes: string[];
  address: string;
  deviceId: string;
}

async function account(net: Network, username: string, deviceId: string): Promise<Account> {
  const address = `${username}@${DOMAIN}`;
  const store = new MemoryKeyStore();
  await setupAccount({ api: net.node(DOMAIN).accountApi(username), username, address, deviceId, store }, RecoveryKey.generate());
  return { address, deviceId, store };
}

/** A tab's own view of the shared store: everything goes to the shared data, writes are recorded. */
function tabStore(shared: KeyStore, writes: string[]): KeyStore {
  return new Proxy(shared, {
    get(target, prop) {
      if (prop === "putSecret")
        return (name: string, value: Uint8Array) => {
          writes.push(name);
          return target.putSecret(name, value);
        };
      const v = Reflect.get(target, prop) as unknown;
      return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  });
}

interface Browser {
  locks: FakeLocks | null;
  bc: FakeBroadcast;
}

const browser = (): Browser => ({ locks: new FakeLocks(), bc: new FakeBroadcast() });

async function openTab(net: Network, acc: Account, b: Browser | null): Promise<Tab> {
  const events: MlsEvent[] = [];
  const writes: string[] = [];
  const mls = await openMlsManager(tabStore(acc.store, writes), {
    api: net.api(acc.address, acc.deviceId),
    address: acc.address,
    deviceId: acc.deviceId,
    homeDomain: DOMAIN,
    onEvent: (e) => events.push(e),
    backupDelayMs: 60_000,
    ...(b ? { tabs: { name: `tavrn-mls|https://${DOMAIN}|${acc.address}/${acc.deviceId}`, locks: b.locks, channel: b.bc.channel, timeoutMs: 5_000 } } : {}),
  });
  if (!mls) throw new Error("no MLS client");
  return { mls, events, writes, address: acc.address, deviceId: acc.deviceId };
}

async function send(t: Tab, body: string, id: string) {
  const { content, epoch } = await t.mls.encrypt(CONV, { type: "text", body });
  return { id, author: t.address, device_id: t.deviceId, epoch, content };
}

const text = (body: string) => ({ ok: true, content: { type: "text", body } });
const stateWrites = (t: Tab) => t.writes.filter((n) => n === CLIENT_STATE || n === META);
const rejoins = (...tabs: Tab[]) => tabs.flatMap((t) => t.events.filter((e) => e.type === "rejoined"));

/** Alice with two tabs of one browser and Bob in his own browser; tab 2 opens the DM first. */
async function dm() {
  const net = new Network();
  const alice = await account(net, "alice", DEV.a);
  const bob = await openTab(net, await account(net, "bob", DEV.b), null);
  const b = browser();
  const t1 = await openTab(net, alice, b);
  const t2 = await openTab(net, alice, b);
  expect(await t2.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
  expect(await t2.mls.addMissingDevices(CONV, [alice.address, bob.address])).toEqual([]);
  expect(await bob.mls.processWelcomes(DOMAIN)).toEqual([CONV]);
  expect(await t1.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
  return { net, alice, bob, b, t1, t2 };
}

describe("MLS state shared by the tabs of one browser", () => {
  it("two tabs of one device send and read in a DM: one leaf, no rejoin, only the owner writes the state", async () => {
    const { alice, bob, t1, t2 } = await dm();
    expect(t1.mls.epoch(CONV)).toBe(1);
    expect(t2.mls.epoch(CONV)).toBe(1);
    const m1 = await send(t1, "aus Tab 1", "m1");
    const m2 = await send(t2, "aus Tab 2", "m2");
    expect(await bob.mls.decrypt(CONV, m1)).toEqual(text("aus Tab 1"));
    expect(await bob.mls.decrypt(CONV, m2)).toEqual(text("aus Tab 2"));
    const m3 = await send(bob, "an beide Tabs", "m3");
    for (const t of [t1, t2]) expect(await t.mls.decrypt(CONV, m3)).toEqual(text("an beide Tabs"));
    expect(await t1.mls.decrypt(CONV, m2)).toEqual(text("aus Tab 2"));
    expect(await t2.mls.decrypt(CONV, m1)).toEqual(text("aus Tab 1"));
    // One leaf for Alice's device, nothing a ghost check would flag.
    expect(t2.mls.roster(CONV).filter((i) => i.startsWith(alice.address))).toEqual([`${alice.address}/${DEV.a}`]);
    expect(await bob.mls.ghostCheck(CONV, [alice.address, bob.address])).toEqual([]);
    expect(rejoins(t1, t2, bob)).toEqual([]);
    // The follower never wrote the client state or the bookkeeping; the owner did.
    expect(stateWrites(t2)).toEqual([]);
    expect(t1.writes).toContain(CLIENT_STATE);
    // The follower's views heard of the epochs the owner went through.
    expect(t2.events).toContainEqual({ type: "epoch", conversationId: CONV });
    // The Adds of the forwarded call are reported once, in the owner tab (it shares the history).
    expect(t1.events.filter((e) => e.type === "added")).toHaveLength(1);
    expect(t2.events.filter((e) => e.type === "added")).toHaveLength(0);
  });

  it("a follower follows commits of others and its own forwarded commits, and decrypts newer epochs", async () => {
    const { bob, t1, t2 } = await dm();
    expect(await bob.mls.selfUpdate(CONV)).toBe(true);
    const fresh = await send(bob, "neue Epoche", "m4");
    // Tab 2 decrypts without a catch-up first: the missing key is fetched through the owner.
    expect(await t2.mls.decrypt(CONV, fresh)).toEqual(text("neue Epoche"));
    expect(t2.mls.epoch(CONV)).toBe(2);
    expect(await t2.mls.selfUpdate(CONV)).toBe(true);
    expect(t2.mls.epoch(CONV)).toBe(3);
    expect(t1.mls.epoch(CONV)).toBe(3);
    // Synchronous reads of the follower see the new epoch at once (voice keys after the self update of a voice join).
    expect(t2.mls.voiceKey(CONV)).toEqual(t1.mls.voiceKey(CONV));
    await bob.mls.catchUp(CONV);
    expect(await bob.mls.decrypt(CONV, await send(t2, "nach dem Update", "m5"))).toEqual(text("nach dem Update"));
    expect(rejoins(t1, t2, bob)).toEqual([]);
    expect(stateWrites(t2)).toEqual([]);
  });

  it("hand-over: when the owner tab closes the next tab takes over from the stored state", async () => {
    const { net, alice, bob, b, t1, t2 } = await dm();
    const t3 = await openTab(net, alice, b);
    t1.mls.dispose();
    await settle(10);
    expect(await t2.mls.selfUpdate(CONV)).toBe(true);
    // Tab 2 owns the state now and writes it; tab 3 forwards to tab 2.
    expect(stateWrites(t2)).toContain(CLIENT_STATE);
    const m = await send(t3, "aus Tab 3", "m6");
    expect(m.epoch).toBe(2);
    await bob.mls.catchUp(CONV);
    expect(await bob.mls.decrypt(CONV, m)).toEqual(text("aus Tab 3"));
    expect(await t3.mls.decrypt(CONV, await send(bob, "zurück", "m7"))).toEqual(text("zurück"));
    expect(stateWrites(t3)).toEqual([]);
    expect(rejoins(t1, t2, t3, bob)).toEqual([]);
    expect(await bob.mls.ghostCheck(CONV, [alice.address, bob.address])).toEqual([]);
  });

  it("a follower's channels with webhooks get their inbox keys published by the owner", async () => {
    const { net, t1, t2 } = await dm();
    t2.mls.setInboxWanted(CONV, true);
    await settle(10);
    // The owner commits next (a rotation, a join of another device): it publishes the new epoch's key too.
    expect(await t1.mls.selfUpdate(CONV)).toBe(true);
    await settle(10);
    expect(net.node(DOMAIN).inboxPublications.map((p) => p.epoch)).toEqual([1, 2]);
  });

  it("KeyPackages a follower tab tops up are created in the owner's state (their Welcomes can be processed)", async () => {
    const net = new Network();
    const alice = await account(net, "alice", DEV.a);
    const bob = await openTab(net, await account(net, "bob", DEV.b), null);
    const b = browser();
    const t1 = await openTab(net, alice, b);
    const t2 = await openTab(net, alice, b);
    const node = net.node(DOMAIN);
    node.users.get("alice")!.kps.set(DEV.a, []);
    const writes: string[] = [];
    await ensureDevice({ api: node.accountApi("alice"), username: "alice", address: alice.address, deviceId: DEV.a, store: tabStore(alice.store, writes), keyPackages: (n) => t2.mls.createKeyPackages(n) });
    expect(node.users.get("alice")!.kps.get(DEV.a)).toHaveLength(KEY_PACKAGE_BATCH);
    expect(writes.filter((n) => n === CLIENT_STATE)).toEqual([]);
    expect(stateWrites(t2)).toEqual([]);
    // Bob opens a DM and adds Alice's device with one of them: the owner tab processes the Welcome.
    expect(await bob.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    expect(await bob.mls.addMissingDevices(CONV, [bob.address, alice.address])).toEqual([]);
    expect(await t2.mls.processWelcomes(DOMAIN)).toEqual([CONV]);
    expect(t1.mls.hasGroup(CONV)).toBe(true);
    expect(await t2.mls.decrypt(CONV, await send(bob, "willkommen", "m1"))).toEqual(text("willkommen"));
  });

  it("without Web Locks every tab works alone, as before", async () => {
    const net = new Network();
    const alice = await account(net, "alice", DEV.a);
    const t1 = await openTab(net, alice, { locks: null, bc: new FakeBroadcast() });
    expect(await t1.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    expect((await send(t1, "allein", "m1")).epoch).toBe(0);
    expect(t1.writes).toContain(CLIENT_STATE);
  });

  it("control: without coordination a second tab's stale state throws the first tab out of the conversation", async () => {
    const net = new Network();
    const alice = await account(net, "alice", DEV.a);
    const bob = await openTab(net, await account(net, "bob", DEV.b), null);
    const t1 = await openTab(net, alice, null);
    const t2 = await openTab(net, alice, null);
    expect(await t1.mls.ensureJoined(CONV, { canCreate: true })).toBe("joined");
    expect(await t1.mls.addMissingDevices(CONV, [alice.address, bob.address])).toEqual([]);
    await bob.mls.processWelcomes(DOMAIN);
    // Tab 2 loaded the state before the group existed: it joins once more with the same device (an external
    // commit replaces the leaf), and tab 1 finds itself removed on its next catch-up.
    await t2.mls.ensureJoined(CONV, { canCreate: true });
    await t1.mls.catchUp(CONV);
    expect(t1.events.filter((e) => e.type === "removed" || e.type === "rejoined")).not.toEqual([]);
    expect(t1.mls.hasGroup(CONV)).toBe(false);
  });
});
