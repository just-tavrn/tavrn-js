// SPDX-License-Identifier: MPL-2.0
// The tab coordination on its own (election, forwarding, timeouts, hand-over, fallback) with an in-memory lock
// manager and BroadcastChannel; the session manager on top of it is tested in tabs-mls.test.ts.
import { describe, expect, it } from "vitest";
import { TavrnApiError } from "@tavrn/sdk";
import { MlsError } from "../src/mls";
import { TabCoordinator, type TabHost } from "../src/tabs";
import { FakeBroadcast, FakeLocks, settle } from "./fake-tabs";

const NAME = "tavrn-mls|https://node.test|alice@node.test/DEV";

interface Tab {
  name: string;
  tabs: TabCoordinator;
  log: string[];
  /** Operations this tab served for others (or itself after a take-over). */
  served: string[];
  /** Makes `serve` hang (an owner that closes while working). */
  hang: boolean;
  fail?: unknown;
}

function setup() {
  const locks = new FakeLocks();
  const bc = new FakeBroadcast();
  const open = async (name: string, opts: { timeoutMs?: number } = {}): Promise<Tab> => {
    const tab = { name, log: [] as string[], served: [] as string[], hang: false } as Tab;
    const host: TabHost = {
      serve: async (method, args) => {
        tab.served.push(`${method}(${JSON.stringify(args)})`);
        if (tab.hang) return new Promise(() => undefined);
        if (tab.fail) throw tab.fail;
        return { by: name, method, args };
      },
      takeOver: async () => {
        tab.log.push("takeOver");
        await settle(1);
        tab.log.push("reloaded");
      },
      stale: () => tab.log.push("stale"),
      event: (e) => tab.log.push(`event:${JSON.stringify(e)}`),
    };
    const tabs = await TabCoordinator.open({ name: NAME, locks, channel: bc.channel, timeoutMs: opts.timeoutMs }, host);
    if (!tabs) throw new Error("no coordination");
    tab.tabs = tabs;
    return tab;
  };
  return { locks, bc, open };
}

describe("tab coordination", () => {
  it("the first tab wins the lock, later tabs wait for it and forward to the owner", async () => {
    const { locks, open } = setup();
    const a = await open("a");
    const b = await open("b");
    expect(a.tabs.owner).toBe(true);
    expect(a.tabs.ready).toBe(true);
    expect(b.tabs.owner).toBe(false);
    expect(b.tabs.ready).toBe(false);
    expect(locks.state(NAME)).toEqual({ held: true, waiting: 1 });
    expect(await b.tabs.call("encrypt", ["q", { body: "x" }])).toEqual({ by: "a", method: "encrypt", args: ["q", { body: "x" }] });
    expect(a.served).toEqual(['encrypt(["q",{"body":"x"}])']);
    // The owner runs its own calls itself.
    expect(await a.tabs.call("catchUp", ["q"])).toEqual({ by: "a", method: "catchUp", args: ["q"] });
    expect(b.served).toEqual([]);
  });

  it("carries binary arguments and errors with their type across the channel", async () => {
    const { open } = setup();
    const a = await open("a");
    const b = await open("b");
    const r = (await b.tabs.call("importHistoryKeys", ["q", [[3, new Uint8Array([1, 2, 3])]]])) as { args: [string, [number, Uint8Array][]] };
    expect(r.args[1][0]![1]).toEqual(new Uint8Array([1, 2, 3]));
    a.fail = new MlsError("not_joined");
    await expect(b.tabs.call("encrypt", ["q", {}])).rejects.toSatisfy((e: unknown) => e instanceof MlsError && e.code === "not_joined");
    a.fail = new TavrnApiError({ type: "x", title: "t", status: 403, detail: "no", code: "mls.forbidden" } as never);
    await expect(b.tabs.call("removeLeaves", ["q", []])).rejects.toSatisfy((e: unknown) => e instanceof TavrnApiError && e.code === "mls.forbidden" && e.status === 403);
    const odd = new Error("boom");
    odd.name = "bad_signature";
    a.fail = odd;
    await expect(b.tabs.call("catchUp", ["q"])).rejects.toSatisfy((e: unknown) => e instanceof Error && e.name === "bad_signature" && e.message === "boom");
  });

  it("times out when the owner does not answer", async () => {
    const { locks, open } = setup();
    // A tab that holds the lock but never answers (frozen, or an older client without coordination).
    void locks.request(NAME, {}, () => new Promise(() => undefined));
    await settle(1);
    const b = await open("b", { timeoutMs: 30 });
    expect(b.tabs.owner).toBe(false);
    await expect(b.tabs.call("catchUp", ["q"])).rejects.toSatisfy((e: unknown) => e instanceof MlsError && e.code === "owner_unavailable");
  });

  it("hand-over: the next waiter takes the lock, reloads the state first and runs its own call in flight once", async () => {
    const { open } = setup();
    const a = await open("a");
    const b = await open("b");
    a.hang = true;
    const pending = b.tabs.call("selfUpdate", ["q"]);
    await settle();
    expect(a.served).toEqual(['selfUpdate(["q"])']);
    a.tabs.close();
    expect(await pending).toEqual({ by: "b", method: "selfUpdate", args: ["q"] });
    expect(b.tabs.owner).toBe(true);
    expect(b.tabs.ready).toBe(true);
    // The state is reloaded before anything runs on the new owner.
    expect(b.log.slice(0, 2)).toEqual(["takeOver", "reloaded"]);
    expect(b.served).toEqual(['selfUpdate(["q"])']);
  });

  it("hand-over: other tabs send their calls in flight again to the new owner, once", async () => {
    const { open } = setup();
    const a = await open("a");
    const b = await open("b");
    const c = await open("c");
    a.hang = true;
    const pending = c.tabs.call("encrypt", ["q", { body: "hi" }]);
    await settle();
    a.tabs.close();
    expect(await pending).toEqual({ by: "b", method: "encrypt", args: ["q", { body: "hi" }] });
    expect(b.served).toEqual(['encrypt(["q",{"body":"hi"}])']);
    expect(c.served).toEqual([]);
  });

  it("a call that lost its owner twice fails instead of running a third time", async () => {
    const { open } = setup();
    const a = await open("a");
    const b = await open("b");
    const c = await open("c");
    a.hang = true;
    b.hang = true;
    const pending = c.tabs.call("ensureJoined", ["q", { canCreate: true }]);
    const outcome = pending.then(
      () => "resolved",
      (e: unknown) => (e instanceof MlsError ? e.code : "other"),
    );
    await settle();
    a.tabs.close();
    await settle(10);
    expect(b.served).toHaveLength(1);
    b.tabs.close();
    expect(await outcome).toBe("owner_unavailable");
    expect(c.tabs.owner).toBe(true);
    expect(c.served).toEqual([]);
  });

  it("a request that reaches the new owner twice is served once", async () => {
    const { bc, open } = setup();
    const a = await open("a");
    const b = await open("b");
    // A raw duplicate of the same request id (a re-send that crossed the owner announcement).
    const req = { v: 1, t: "req", id: "x:1", from: "x", method: "catchUp", args: ["q"] };
    const peer = bc.channel(NAME);
    peer.postMessage(req);
    peer.postMessage(req);
    await settle();
    expect(a.served).toEqual(['catchUp(["q"])']);
    expect(b.served).toEqual([]);
  });

  it("ignores malformed messages and calls of other versions", async () => {
    const { bc, open } = setup();
    const a = await open("a");
    const peer = bc.channel(NAME);
    for (const m of [null, 1, "req", { t: "req" }, { v: 2, t: "req", id: "y:1", from: "y", method: "catchUp", args: [] }, { v: 1, t: "req", id: 5, from: "y", method: "catchUp", args: [] }, { v: 1, t: "req", id: "y:2", from: "y", method: "catchUp", args: "q" }])
      peer.postMessage(m);
    await settle();
    expect(a.served).toEqual([]);
  });

  it("the owner tells the other tabs about writes and events; it does not hear them itself", async () => {
    const { open } = setup();
    const a = await open("a");
    const b = await open("b");
    const c = await open("c");
    a.tabs.notifyState();
    a.tabs.notifyEvent({ type: "epoch", conversationId: "q" });
    // Followers never send them.
    b.tabs.notifyState();
    b.tabs.notifyEvent({ type: "epoch", conversationId: "nope" });
    await settle();
    for (const t of [b, c]) expect(t.log).toEqual(["stale", 'event:{"type":"epoch","conversationId":"q"}']);
    expect(a.log).toEqual([]);
  });

  it("close releases the lock and fails the calls in flight", async () => {
    const { locks, open } = setup();
    const a = await open("a");
    a.hang = true;
    const b = await open("b");
    const pending = b.tabs.call("catchUp", ["q"]).catch((e: unknown) => (e instanceof MlsError ? e.code : "other"));
    await settle();
    b.tabs.close();
    expect(await pending).toBe("owner_unavailable");
    await expect(b.tabs.call("catchUp", ["q"])).rejects.toBeInstanceOf(MlsError);
    expect(locks.state(NAME)).toEqual({ held: true, waiting: 0 });
    a.tabs.close();
    await settle();
    expect(locks.state(NAME)).toEqual({ held: false, waiting: 0 });
  });

  it("falls back to no coordination without Web Locks or BroadcastChannel", async () => {
    const host: TabHost = { serve: async () => null, takeOver: async () => undefined, stale: () => undefined, event: () => undefined };
    const bc = new FakeBroadcast();
    expect(await TabCoordinator.open({ name: NAME, locks: null, channel: bc.channel }, host)).toBeNull();
    expect(await TabCoordinator.open({ name: NAME, locks: new FakeLocks(), channel: null }, host)).toBeNull();
    const throwing = { request: () => Promise.reject(new Error("SecurityError")) };
    expect(await TabCoordinator.open({ name: NAME, locks: throwing, channel: bc.channel }, host)).toBeNull();
    // Defaults come from globalThis (Node.js has BroadcastChannel; no `navigator.locks` here means no coordination).
    const g = globalThis as { navigator?: { locks?: unknown } };
    if (!g.navigator?.locks) expect(await TabCoordinator.open({ name: NAME }, host)).toBeNull();
  });
});
