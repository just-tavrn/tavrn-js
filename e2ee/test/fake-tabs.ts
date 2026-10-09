// SPDX-License-Identifier: MPL-2.0
// In-memory stand-ins for the browser APIs of the tab coordination: a Web Locks manager (exclusive locks, a FIFO
// queue of waiters, `ifAvailable` and `signal`) and BroadcastChannel (structured clone, asynchronous delivery in
// order to every other channel of the same name).
import type { TabChannel, TabLockManager } from "../src/tabs";

interface Waiter {
  callback: (lock: unknown) => Promise<unknown>;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
}

function abortError(): Error {
  const e = new Error("The request was aborted");
  e.name = "AbortError";
  return e;
}

export class FakeLocks implements TabLockManager {
  private readonly held = new Set<string>();
  private readonly queues = new Map<string, Waiter[]>();
  /** Requests made (name and mode), for assertions. */
  readonly requests: { name: string; ifAvailable: boolean }[] = [];

  request(name: string, options: { ifAvailable?: boolean; signal?: AbortSignal }, callback: (lock: unknown) => Promise<unknown>): Promise<unknown> {
    this.requests.push({ name, ifAvailable: !!options.ifAvailable });
    return new Promise((resolve, reject) => {
      if (options.signal?.aborted) return reject(abortError());
      const queue = this.queues.get(name) ?? [];
      this.queues.set(name, queue);
      if (!this.held.has(name) && queue.length === 0) return this.grant(name, { callback, resolve, reject });
      if (options.ifAvailable) {
        Promise.resolve()
          .then(() => callback(null))
          .then(resolve, reject);
        return;
      }
      const waiter: Waiter = { callback, resolve, reject };
      queue.push(waiter);
      options.signal?.addEventListener("abort", () => {
        const i = queue.indexOf(waiter);
        if (i >= 0) queue.splice(i, 1);
        reject(abortError());
      });
    });
  }

  /** Whether somebody holds the lock `name`, and how many wait for it. */
  state(name: string): { held: boolean; waiting: number } {
    return { held: this.held.has(name), waiting: this.queues.get(name)?.length ?? 0 };
  }

  private grant(name: string, w: Waiter) {
    this.held.add(name);
    Promise.resolve()
      .then(() => w.callback({ name }))
      .then(w.resolve, w.reject)
      .finally(() => {
        this.held.delete(name);
        const next = this.queues.get(name)?.shift();
        if (next) this.grant(name, next);
      });
  }
}

/** One BroadcastChannel "origin": channels of the same name reach each other. */
export class FakeBroadcast {
  private readonly open = new Map<string, Set<FakeChannel>>();
  /** Every message posted (cloned), for assertions. */
  readonly posted: { name: string; data: unknown }[] = [];

  channel = (name: string): TabChannel => {
    const c = new FakeChannel(name, this);
    const set = this.open.get(name) ?? new Set<FakeChannel>();
    set.add(c);
    this.open.set(name, set);
    return c;
  };

  /** @internal */
  deliver(from: FakeChannel, data: unknown) {
    const cloned = structuredClone(data);
    this.posted.push({ name: from.name, data: cloned });
    for (const c of this.open.get(from.name) ?? []) {
      if (c === from) continue;
      // A task per receiver: messages arrive in the order they were posted.
      setTimeout(() => {
        if (!c.closed) c.onmessage?.({ data: structuredClone(cloned) });
      }, 0);
    }
  }

  /** @internal */
  drop(c: FakeChannel) {
    this.open.get(c.name)?.delete(c);
  }
}

class FakeChannel implements TabChannel {
  onmessage: ((e: { data: unknown }) => void) | null = null;
  closed = false;

  constructor(
    readonly name: string,
    private readonly hub: FakeBroadcast,
  ) {}

  postMessage(data: unknown): void {
    if (this.closed) throw new Error("InvalidStateError: channel closed");
    this.hub.deliver(this, data);
  }

  close(): void {
    this.closed = true;
    this.hub.drop(this);
  }
}

/** Resolves after pending timers and microtasks (several rounds of channel messages). */
export async function settle(rounds = 5): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setTimeout(r, 0));
}
