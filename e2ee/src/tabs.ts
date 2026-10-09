// SPDX-License-Identifier: MPL-2.0
/**
 * Coordination of one MLS state between the tabs of a browser profile (they share one IndexedDB store).
 *
 * One tab **owns** the state: it holds a Web Lock (`navigator.locks`) named per node and account, runs every
 * state-changing operation and alone writes the client state. The other tabs keep a read-only copy (loaded from the
 * store) for synchronous reads and decryption, and **forward** their state-changing operations to the owner over a
 * BroadcastChannel of the same name (request and response with ids, a timeout per request). The owner announces
 * every write (`state`: copies reload before they read again) and the events the views need (`event`).
 *
 * **Hand-over:** when the owner tab closes (or signs out) the browser releases its lock and the next waiting tab gets
 * it; that tab reloads the state from the store before it runs anything, then announces itself (`owner`). Requests
 * in flight are sent once more, to the new owner (a tab that becomes the owner runs its own ones itself); a request
 * that loses its owner a second time fails with `MlsError("owner_unavailable")`, like one that gets no answer
 * within the timeout. Every forwarded operation can run twice without harm (joins and catch-ups are idempotent, a
 * second commit is just one more epoch, an encryption whose result never arrived was never sent).
 *
 * Without Web Locks or BroadcastChannel (or in a single process such as a bot) there is no coordination: the
 * manager works alone, as before (a second tab may then overwrite the state and rejoin after an invalid commit).
 */
import { TavrnApiError, type ProblemDetails } from "@tavrn/sdk";
import { MlsError } from "./mls";

/** The subset of the Web Locks API (`navigator.locks`) the election needs. */
export interface TabLockManager {
  request(name: string, options: { ifAvailable?: boolean; signal?: AbortSignal }, callback: (lock: unknown) => Promise<unknown>): Promise<unknown>;
}

/** The subset of `BroadcastChannel` the forwarding needs. */
export interface TabChannel {
  postMessage(message: unknown): void;
  onmessage: ((e: { data: unknown }) => void) | null;
  close(): void;
}

export interface TabOptions {
  /**
   * Lock and channel name, the same in every tab that shares the state: per node and account (and device), e.g.
   * `tavrn-mls|<home node origin>|<address>/<device id>`.
   */
  name: string;
  /** Default `navigator.locks` where available; null (or none available) = no coordination. */
  locks?: TabLockManager | null;
  /** Default `new BroadcastChannel(name)` where available; null (or none available) = no coordination. */
  channel?: ((name: string) => TabChannel) | null;
  /** How long a forwarded operation may take before it fails with `owner_unavailable` (default 30 s). */
  timeoutMs?: number;
}

/** What the coordination needs from the tab (implemented by `openMlsManager`). */
export interface TabHost {
  /** Runs an operation in this tab, which owns the state (its own forwarded calls, or another tab's). */
  serve(method: string, args: unknown[]): Promise<unknown>;
  /** This tab got the lock after another owner left: load the stored state before anything runs here. */
  takeOver(): Promise<void>;
  /** The owner wrote the state: reload the copy before reading it again. */
  stale(): void;
  /** An event of the owner's manager, for this tab's views. */
  event(e: unknown): void;
}

export const TAB_TIMEOUT_MS = 30_000;
/** Request ids a new owner remembers to serve a request only once (a re-send may cross its announcement). */
const SERVED_WINDOW = 1024;

interface WireError {
  name: string;
  message: string;
  code?: string;
  problem?: ProblemDetails;
}

type Message =
  | { v: 1; t: "req"; id: string; from: string; method: string; args: unknown[] }
  | { v: 1; t: "res"; id: string; to: string; ok: true; value: unknown }
  | { v: 1; t: "res"; id: string; to: string; ok: false; error: WireError }
  | { v: 1; t: "owner"; from: string }
  | { v: 1; t: "state"; from: string }
  | { v: 1; t: "event"; from: string; event: unknown };

interface Pending {
  id: string;
  method: string;
  args: unknown[];
  resolve(v: unknown): void;
  reject(e: unknown): void;
  timer: ReturnType<typeof setTimeout> | null;
  /** Sent once more after its owner left (or run here after this tab took over). */
  retried: boolean;
}

function defaultLocks(): TabLockManager | null {
  const locks = (globalThis as { navigator?: { locks?: TabLockManager } }).navigator?.locks;
  return locks && typeof locks.request === "function" ? locks : null;
}

function defaultChannel(): ((name: string) => TabChannel) | null {
  const BC = (globalThis as { BroadcastChannel?: new (name: string) => TabChannel }).BroadcastChannel;
  return typeof BC === "function" ? (name) => new BC(name) : null;
}

function randomId(): string {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

const unavailable = () => new MlsError("owner_unavailable");

function toWire(e: unknown): WireError {
  if (e instanceof TavrnApiError) return { name: "TavrnApiError", message: e.message, problem: JSON.parse(JSON.stringify(e.problem)) as ProblemDetails };
  if (e instanceof MlsError) return { name: "MlsError", message: e.message, code: e.code };
  if (e instanceof Error) return { name: e.name, message: e.message };
  return { name: "Error", message: String(e) };
}

function fromWire(w: WireError): Error {
  if (w.name === "TavrnApiError" && w.problem) return new TavrnApiError(w.problem);
  if (w.name === "MlsError" && w.code) return new MlsError(w.code as MlsError["code"]);
  const e = new Error(w.message);
  e.name = w.name;
  return e;
}

function isMessage(m: unknown): m is Message {
  if (!m || typeof m !== "object") return false;
  const o = m as Record<string, unknown>;
  if (o.v !== 1) return false;
  switch (o.t) {
    case "req":
      return typeof o.id === "string" && typeof o.from === "string" && typeof o.method === "string" && Array.isArray(o.args);
    case "res":
      return typeof o.id === "string" && typeof o.to === "string" && typeof o.ok === "boolean" && (o.ok || (!!o.error && typeof o.error === "object"));
    case "owner":
    case "state":
      return typeof o.from === "string";
    case "event":
      return typeof o.from === "string" && "event" in o;
    default:
      return false;
  }
}

export class TabCoordinator {
  private readonly id = randomId();
  private seq = 0;
  private holds = false;
  private serving = false;
  private closed = false;
  /** Resolves when this tab may run operations after a take-over (null while it is not taking over). */
  private takingOver: Promise<void> | null = null;
  private readonly pending = new Map<string, Pending>();
  private readonly served = new Set<string>();
  private readonly abort = new AbortController();
  private release: () => void = () => undefined;
  private readonly held = new Promise<void>((r) => (this.release = r));

  private constructor(
    private readonly opts: { name: string; locks: TabLockManager; timeoutMs: number },
    private readonly channel: TabChannel,
    private readonly host: TabHost,
  ) {
    channel.onmessage = (e) => this.receive(e.data);
  }

  /**
   * Joins the coordination of `opts.name`: resolves once it is known whether this tab owns the state right now.
   * Null when the browser lacks Web Locks or BroadcastChannel (the caller works alone, as before).
   */
  static async open(opts: TabOptions, host: TabHost): Promise<TabCoordinator | null> {
    const locks = opts.locks === undefined ? defaultLocks() : opts.locks;
    const makeChannel = opts.channel === undefined ? defaultChannel() : opts.channel;
    if (!locks || !makeChannel) return null;
    let channel: TabChannel;
    try {
      channel = makeChannel(opts.name);
    } catch {
      return null;
    }
    const tabs = new TabCoordinator({ name: opts.name, locks, timeoutMs: opts.timeoutMs ?? TAB_TIMEOUT_MS }, channel, host);
    try {
      await tabs.elect();
    } catch {
      tabs.close();
      return null;
    }
    return tabs;
  }

  /** Whether this tab holds the lock (it may still be reloading the state after a take-over). */
  get owner(): boolean {
    return this.holds && !this.closed;
  }

  /** Whether this tab runs operations itself right now: it owns the state and has loaded it. */
  get ready(): boolean {
    return this.serving && !this.closed;
  }

  private elect(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.opts.locks
        .request(this.opts.name, { ifAvailable: true }, async (lock) => {
          if (!lock) {
            // Another tab owns the state: wait for the lock (hand-over) and forward until then.
            this.wait();
            resolve();
            return;
          }
          this.holds = true;
          this.serving = true;
          resolve();
          await this.held;
        })
        .catch(reject);
    });
  }

  /** Queues for the lock: granted when the owner tab closes. */
  private wait() {
    this.opts.locks
      .request(this.opts.name, { signal: this.abort.signal }, async () => {
        if (this.closed) return;
        this.holds = true;
        this.takingOver = this.host.takeOver();
        try {
          await this.takingOver;
        } catch {
          // The state cannot be loaded here (locked meanwhile): leave the lock to the next tab.
          this.close();
          return;
        }
        this.takingOver = null;
        this.serving = true;
        this.post({ v: 1, t: "owner", from: this.id });
        this.retryPending(true);
        await this.held;
      })
      .catch(() => undefined);
  }

  /**
   * Runs `method` in the owner tab: here when this tab owns the state (after a take-over has loaded it), otherwise
   * forwarded. Fails with `MlsError("owner_unavailable")` without an answer in time or after losing two owners.
   */
  call(method: string, args: unknown[]): Promise<unknown> {
    if (this.closed) return Promise.reject(unavailable());
    if (this.serving) return this.serve(method, args);
    if (this.holds && this.takingOver) return this.takingOver.then(() => this.serve(method, args));
    return new Promise((resolve, reject) => {
      const p: Pending = { id: `${this.id}:${++this.seq}`, method, args, resolve, reject, timer: null, retried: false };
      this.pending.set(p.id, p);
      this.send(p);
    });
  }

  /** Owner: the stored state changed (the other tabs reload their copies). */
  notifyState(): void {
    if (this.ready) this.post({ v: 1, t: "state", from: this.id });
  }

  /** Owner: an event the other tabs' views need. */
  notifyEvent(event: unknown): void {
    if (this.ready) this.post({ v: 1, t: "event", from: this.id, event });
  }

  /** Leaves the coordination: releases the lock (the next tab takes over) and fails the calls in flight. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.release();
    this.abort.abort();
    for (const p of this.pending.values()) this.settle(p, unavailable(), false);
    this.channel.onmessage = null;
    try {
      this.channel.close();
    } catch {
      /* already closed */
    }
  }

  private serve(method: string, args: unknown[]): Promise<unknown> {
    return Promise.resolve().then(() => this.host.serve(method, args));
  }

  /** Answers a request; a result the channel cannot clone becomes an error (the caller does not wait for nothing). */
  private respond(id: string, to: string, value: unknown) {
    if (this.closed) return;
    try {
      this.channel.postMessage({ v: 1, t: "res", id, to, ok: true, value } satisfies Message);
    } catch (e) {
      this.post({ v: 1, t: "res", id, to, ok: false, error: toWire(e) });
    }
  }

  private post(m: Message) {
    if (this.closed) return;
    try {
      this.channel.postMessage(m);
    } catch {
      /* closed channel: the timeouts take care of the calls */
    }
  }

  private send(p: Pending) {
    if (p.timer) clearTimeout(p.timer);
    p.timer = setTimeout(() => this.settle(p, unavailable(), false), this.opts.timeoutMs);
    this.post({ v: 1, t: "req", id: p.id, from: this.id, method: p.method, args: p.args });
  }

  private settle(p: Pending, value: unknown, ok: boolean) {
    if (!this.pending.delete(p.id)) return;
    if (p.timer) clearTimeout(p.timer);
    if (ok) p.resolve(value);
    else p.reject(value);
  }

  /** After a hand-over: every call in flight once more (here when this tab is the new owner); twice fails. */
  private retryPending(here: boolean) {
    for (const p of [...this.pending.values()]) {
      if (p.retried) {
        this.settle(p, unavailable(), false);
        continue;
      }
      p.retried = true;
      if (here) {
        this.pending.delete(p.id);
        if (p.timer) clearTimeout(p.timer);
        this.serve(p.method, p.args).then(p.resolve, p.reject);
      } else {
        this.send(p);
      }
    }
  }

  private receive(data: unknown) {
    if (this.closed || !isMessage(data)) return;
    switch (data.t) {
      case "req":
        if (!this.serving || this.served.has(data.id)) return;
        this.served.add(data.id);
        if (this.served.size > SERVED_WINDOW) this.served.delete(this.served.values().next().value as string);
        this.serve(data.method, data.args).then(
          (value) => this.respond(data.id, data.from, value),
          (e: unknown) => this.post({ v: 1, t: "res", id: data.id, to: data.from, ok: false, error: toWire(e) }),
        );
        return;
      case "res": {
        if (data.to !== this.id) return;
        const p = this.pending.get(data.id);
        if (!p) return;
        if (data.ok) this.settle(p, data.value, true);
        else this.settle(p, fromWire(data.error), false);
        return;
      }
      case "owner":
        if (!this.holds) this.retryPending(false);
        return;
      case "state":
        if (!this.holds) this.host.stale();
        return;
      case "event":
        if (!this.holds) this.host.event(data.event);
        return;
    }
  }
}
