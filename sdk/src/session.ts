// SPDX-License-Identifier: Apache-2.0
/**
 * Token refresh for one session (PROTOCOL.md §5b): one refresh in flight per session, coordinated across
 * contexts that share the session (browser tabs) through a named lock and shared storage, retries on network
 * errors, and a definitive end only when the node refuses the refresh token itself.
 *
 * The node rotates refresh tokens on every use; a token presented again after its 30-second grace revokes the
 * whole session. Without coordination, parallel 401s (or a second tab with the same tokens) refresh with the same
 * token, and the late one logs everybody out. With this helper every context waits for the one refresh in
 * flight and adopts the tokens another context stored meanwhile.
 */
import { TavrnApiError } from "./errors";
import type { TokenPair } from "./generated/types.gen";

/** The subset of the Web Locks API (`navigator.locks`) this helper needs. */
export interface LockManagerLike {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
}

/** Tokens as another context stored them; `refresh: null` = signed out there. */
export interface SharedTokens {
  access: string | null;
  refresh: string | null;
}

export interface RefresherOptions {
  /** Lock name shared by every context that uses this session, e.g. `tavrn-refresh:<node domain>`. */
  lockName: string;
  /** The refresh token this context holds right now. */
  current(): string | null;
  /** The newest tokens in the storage all contexts share (re-read on every call); omit without shared storage. */
  shared?(): SharedTokens | null;
  /** Takes over tokens another context stored (no request). */
  adopt?(tokens: { access: string; refresh: string }): void;
  /** Calls the node's refresh route with `refreshToken`. */
  call(refreshToken: string): Promise<TokenPair>;
  /** Stores the new pair (memory and shared storage) before the lock is released. */
  store(pair: TokenPair): void;
  /** The node refused the refresh token itself (`400`/`401`): the session is over. */
  onInvalid(): void;
  /** Lock implementation; default `navigator.locks` where available, otherwise none (the node's grace covers it). */
  locks?: LockManagerLike | null;
  /** Waits between attempts after network errors, `5xx` and `429` (default 500 ms, then 1.5 s). */
  retryDelaysMs?: number[];
  /** Timer (tests). */
  sleep?(ms: number): Promise<void>;
}

/** `true` for answers that end the session: the node refused the refresh token itself. */
export function isDefinitiveRefreshError(e: unknown): boolean {
  return e instanceof TavrnApiError && (e.status === 400 || e.status === 401);
}

function retryable(e: unknown): boolean {
  if (!(e instanceof TavrnApiError)) return true;
  return e.status === 0 || e.status === 429 || e.status >= 500;
}

function defaultLocks(): LockManagerLike | null {
  const nav = (globalThis as { navigator?: { locks?: { request?: unknown } } }).navigator;
  const locks = nav?.locks;
  if (!locks || typeof locks.request !== "function") return null;
  return { request: (name, cb) => (locks as unknown as LockManagerLike).request(name, cb) };
}

/**
 * A refresh function for `ApiOptions.refreshToken` and `SocketOptions.refreshToken`: resolves to the new access
 * token, to `null` when there is no session or the node refused the refresh token (after `onInvalid`), and throws
 * the last network error when the node could not be reached (the caller keeps its session and retries later).
 */
export function createRefresher(opts: RefresherOptions): () => Promise<string | null> {
  const locks = opts.locks === undefined ? defaultLocks() : opts.locks;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const delays = opts.retryDelaysMs ?? [500, 1500];
  let inflight: Promise<string | null> | null = null;

  /** Tokens another context stored after rotating `presented`, if any. */
  const newerElsewhere = (presented: string | null): { access: string; refresh: string } | "signed_out" | null => {
    const s = opts.shared?.();
    if (!s) return null;
    if (!s.refresh) return "signed_out";
    if (s.refresh !== presented && s.access) return { access: s.access, refresh: s.refresh };
    return null;
  };

  const refreshLocked = async (presented: string | null): Promise<string | null> => {
    const elsewhere = newerElsewhere(presented);
    if (elsewhere === "signed_out") {
      opts.onInvalid();
      return null;
    }
    if (elsewhere) {
      opts.adopt?.(elsewhere);
      return elsewhere.access;
    }
    if (!presented) return null;
    for (let attempt = 0; ; attempt++) {
      try {
        const pair = await opts.call(presented);
        opts.store(pair);
        return pair.access_token;
      } catch (e) {
        if (isDefinitiveRefreshError(e)) {
          // A context without the lock may have rotated the token meanwhile.
          const later = newerElsewhere(presented);
          if (later && later !== "signed_out") {
            opts.adopt?.(later);
            return later.access;
          }
          opts.onInvalid();
          return null;
        }
        if (!retryable(e) || attempt >= delays.length) throw e;
        await sleep(delays[attempt] ?? 1000);
      }
    }
  };

  return () => {
    if (inflight) return inflight;
    const presented = opts.current();
    const run = () => refreshLocked(presented);
    inflight = (locks ? locks.request(opts.lockName, run) : run()).finally(() => {
      inflight = null;
    });
    return inflight;
  };
}
