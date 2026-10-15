// SPDX-License-Identifier: Apache-2.0
/**
 * Rate limits of app tokens (APPLICATIONS.md §2.7): a refused request answers `429` with `Retry-After` (seconds or an
 * HTTP date) and `meta.limit`. The runtime's requests go through {@link retryingFetch}, which waits the announced time
 * and sends the request again, a few times and never longer than a cap; beyond that the `429` reaches the caller as a
 * `TavrnApiError` (status 429) like any other refusal.
 */
import type { BotLogger } from "./logger";

export interface RetryOptions {
  /** Attempts after the first one (default 3). */
  retries?: number;
  /** Longest single wait; a longer `Retry-After` is not waited for (default 30 s). */
  maxWaitMs?: number;
  /** Wait when the node sends no usable `Retry-After` (default 1 s). */
  defaultWaitMs?: number;
  logger?: BotLogger;
  /** Clock and timer (tests). */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

/** Milliseconds a `Retry-After` value asks to wait (delta seconds or an HTTP date), null when it is unusable. */
export function retryAfterMs(value: string | null | undefined, now: number = Date.now()): number | null {
  const v = value?.trim();
  if (!v) return null;
  if (/^\d+$/.test(v)) return Number(v) * 1000;
  const at = Date.parse(v);
  if (!Number.isFinite(at)) return null;
  return Math.max(0, at - now);
}

/** A body that can be sent again unchanged (streams cannot). */
function replayable(body: BodyInit | null | undefined): boolean {
  return body === undefined || body === null || typeof body === "string" || body instanceof Uint8Array || body instanceof ArrayBuffer || (typeof Blob !== "undefined" && body instanceof Blob) || body instanceof URLSearchParams;
}

/** Waits `ms`, or rejects with the signal's reason as soon as it aborts. */
function abortableSleep(sleep: (ms: number) => Promise<void>, ms: number, signal: AbortSignal | null | undefined): Promise<void> {
  if (!signal) return sleep(ms);
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<void>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    sleep(ms).then(
      () => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      },
      (e: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(e);
      },
    );
  });
}

/**
 * `fetch` that honours `429 Retry-After`: waits and repeats the request up to `retries` times while each wait is at
 * most `maxWaitMs`, then returns the last response unchanged. Other responses and network errors pass through. A
 * wait ends early when the request's signal aborts (its deadline passed or the caller gave up).
 */
export function retryingFetch(fetchImpl: typeof fetch = fetch, opts: RetryOptions = {}): typeof fetch {
  const retries = opts.retries ?? 3;
  const maxWait = opts.maxWaitMs ?? 30_000;
  const fallback = opts.defaultWaitMs ?? 1000;
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const wrapped = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    for (let attempt = 0; ; attempt++) {
      const resp = await fetchImpl(input, init);
      if (resp.status !== 429 || attempt >= retries || !replayable(init?.body) || input instanceof Request) return resp;
      const wait = retryAfterMs(resp.headers.get("Retry-After"), now()) ?? fallback;
      if (wait > maxWait) return resp;
      opts.logger?.warn("rate limited, retrying", { wait_ms: wait, attempt: attempt + 1 });
      await resp.body?.cancel().catch(() => undefined);
      await abortableSleep(sleep, wait, init?.signal);
    }
  };
  return wrapped as typeof fetch;
}
