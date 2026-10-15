// SPDX-License-Identifier: Apache-2.0
/**
 * Transport helpers shared by the API client, node discovery and hook verification: deadlines (a timeout combined
 * with the caller's `AbortSignal`), bounded reading of response bodies and the network error shapes. Everything a
 * request can fail with on the way arrives as `TavrnApiError` with status 0:
 *
 * - `network.error`: the node could not be reached (DNS, TLS, connection refused, CORS);
 * - `network.timeout`: no complete answer within the deadline;
 * - `request.aborted`: the caller's signal aborted the request;
 * - `response.too_large`: the answer is larger than the client accepts;
 * - `request.invalid_path`: an id would leave its path segment (`.`, `..`, empty).
 */
import { TavrnApiError } from "./errors";

/** Default deadline of an API request (JSON and small binary routes). */
export const DEFAULT_TIMEOUT_MS = 30_000;
/** Default deadline of uploads and downloads of files (attachments, files channels, backups). */
export const DEFAULT_TRANSFER_TIMEOUT_MS = 10 * 60_000;
/** Largest JSON answer the API client reads by default. */
export const DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

export function transportError(code: "network.error" | "network.timeout" | "request.aborted" | "response.too_large" | "request.invalid_path", detail: string): TavrnApiError {
  const titles = {
    "network.error": "Network error",
    "network.timeout": "Timeout",
    "request.aborted": "Aborted",
    "response.too_large": "Response too large",
    "request.invalid_path": "Invalid request",
  } as const;
  return new TavrnApiError({ type: "about:blank", title: titles[code], status: 0, detail, code });
}

/** A deadline: the timer and the callers' signals combined into one signal for `fetch` and the body read. */
export interface Deadline {
  readonly signal: AbortSignal | undefined;
  /** Stops the timer only (a streamed body stays abortable through the callers' signals). */
  stopTimer(): void;
  /** Stops the timer and detaches from the callers' signals; call it once the answer was read. */
  done(): void;
  /** The error for a failure while the request or its body read was running. */
  failure(e: unknown): TavrnApiError;
}

/**
 * A deadline of `ms` milliseconds (0 or less: none) that also ends when one of `signals` aborts. Without either the
 * request runs without a signal, like a plain `fetch`.
 */
export function deadline(ms: number, ...signals: (AbortSignal | null | undefined)[]): Deadline {
  const callers = signals.filter((s): s is AbortSignal => !!s);
  const controller = ms > 0 || callers.length ? new AbortController() : null;
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const listeners: [AbortSignal, () => void][] = [];
  for (const s of callers) {
    const onAbort = () => controller!.abort(s.reason ?? abortReason("AbortError"));
    if (s.aborted) {
      onAbort();
      break;
    }
    s.addEventListener("abort", onAbort, { once: true });
    listeners.push([s, onAbort]);
  }
  if (controller && ms > 0 && !controller.signal.aborted) {
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort(abortReason("TimeoutError"));
    }, ms);
  }
  const stopTimer = () => {
    if (timer) clearTimeout(timer);
    timer = null;
  };
  return {
    signal: controller?.signal,
    stopTimer,
    done() {
      stopTimer();
      for (const [s, l] of listeners.splice(0)) s.removeEventListener("abort", l);
    },
    failure(e: unknown): TavrnApiError {
      if (e instanceof TavrnApiError) return e;
      if (timedOut) return transportError("network.timeout", `no answer within ${ms} ms`);
      if (controller?.signal.aborted) return transportError("request.aborted", "the request was aborted");
      return transportError("network.error", e instanceof Error ? e.message : String(e));
    },
  };
}

function abortReason(name: "AbortError" | "TimeoutError"): unknown {
  return typeof DOMException === "function" ? new DOMException(name === "TimeoutError" ? "The request timed out" : "The request was aborted", name) : new Error(name);
}

/** Discards a body that will not be read (frees the connection). */
export function discard(resp: Response): void {
  void resp.body?.cancel().catch(() => undefined);
}

/**
 * The body of `resp` as bytes, at most `maxBytes`: a larger `Content-Length` is refused before reading, a body that
 * grows past the cap is cancelled there (`response.too_large`).
 */
export async function readBytes(resp: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = Number(resp.headers?.get?.("Content-Length") ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) {
    discard(resp);
    throw transportError("response.too_large", `${declared} bytes, at most ${maxBytes} accepted`);
  }
  const body = resp.body;
  if (!body || typeof body.getReader !== "function") {
    // Response-like objects without a stream (tests, polyfills): read as a whole, then check.
    const bytes = new Uint8Array(await resp.arrayBuffer());
    if (bytes.length > maxBytes) throw transportError("response.too_large", `more than ${maxBytes} bytes`);
    return bytes;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw transportError("response.too_large", `more than ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  if (chunks.length === 1) return chunks[0]!;
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

/** The body of `resp` as UTF-8 text, at most `maxBytes` (see {@link readBytes}). */
export async function readText(resp: Response, maxBytes: number): Promise<string> {
  return new TextDecoder().decode(await readBytes(resp, maxBytes));
}

/**
 * Is `path` (the part before `?`) free of segments that a URL parser would resolve away or that an empty id leaves
 * behind? `.`/`..` (also percent-encoded) and empty segments are refused; ids are percent-encoded by the callers.
 */
export function safePath(path: string): boolean {
  const pathname = path.split(/[?#]/, 1)[0]!;
  const segments = pathname.split("/").slice(1);
  return segments.every((s) => s !== "" && !/^(\.|%2e){1,2}$/i.test(s));
}
