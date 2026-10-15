// SPDX-License-Identifier: Apache-2.0
/**
 * WebSocket client for `/api/v1/ws`: Hello/Ready, events, Ping/Pong, reconnection with backoff, a liveness watchdog
 * (the node pings every 30 s, PROTOCOL.md §6 item 5: a connection without any frame for {@link DEFAULT_LIVENESS_MS}
 * is treated as dead and replaced). Runs in the browser and in Node.js (bots).
 */
export type SocketStatus = "connecting" | "ready" | "reconnecting" | "closed";

export interface TavrnEvent<T = unknown> {
  id: string;
  type: string;
  data: T;
}

export interface SocketOptions {
  url: string;
  getToken: () => string | null | Promise<string | null>;
  capabilities?: string[];
  /** For tests or Node.js: a custom WebSocket implementation. */
  WebSocketImpl?: typeof WebSocket;
  onStatus?: (status: SocketStatus) => void;
  /** The node demands a full rebuild of the state. */
  onResync?: () => void;
  onEvent?: (event: TavrnEvent) => void;
  /**
   * Close code 4001 (token expired or refused): called once per failed connection to refresh the session (e.g.
   * the function of `createRefresher`). A new token reconnects at once; `null` (the session is over) ends in
   * {@link SocketOptions.onAuthFailure}; an error (node unreachable) reconnects later with backoff.
   */
  refreshToken?: () => Promise<string | null>;
  /** The session is over: 4001 without `refreshToken`, a refresh that returned null, or 4001 right after a refresh. */
  onAuthFailure?: () => void;
  /**
   * Every close of the connection by the node or the network (not by {@link TavrnSocket.close}), with its code.
   * After `4004` (a newer connection of the same app token replaced this one, APPLICATIONS.md §2.6) the socket
   * does not reconnect.
   */
  onClose?: (code: number, reason: string) => void;
  /**
   * A connection that delivers no frame at all (event, ping, ready) for this long is closed locally (code 4000,
   * reported to {@link SocketOptions.onClose}) and replaced; the new connection resyncs. Default
   * {@link DEFAULT_LIVENESS_MS}; 0 turns the watchdog off.
   */
  livenessMs?: number;
  /**
   * A listener (`onEvent`, `on()`) threw: the other listeners still get the event. Default: `console.error`.
   */
  onListenerError?: (error: unknown, event: TavrnEvent) => void;
  /**
   * Largest text frame accepted, in characters (default {@link DEFAULT_MAX_FRAME_LENGTH}): a longer one is not parsed;
   * the connection is closed (code 4000, reason `frame_too_large`, reported to {@link SocketOptions.onClose}) and
   * replaced, and the new connection resyncs. The same value goes to the WebSocket implementation as `maxPayload`
   * (bytes, the option of the Node.js package `ws`, which then refuses a larger frame before buffering it; browsers
   * and the built-in WebSocket of Node.js ignore it, there the check runs after the frame arrived).
   */
  maxFrameLength?: number;
}

/** Two missed pings of the node (every 30 s) plus slack. */
export const DEFAULT_LIVENESS_MS = 75_000;

/** Largest text frame parsed by default: 16 Mi characters, far above any event of the protocol. */
export const DEFAULT_MAX_FRAME_LENGTH = 16 * 1024 * 1024;

const CLOSE_RESTART = 4000;
const CLOSE_AUTH = 4001;
/** Replaced by a newer connection of the same app token: do not reconnect (APPLICATIONS.md §2.6). */
const CLOSE_REPLACED = 4004;
/** 4001 reasons a refresh cannot fix. */
const FINAL_AUTH_REASONS = new Set(["auth.account_disabled", "auth.admin_token_not_allowed"]);

export class TavrnSocket {
  private ws: WebSocket | null = null;
  private attempt = 0;
  /** 4001 closes since the last `ready` that were answered with a refresh. */
  private authRefreshes = 0;
  private closedByUser = false;
  /**
   * Bumped by every {@link TavrnSocket.connect} and {@link TavrnSocket.close}: an `open()` that awaited its token
   * across one of them is obsolete and must not create a socket.
   */
  private generation = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  /** Liveness watchdog of the current connection. */
  private watchdog: ReturnType<typeof setTimeout> | null = null;
  private listeners = new Map<string, Set<(data: never) => void>>();
  status: SocketStatus = "closed";
  sessionId: string | null = null;

  constructor(private readonly opts: SocketOptions) {}

  connect(): void {
    this.closedByUser = false;
    this.generation += 1;
    void this.open();
  }

  close(): void {
    this.closedByUser = true;
    this.generation += 1;
    if (this.timer) clearTimeout(this.timer);
    this.stopWatchdog();
    this.ws?.close(1000, "client");
    this.ws = null;
    this.setStatus("closed");
  }

  /** Event listener for one type (e.g. `message.create`). Returns an unsubscribe function. */
  on<T = unknown>(type: string, handler: (data: T) => void): () => void {
    const set = this.listeners.get(type) ?? new Set();
    set.add(handler as (data: never) => void);
    this.listeners.set(type, set);
    return () => {
      set.delete(handler as (data: never) => void);
      if (!set.size && this.listeners.get(type) === set) this.listeners.delete(type);
    };
  }

  send(op: Record<string, unknown>): boolean {
    if (this.ws?.readyState !== 1) return false;
    this.ws.send(JSON.stringify(op));
    return true;
  }

  typing(roomId: string, channelId: string): boolean {
    return this.send({ op: "typing", room_id: roomId, channel_id: channelId });
  }

  /** Typing notice in a DM or group DM (delivered to its members). */
  typingIn(conversationId: string): boolean {
    return this.send({ op: "typing", conversation_id: conversationId });
  }

  ack(conversationId: string, messageId: string): boolean {
    return this.send({ op: "ack", conversation_id: conversationId, message_id: messageId });
  }

  private setStatus(status: SocketStatus) {
    this.status = status;
    this.opts.onStatus?.(status);
  }

  /** One connection attempt; a failure before the socket exists (token provider, constructor) retries with backoff. */
  private async open(): Promise<void> {
    const generation = this.generation;
    try {
      await this.openInner(generation);
    } catch {
      if (generation !== this.generation || this.closedByUser) return;
      this.scheduleReconnect();
    }
  }

  private async openInner(generation: number): Promise<void> {
    const token = await this.opts.getToken();
    // close() or a newer connect() happened during the token fetch: this attempt is obsolete.
    if (generation !== this.generation || this.closedByUser) return;
    if (!token) {
      this.opts.onAuthFailure?.();
      this.setStatus("closed");
      return;
    }
    this.setStatus(this.attempt === 0 ? "connecting" : "reconnecting");
    const Impl = this.opts.WebSocketImpl ?? WebSocket;
    const previous = this.ws;
    if (previous) {
      // A second connect() while a socket was live: only the newest one may receive events.
      this.ws = null;
      previous.close(1000, "client");
    }
    // The third argument is the options of `ws` (maxPayload: refused while receiving); other implementations ignore it.
    const ws = new (Impl as unknown as new (url: string, protocols: undefined, options: { maxPayload: number }) => WebSocket)(this.opts.url, undefined, { maxPayload: this.maxFrameLength });
    this.ws = ws;
    this.armWatchdog(ws);
    ws.onopen = () => {
      if (this.ws !== ws) {
        ws.close(1000, "client");
        return;
      }
      this.armWatchdog(ws);
      ws.send(JSON.stringify({ op: "hello", token, capabilities: this.opts.capabilities ?? ["content.v1"], last_event_id: null }));
    };
    ws.onmessage = (m: MessageEvent) => {
      if (this.ws !== ws) return;
      if (typeof m.data === "string" && m.data.length > this.maxFrameLength) {
        this.replace(ws, "frame_too_large");
        return;
      }
      this.armWatchdog(ws);
      this.handle(String(m.data));
    };
    ws.onclose = (ev: CloseEvent) => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.stopWatchdog();
      if (!this.closedByUser) this.opts.onClose?.(ev.code, String((ev as { reason?: unknown }).reason ?? ""));
      if (ev.code === CLOSE_REPLACED) {
        this.closedByUser = true;
        this.setStatus("closed");
        return;
      }
      if (ev.code === CLOSE_AUTH) {
        this.onAuthClose(String((ev as { reason?: unknown }).reason ?? ""));
        return;
      }
      if (this.closedByUser) return;
      this.scheduleReconnect(ev.code === CLOSE_RESTART ? 250 : undefined);
    };
    ws.onerror = () => {
      /* onclose always follows */
    };
  }

  /** (Re)starts the liveness timer of `ws`: any frame proves the connection alive. */
  private armWatchdog(ws: WebSocket) {
    const ms = this.opts.livenessMs ?? DEFAULT_LIVENESS_MS;
    this.stopWatchdog();
    if (ms <= 0) return;
    this.watchdog = setTimeout(() => this.silent(ws), ms);
  }

  private get maxFrameLength(): number {
    return this.opts.maxFrameLength ?? DEFAULT_MAX_FRAME_LENGTH;
  }

  private stopWatchdog() {
    if (this.watchdog) clearTimeout(this.watchdog);
    this.watchdog = null;
  }

  /** No frame for the liveness interval: a half-open connection (NAT timeout, sleep). Replace it. */
  private silent(ws: WebSocket) {
    this.watchdog = null;
    this.replace(ws, "liveness");
  }

  /** Closes `ws` locally (code 4000 with `reason`) and connects again. */
  private replace(ws: WebSocket, reason: string) {
    if (this.ws !== ws || this.closedByUser) return;
    this.ws = null;
    this.stopWatchdog();
    try {
      ws.close(CLOSE_RESTART, reason);
    } catch {
      /* already closing */
    }
    this.opts.onClose?.(CLOSE_RESTART, reason);
    this.scheduleReconnect();
  }

  /** 4001: refresh once and reconnect; the session is over when that is not possible. */
  private onAuthClose(reason: string) {
    const fail = () => {
      this.opts.onAuthFailure?.();
      this.setStatus("closed");
    };
    if (this.closedByUser) return;
    if (!this.opts.refreshToken || FINAL_AUTH_REASONS.has(reason) || this.authRefreshes >= 1) return fail();
    this.authRefreshes += 1;
    this.setStatus("reconnecting");
    this.opts.refreshToken().then(
      (token) => {
        if (this.closedByUser) return;
        if (token) void this.open();
        else fail();
      },
      () => {
        // Node unreachable: not the end of the session; try again later (with a refresh again if needed).
        if (this.closedByUser) return;
        this.authRefreshes = 0;
        this.scheduleReconnect();
      },
    );
  }

  private scheduleReconnect(fixedDelay?: number) {
    this.setStatus("reconnecting");
    this.attempt += 1;
    const base = Math.min(30_000, 500 * 2 ** Math.min(this.attempt, 6));
    const delay = fixedDelay ?? base / 2 + Math.random() * (base / 2);
    this.timer = setTimeout(() => void this.open(), delay);
  }

  private handle(raw: string) {
    let frame: { op: string; [k: string]: unknown };
    try {
      frame = JSON.parse(raw) as { op: string };
    } catch {
      return;
    }
    switch (frame.op) {
      case "ready":
        this.attempt = 0;
        this.authRefreshes = 0;
        this.sessionId = String(frame.session_id ?? "");
        this.setStatus("ready");
        break;
      case "ping":
        this.send({ op: "pong" });
        break;
      case "resync":
        this.opts.onResync?.();
        break;
      case "event": {
        const event = { id: String(frame.id), type: String(frame.type), data: frame.data } as TavrnEvent;
        // Every listener gets the event, whatever another one does (a throw would also escape the socket callback).
        const call = (fn: () => void) => {
          try {
            fn();
          } catch (e) {
            if (this.opts.onListenerError) this.opts.onListenerError(e, event);
            else console.error("tavrn socket: event listener failed", event.type, e);
          }
        };
        if (this.opts.onEvent) call(() => this.opts.onEvent!(event));
        for (const h of [...(this.listeners.get(event.type) ?? [])]) call(() => h(event.data as never));
        for (const h of [...(this.listeners.get("*") ?? [])]) call(() => h(event as never));
        break;
      }
      default:
        break;
    }
  }
}
