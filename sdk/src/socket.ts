// SPDX-License-Identifier: Apache-2.0
/**
 * WebSocket client for `/api/v1/ws`: Hello/Ready, events, Ping/Pong, reconnection with backoff.
 * Runs in the browser and in Node.js (bots).
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
}

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
  private timer: ReturnType<typeof setTimeout> | null = null;
  private listeners = new Map<string, Set<(data: never) => void>>();
  status: SocketStatus = "closed";
  sessionId: string | null = null;

  constructor(private readonly opts: SocketOptions) {}

  connect(): void {
    this.closedByUser = false;
    void this.open();
  }

  close(): void {
    this.closedByUser = true;
    if (this.timer) clearTimeout(this.timer);
    this.ws?.close(1000, "client");
    this.ws = null;
    this.setStatus("closed");
  }

  /** Event listener for one type (e.g. `message.create`). Returns an unsubscribe function. */
  on<T = unknown>(type: string, handler: (data: T) => void): () => void {
    const set = this.listeners.get(type) ?? new Set();
    set.add(handler as (data: never) => void);
    this.listeners.set(type, set);
    return () => set.delete(handler as (data: never) => void);
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

  private async open() {
    const token = await this.opts.getToken();
    if (!token) {
      this.opts.onAuthFailure?.();
      this.setStatus("closed");
      return;
    }
    this.setStatus(this.attempt === 0 ? "connecting" : "reconnecting");
    const Impl = this.opts.WebSocketImpl ?? WebSocket;
    const ws = new Impl(this.opts.url);
    this.ws = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ op: "hello", token, capabilities: this.opts.capabilities ?? ["content.v1"], last_event_id: null }));
    };
    ws.onmessage = (m: MessageEvent) => this.handle(String(m.data));
    ws.onclose = (ev: CloseEvent) => {
      if (this.ws !== ws) return;
      this.ws = null;
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
        this.opts.onEvent?.(event);
        this.listeners.get(event.type)?.forEach((h) => h(event.data as never));
        this.listeners.get("*")?.forEach((h) => h(event as never));
        break;
      }
      default:
        break;
    }
  }
}
