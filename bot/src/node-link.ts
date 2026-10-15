// SPDX-License-Identifier: Apache-2.0
/**
 * The bot's connection to one node: an API client with the right credentials and the WebSocket.
 *
 * - **Home node** (H): the app token itself. App tokens do not refresh (APPLICATIONS.md §2.2): a `4001` reconnects
 *   once with the current secret (it may have been rotated meanwhile) and otherwise ends the bot.
 * - **Room node** of a remote installation (T): a federated session like a remote user's (FEDERATION.md §2.5,
 *   APPLICATIONS.md §2.8): a federation token from H exchanged at `POST /auth/federated`. Access tokens refresh with
 *   the session's refresh token; when T refuses it, or before the session's 7-day cap ends, the link signs in again
 *   with a fresh federation token.
 */
import { TavrnApi, TavrnApiError, TavrnSocket, createRefresher, type NodeEndpoints, type SocketStatus, type TavrnEvent, type UserPrivate } from "@tavrn/sdk";
import { BotError } from "./errors";
import type { BotLogger } from "./logger";

/** Renew a federated session when less than this is left of its 7-day cap. */
export const RENEW_BEFORE_MS = 24 * 3600 * 1000;
/** Device name of the bot's federated sessions (shown in the node's session lists). */
export const FEDERATED_DEVICE_NAME = "tavrn bot";
/** WebSocket capabilities the runtime understands. */
export const BOT_CAPABILITIES = ["content.v1", "reactions", "e2ee.mls1"];

const CLOSE_REPLACED = 4004;

interface Session {
  token: string;
  refresh: string;
  user: UserPrivate;
  expiresAt: number;
}

export interface LinkHandlers {
  onEvent(link: NodeLink, event: TavrnEvent): void;
  /** The socket is ready; `first` for the first connection, later ones follow a gap (events may be lost). */
  onReady(link: NodeLink, first: boolean): void;
  /** The node asked for a resync on an open connection. */
  onResync(link: NodeLink): void;
  /** The connection ended for good (token refused, replaced). */
  onFatal(link: NodeLink, error: BotError): void;
}

export interface LinkOptions {
  domain: string;
  endpoints: NodeEndpoints;
  logger: BotLogger;
  handlers: LinkHandlers;
  clientHeader: string;
  fetchImpl?: typeof fetch;
  WebSocketImpl?: typeof WebSocket;
  now?: () => number;
}

export class NodeLink {
  readonly domain: string;
  readonly endpoints: NodeEndpoints;
  /** API client with the bot's credentials on this node. */
  readonly api: TavrnApi;
  /** API client without credentials (public routes). */
  readonly publicApi: TavrnApi;
  private socket: TavrnSocket | null = null;
  private readyOnce = false;
  private closed = false;
  private readyWaiters: { resolve: () => void; reject: (e: unknown) => void }[] = [];
  /** Home node: the current app token. */
  private appToken: (() => string) | null = null;
  /** Room node: the federated session and how to get a new one. */
  private session: Session | null = null;
  private login: (() => Promise<Session>) | null = null;
  private refresher: (() => Promise<string | null>) | null = null;
  private relogin: Promise<string | null> | null = null;

  private constructor(private readonly opts: LinkOptions) {
    this.domain = opts.domain;
    this.endpoints = opts.endpoints;
    this.publicApi = new TavrnApi({ baseUrl: opts.endpoints.base, clientHeader: opts.clientHeader, fetchImpl: opts.fetchImpl });
    this.api = new TavrnApi({
      baseUrl: opts.endpoints.base,
      clientHeader: opts.clientHeader,
      fetchImpl: opts.fetchImpl,
      getToken: () => this.token(),
      refreshToken: () => this.refresh(),
    });
  }

  /** The link to the bot's home node, authenticated with the app token. */
  static home(opts: LinkOptions, appToken: () => string): NodeLink {
    const link = new NodeLink(opts);
    link.appToken = appToken;
    return link;
  }

  /**
   * The link to a room node of a remote installation: signs in with a federation token of the home node (`home`)
   * before it returns.
   */
  static async remote(opts: LinkOptions, home: TavrnApi): Promise<NodeLink> {
    const link = new NodeLink(opts);
    const now = opts.now ?? Date.now;
    link.login = async () => {
      const { token } = await home.federation.token(opts.domain);
      const resp = await link.publicApi.auth.federated(token, FEDERATED_DEVICE_NAME);
      const expiresAt = Date.parse(resp.session_expires_at);
      return { token: resp.access_token, refresh: resp.refresh_token, user: resp.user, expiresAt: Number.isFinite(expiresAt) ? expiresAt : now() + 7 * 24 * 3600 * 1000 };
    };
    link.session = await link.login();
    link.refresher = createRefresher({
      lockName: `tavrn-bot:${opts.domain}`,
      locks: null,
      current: () => link.session?.refresh ?? null,
      call: (refresh) => link.publicApi.auth.refresh(refresh),
      store: (pair) => {
        if (link.session) link.session = { ...link.session, token: pair.access_token, refresh: pair.refresh_token };
      },
      onInvalid: () => undefined,
    });
    return link;
  }

  get isHome(): boolean {
    return this.appToken !== null;
  }

  /** The bot as this node knows it (remote links; the home link reads it from the node). */
  get remoteUser(): UserPrivate | null {
    return this.session?.user ?? null;
  }

  /** End of the federated session (epoch ms), null for the home link. */
  get sessionExpiresAt(): number | null {
    return this.session?.expiresAt ?? null;
  }

  private token(): string | null {
    if (this.appToken) return this.appToken();
    return this.session?.token ?? null;
  }

  /**
   * After a 401 or a `4001`. Home: the current app token (rotation may have replaced it). Room node: refresh, and
   * sign in again with a fresh federation token when the node refused the refresh token.
   */
  private async refresh(): Promise<string | null> {
    if (this.appToken) return this.appToken();
    if (!this.refresher || !this.login) return null;
    const fresh = await this.refresher();
    if (fresh) return fresh;
    return this.signInAgain();
  }

  /** A new federated session (single flight). Null when a node refused it. */
  signInAgain(): Promise<string | null> {
    if (!this.login) return Promise.resolve(null);
    this.relogin ??= this.login()
      .then(
        (s) => {
          this.session = s;
          return s.token;
        },
        (e: unknown) => {
          if (e instanceof TavrnApiError && e.status > 0) {
            this.opts.logger.warn("federated sign-in refused", { node: this.domain, code: e.code });
            return null;
          }
          throw e;
        },
      )
      .finally(() => {
        this.relogin = null;
      });
    return this.relogin;
  }

  /** Renews the federated session when its cap is near (best effort; called periodically). */
  async renewIfExpiring(): Promise<void> {
    const at = this.session?.expiresAt;
    const now = (this.opts.now ?? Date.now)();
    if (at === undefined || at - now > RENEW_BEFORE_MS) return;
    await this.signInAgain().catch((e: unknown) => this.opts.logger.warn("federated session renewal failed", { node: this.domain, error: e }));
  }

  /** Opens the WebSocket (reconnects with backoff until {@link close}). */
  connect(): void {
    if (this.socket || this.closed) return;
    const log = this.opts.logger;
    this.socket = new TavrnSocket({
      url: this.endpoints.ws,
      getToken: () => this.token(),
      capabilities: BOT_CAPABILITIES,
      WebSocketImpl: this.opts.WebSocketImpl,
      onStatus: (status: SocketStatus) => {
        log.debug("socket status", { node: this.domain, status });
        if (status === "ready") {
          const first = !this.readyOnce;
          this.readyOnce = true;
          for (const w of this.readyWaiters.splice(0)) w.resolve();
          this.opts.handlers.onReady(this, first);
        }
      },
      onResync: () => this.opts.handlers.onResync(this),
      onEvent: (event) => this.opts.handlers.onEvent(this, event),
      refreshToken: () => this.refresh(),
      onAuthFailure: () => this.fatal(new BotError("token_refused", `${this.domain} refused the bot's credentials (token revoked, reset or expired, or the application was disabled)`)),
      onClose: (code: number) => {
        if (code === CLOSE_REPLACED) this.fatal(new BotError("replaced", `A newer connection of the same token replaced this one on ${this.domain}`));
      },
    });
    this.socket.connect();
  }

  /** Resolves when the socket is ready the first time (rejects when the link failed for good or after `ms`). */
  waitReady(ms: number): Promise<void> {
    if (this.readyOnce) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new BotError("node_invalid", `No WebSocket connection to ${this.domain} within ${ms} ms`)), ms);
      this.readyWaiters.push({
        resolve: () => {
          clearTimeout(timer);
          resolve();
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
    });
  }

  private fatal(error: BotError) {
    if (this.closed) return;
    this.close();
    for (const w of this.readyWaiters.splice(0)) w.reject(error);
    this.opts.handlers.onFatal(this, error);
  }

  get connected(): boolean {
    return this.socket?.status === "ready";
  }

  /** Sends the `typing` operation for a conversation (PROTOCOL.md §6); false while the socket is not open. */
  typing(conversationId: string): boolean {
    return this.socket?.typingIn(conversationId) ?? false;
  }

  /** Closes the WebSocket for good. */
  close(): void {
    this.closed = true;
    this.socket?.close();
    this.socket = null;
  }
}
