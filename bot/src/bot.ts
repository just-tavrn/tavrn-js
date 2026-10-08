// SPDX-License-Identifier: Apache-2.0
/**
 * The bot runtime (APPLICATIONS.md §3, §11 step 5): `createBot()` gives a {@link Bot} that, on `start()`,
 *
 * 1. reads the app token's claims (device `dev`, application, home node, expiry) and the bot account (`GET /users/me`);
 * 2. bootstraps the identity from the bot key file (§3.1): on the first start it creates the master secret and the
 *    key file (0600) and publishes the identity key with the app token; later starts reuse the key; a missing key
 *    for an existing identity stops with a clear error;
 * 3. opens the encrypted state directory (`FileKeyStore`), attests the token's device and keeps KeyPackages
 *    uploaded (§3.2); with `historyBackup: true` it also keeps history backups on the home node and restores them into
 *    a fresh state directory (off by default, design note 4.7);
 * 4. connects the WebSocket of the home node and, for every remote installation (`GET /applications/me/installations`),
 *    a federated session and WebSocket on that room node (§2.8, §4.5);
 * 5. joins the MLS groups of the encrypted channels it can view, eagerly or on first need (§3.3), and delivers
 *    messages decrypted (`bot.on("message")`), sends with encryption where the conversation needs it, and runs
 *    commands (`bot.command()`, §5).
 *
 * `stop()` closes the sockets, waits for running handlers and flushes the pending history backups (if enabled).
 */
import { LocalKeyMismatchError, MlsError, ensureDevice, localStatus, mlsApiOf, openMlsManager, qualify, splitQualified, type Decrypted, type MlsManager, type PlainStatus } from "@tavrn/e2ee";
import { FileKeyStore, StateDirInUseError } from "@tavrn/e2ee/node";
import { TavrnApi, TavrnApiError, b64urlEncode, resolveNode, type Channel, type CommandDefinition, type CommandSet, type Message, type NodeEndpoints, type TavrnEvent, type UserKeys, type UserPrivate, type WellKnown } from "@tavrn/sdk";
import { threadTitle } from "./threads";
import { CommandRouter, type CommandCrypto, type CommandHandler, type InvokeContext, type ReplyContent } from "./commands";
import { BotError } from "./errors";
import { createKeyFile, defaultKeyFile, identityKeyOf, readKey } from "./keyfile";
import { consoleLogger, type BotLogger } from "./logger";
import { NodeLink } from "./node-link";
import { appTokenClaims, type AppTokenClaims } from "./token";

export const BOT_VERSION = "0.1.0";
/** Default state directory (`TAVRN_BOT_STATE_DIR`, APPLICATIONS.md §3.3). */
export const DEFAULT_STATE_DIR = ".tavrn-state";
/** Channel kinds whose MLS groups the bot joins (voice groups only carry frame keys). */
export const JOINABLE_KINDS = new Set(["text", "announcement", "forum"]);
const READY_TIMEOUT_MS = 30_000;
const MAINTENANCE_MS = 10 * 60 * 1000;

export interface BotOptions {
  /** Home node: its base URL (`https://node.example`, also an internal URL) or its domain (`node.example`). */
  node: string;
  /** The app token (`TAVRN_BOT_TOKEN`). */
  token: string;
  /** The key file's text or its compact `key:` value (`TAVRN_BOT_KEY`); takes precedence over `keyFile`. */
  key?: string | null;
  /** Path of the key file (`TAVRN_BOT_KEY_FILE`, default `./tavrn-key-<username>.txt`); created on the first start. */
  keyFile?: string | null;
  /** Encrypted local state (`TAVRN_BOT_STATE_DIR`, default `./.tavrn-state`); one process and token per directory. */
  stateDir?: string | null;
  logger?: BotLogger;
  /**
   * `eager` (default): join the encryption group of every encrypted channel the bot can view as soon as it is
   * installed (or the channel appears). `lazy`: join on first need (a message, a command, `send`); recommended for
   * large rooms, because every join creates an epoch.
   */
  joinPolicy?: "eager" | "lazy";
  /** Defer commands automatically when the handler did not answer after this long (default 2000 ms). */
  autoDeferMs?: number;
  /** Allow `http://`/`ws://` endpoints of other nodes (development); default: when `node` is an `http://` URL. */
  allowInsecure?: boolean;
  /** Interval of KeyPackage top-up, session renewal and backup retries (default 10 minutes). */
  maintenanceMs?: number;
  /** Debounce of the history backup upload (default 1000 ms). */
  backupDelayMs?: number;
  /**
   * Keep history backups of the epoch keys on the home node (`ENCRYPTION.md` §7) and restore them into a fresh state
   * directory. Default `false`: the bot uploads nothing and a restart with a new state directory reads only messages
   * sent after it joined again. Enable it only for bots that must read older messages after losing their state; the
   * backups are encrypted with the bot's key, so whoever holds the key file can read that history (design note 4.7).
   */
  historyBackup?: boolean;
  /** WebSocket implementation (Node.js 20 without `--experimental-websocket`: `import WebSocket from "ws"`). */
  WebSocketImpl?: typeof WebSocket;
  fetchImpl?: typeof fetch;
}

/** Who the bot is, once started. */
export interface BotInfo {
  address: string;
  username: string;
  userId: string;
  applicationId: string;
  /** `<home domain>/<application id>`. */
  applicationRef: string;
  deviceId: string;
  homeDomain: string;
}

/** A received message, decrypted when it was encrypted. */
export interface BotMessage {
  id: string;
  /** Domain of the node hosting the conversation. */
  node: string;
  conversationId: string;
  /** Qualified conversation id `<node>/<conversation id>` (pass it to `send`). */
  conversation: string;
  /** Room of a channel message (null in DMs or when unknown). */
  roomId: string | null;
  author: string;
  /** `user`, `bot`, `webhook`, … (APPLICATIONS.md §1.5). */
  authorKind: string;
  deviceId: string | null;
  encrypted: boolean;
  /** The content object (`{ type: "text", body, … }`). */
  content: Record<string, unknown>;
  /** `content.body` when it is text, else "". */
  text: string;
  mentions: string[];
  /** The message mentions the bot. */
  mentionsMe: boolean;
  /** Plaintext messages: the author device's signature check (FEDERATION.md §10.3); null for encrypted ones. */
  signature: PlainStatus | null;
  replyToId: string | null;
  /** The thread the message belongs to (PROTOCOL.md §7e), null for messages of the channel itself. */
  threadId: string | null;
  createdAt: string;
  raw: Message;
  /** Answers in the same conversation (and the same thread), as a reply to this message. */
  reply(content: ReplyContent, opts?: SendOptions): Promise<Message>;
  /**
   * Answers in a thread: the message's own thread, the thread it already started, or a new thread started from it
   * (`title` defaults to the start of the message's text). Room channels only.
   */
  replyInThread(content: ReplyContent, opts?: SendOptions & { title?: string }): Promise<Message>;
}

export { threadTitle };

export interface SendOptions {
  /** Message id this one answers. */
  replyTo?: string | null;
  /** Addresses mentioned (lowercase, without duplicates). */
  mentions?: string[];
  /** Write into this thread of the channel (PROTOCOL.md §7e). */
  threadId?: string | null;
}

export interface InstallEvent {
  node: string;
  roomId: string;
  roomName: string;
  installedBy: string | null;
}

export interface UninstallEvent {
  node: string;
  roomId: string;
  reason: string;
}

export interface TokenExpiringEvent {
  applicationId: string;
  tokenId: string;
  expiresAt: string;
  /** 7 or 1. */
  days: number;
}

export interface UndecryptableEvent {
  node: string;
  conversation: string;
  messageId: string;
  author: string;
  reason: Exclude<Decrypted, { ok: true }>["reason"] | "not_member";
}

export interface BotEvents {
  ready: [BotInfo];
  message: [BotMessage];
  undecryptable: [UndecryptableEvent];
  install: [InstallEvent];
  uninstall: [UninstallEvent];
  /** `application.token_expiring` (§2.2): rotate with {@link Bot.rotateToken} or ask the owner for a new token. */
  tokenExpiring: [TokenExpiringEvent];
  /** {@link Bot.rotateToken} produced a new secret: store it, the previous one stays valid for 24 hours. */
  tokenRotated: [{ secret: string; expiresAt: string }];
  /** Every WebSocket event of every node, unchanged (for events the runtime does not interpret). */
  event: [{ node: string; event: TavrnEvent }];
  error: [Error];
}

type Listener<A extends unknown[]> = (...args: A) => void | Promise<void>;

interface ChannelInfo {
  node: string;
  roomId: string;
  id: string;
  kind: string;
  encrypted: boolean;
  noBots: boolean;
}

/** The backup store of a bot without `historyBackup`: lists nothing, has nothing, keeps nothing. */
const NO_BACKUPS = {
  list: async () => ({ items: [] }),
  get: async () => null,
  put: async () => undefined,
};

/** Creates a bot; nothing happens until {@link Bot.start}. */
export function createBot(opts: BotOptions): Bot {
  return new Bot(opts);
}

function code(e: unknown): string | undefined {
  return e instanceof TavrnApiError ? e.code : undefined;
}

function normalizeContent(content: ReplyContent): Record<string, unknown> {
  if (typeof content === "string") return { type: "text", body: content };
  if (!content || typeof content !== "object" || Array.isArray(content)) throw new TypeError("content must be text or a content object");
  return content;
}

function mentionList(list: string[] | undefined): string[] {
  return [...new Set((list ?? []).map((a) => a.trim().toLowerCase()).filter(Boolean))];
}

export class Bot {
  readonly logger: BotLogger;
  private token: string;
  private readonly listeners = new Map<keyof BotEvents, Set<(...args: unknown[]) => unknown>>();
  private readonly commands: CommandRouter;
  private readonly links = new Map<string, NodeLink>();
  private readonly connecting = new Map<string, Promise<NodeLink | null>>();
  private readonly channels = new Map<string, ChannelInfo>();
  private readonly direct = new Map<string, boolean>();
  private readonly publicClients = new Map<string, TavrnApi>();
  private readonly inflight = new Set<Promise<unknown>>();
  private readonly joining = new Map<string, Promise<boolean>>();
  private claims: AppTokenClaims | null = null;
  private me: UserPrivate | null = null;
  private mls: MlsManager | null = null;
  private store: FileKeyStore | null = null;
  private home: NodeLink | null = null;
  private maintenance: ReturnType<typeof setInterval> | null = null;
  private topUpRunning: Promise<void> | null = null;
  private starting: Promise<void> | null = null;
  private state: "new" | "starting" | "running" | "stopping" | "stopped" = "new";
  private allowInsecure: boolean;

  constructor(private readonly opts: BotOptions) {
    this.logger = opts.logger ?? consoleLogger();
    this.token = opts.token.trim();
    this.commands = new CommandRouter({ logger: this.logger, autoDeferMs: opts.autoDeferMs });
    this.allowInsecure = opts.allowInsecure ?? /^http:\/\//i.test(opts.node.trim());
  }

  // ---- Events and commands --------------------------------------------------------------------

  /** Adds a listener; returns a function that removes it. Async listeners are awaited by `stop()`. */
  on<K extends keyof BotEvents>(event: K, listener: Listener<BotEvents[K]>): () => void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    const fn = listener as unknown as (...args: unknown[]) => unknown;
    set.add(fn);
    return () => set.delete(fn);
  }

  private emit<K extends keyof BotEvents>(event: K, ...args: BotEvents[K]): void {
    const set = this.listeners.get(event);
    if (!set?.size) {
      if (event === "error") this.logger.error("bot error", { error: args[0] });
      return;
    }
    for (const listener of set) {
      try {
        const r = listener(...args);
        if (r && typeof (r as Promise<void>).then === "function") this.track((r as Promise<void>).catch((e: unknown) => this.listenerFailed(event, e)));
      } catch (e) {
        this.listenerFailed(event, e);
      }
    }
  }

  private listenerFailed(event: keyof BotEvents, e: unknown) {
    this.logger.error("event listener failed", { event, error: e });
    if (event !== "error") this.emit("error", e instanceof Error ? e : new Error(String(e)));
  }

  /** Registers the handler of an application command (APPLICATIONS.md §5); the definitions are announced separately. */
  command(name: string, handler: CommandHandler): this {
    this.commands.register(name, handler);
    return this;
  }

  /**
   * Announces the application's command definitions (`PUT /applications/me/commands`, scope `commands`, §5.1): the
   * whole set is replaced, ids stay stable per name, at most 10 changes per hour (an identical set changes nothing).
   */
  async setCommands(commands: CommandDefinition[]): Promise<CommandSet> {
    const home = this.home;
    if (!home || (this.state !== "running" && this.state !== "starting")) throw new BotError("stopped", "The bot is not running");
    return home.api.commands.setMine(commands);
  }

  private track<T>(p: Promise<T>): Promise<T> {
    this.inflight.add(p);
    void p.finally(() => this.inflight.delete(p)).catch(() => undefined);
    return p;
  }

  // ---- Start ----------------------------------------------------------------------------------

  /** Who the bot is (after `start()`). */
  get info(): BotInfo {
    const me = this.me;
    const claims = this.claims;
    if (!me || !claims) throw new BotError("stopped", "The bot is not started");
    return { address: me.address, username: me.username, userId: me.id, applicationId: claims.app, applicationRef: `${claims.iss}/${claims.app}`, deviceId: claims.dev, homeDomain: claims.iss };
  }

  /** The current app token secret (changes with {@link rotateToken}). */
  get currentToken(): string {
    return this.token;
  }

  /** Domains of the nodes the bot is connected to (home node first). */
  get nodes(): string[] {
    return [...this.links.keys()];
  }

  /** Starts the bot; resolves when the home node and every room node of an installation are connected. */
  start(): Promise<void> {
    if (this.state === "stopping" || this.state === "stopped") return Promise.reject(new BotError("stopped", "A stopped bot cannot be started again; create a new one"));
    this.starting ??= this.startInner().catch(async (e: unknown) => {
      await this.stop().catch(() => undefined);
      throw e;
    });
    return this.starting;
  }

  private async startInner(): Promise<void> {
    this.state = "starting";
    const log = this.logger;
    const claims = appTokenClaims(this.token);
    if (claims.exp * 1000 <= Date.now()) throw new BotError("token_expired", "The app token has expired; ask the owner to reset it (application settings → tokens)");
    this.claims = claims;
    const endpoints = await this.homeEndpoints(claims.iss);
    const home = NodeLink.home(this.linkOptions(claims.iss, endpoints), () => this.token);
    this.home = home;
    this.links.set(claims.iss, home);

    let me: UserPrivate;
    try {
      me = await home.api.users.me();
    } catch (e) {
      if (e instanceof TavrnApiError && (e.status === 401 || e.status === 403)) throw new BotError("token_refused", `The home node refused the token (${e.code}): it was revoked or reset, or the application is disabled`, { cause: e });
      throw new BotError("node_invalid", `The home node ${claims.iss} could not be reached`, { cause: e });
    }
    if (me.kind !== "bot") throw new BotError("token_invalid", "The token does not belong to a bot account");
    this.me = me;
    log.info("bot account", { address: me.address, device: claims.dev, application: claims.app });

    await this.openState(home, me, claims);
    home.connect();
    await home.waitReady(READY_TIMEOUT_MS);
    await this.syncNode(home);
    await this.connectInstallations();
    const every = this.opts.maintenanceMs ?? MAINTENANCE_MS;
    this.maintenance = setInterval(() => void this.track(this.maintain()), every);
    this.maintenance.unref?.();
    this.state = "running";
    log.info("bot ready", { address: me.address, nodes: this.nodes });
    this.emit("ready", this.info);
  }

  private linkOptions(domain: string, endpoints: NodeEndpoints) {
    return {
      domain,
      endpoints,
      logger: this.logger,
      clientHeader: `tavrn-bot/${BOT_VERSION}`,
      fetchImpl: this.opts.fetchImpl,
      WebSocketImpl: this.opts.WebSocketImpl,
      handlers: {
        onEvent: (link: NodeLink, event: TavrnEvent) => this.onEvent(link, event),
        onReady: (link: NodeLink, first: boolean) => {
          if (!first) void this.track(this.syncNode(link));
        },
        onResync: (link: NodeLink) => void this.track(this.syncNode(link)),
        onFatal: (link: NodeLink, error: BotError) => this.onFatal(link, error),
      },
    };
  }

  /**
   * Endpoints of the home node. A URL is used as given for the API and the WebSocket (it may be an internal address);
   * its discovery document must name the token's issuer. A domain is resolved like any node (FEDERATION.md §1.4).
   */
  private async homeEndpoints(issuer: string): Promise<NodeEndpoints> {
    const node = this.opts.node.trim().replace(/\/+$/, "");
    if (/^https?:\/\//i.test(node)) {
      let doc: WellKnown;
      try {
        doc = await new TavrnApi({ baseUrl: node, fetchImpl: this.opts.fetchImpl }).node.wellKnown();
      } catch (e) {
        throw new BotError("node_invalid", `${node} is not reachable or not a tavrn node`, { cause: e });
      }
      if (doc?.domain !== issuer) throw new BotError("node_invalid", `${node} is the node ${String(doc?.domain)}, but the token was issued by ${issuer}`);
      return { domain: issuer, base: node, ws: `${node.replace(/^http/i, "ws")}/api/v1/ws`, web: typeof doc.web === "string" ? doc.web : node };
    }
    if (node.toLowerCase() !== issuer) throw new BotError("node_invalid", `The token was issued by ${issuer}, not by ${node}`);
    try {
      return await resolveNode(issuer, { allowInsecure: this.allowInsecure, fetchImpl: this.opts.fetchImpl });
    } catch (e) {
      throw new BotError("node_invalid", `The node ${issuer} could not be resolved`, { cause: e });
    }
  }

  /** Key file, identity, local state, device attestation, KeyPackages, session manager and backups. */
  private async openState(home: NodeLink, me: UserPrivate, claims: AppTokenClaims): Promise<void> {
    const log = this.logger;
    const keyPath = this.opts.keyFile?.trim() || defaultKeyFile(me.username);
    let master = await readKey({ key: this.opts.key, path: keyPath, logger: log });
    try {
      if (!me.has_identity_key) {
        if (!master) {
          master = await createKeyFile(keyPath, me.address);
          log.info("created the bot key file: keep it safe, it is the only backup of the bot's identity", { path: keyPath });
        }
        const identity = b64urlEncode(await identityKeyOf(master));
        try {
          await home.api.keys.putIdentity({ identity_public_key: identity });
          log.info("published the bot's identity key");
        } catch (e) {
          // Another process of the same bot was first: fine if it published the same key.
          if (code(e) !== "e2ee.identity_exists" || (await home.publicApi.keys.get(me.username)).identity_public_key !== identity) throw e;
        }
      } else {
        if (!master) {
          throw new BotError("key_missing", `The bot ${me.address} already has an identity key, but no key was configured (TAVRN_BOT_KEY or the key file ${keyPath}): restore the key file or ask the owner to reset the bot identity`);
        }
        const published = (await home.publicApi.keys.get(me.username)).identity_public_key ?? null;
        if (published !== b64urlEncode(await identityKeyOf(master))) {
          throw new BotError("key_mismatch", `The configured key does not belong to ${me.address}: restore the right key file or ask the owner to reset the bot identity`);
        }
      }

      const stateDir = this.opts.stateDir?.trim() || DEFAULT_STATE_DIR;
      const store = new FileKeyStore(stateDir);
      this.store = store;
      try {
        const status = await localStatus(store, me.address, claims.dev, {
          onStaleDevice: (old) => log.warn("the state directory belonged to another device of this bot (another token); starting over", { old_device: old, device: claims.dev }),
        });
        if (status === "locked") {
          try {
            await store.unlockWithMaster(me.address, master);
          } catch (e) {
            if (!(e instanceof LocalKeyMismatchError)) throw e;
            log.warn("the state directory belongs to an earlier identity of this bot (identity reset); starting over", { dir: stateDir });
            await store.wipe(me.address);
            await store.saveMaster(me.address, claims.dev, master);
          }
        } else if (status !== "unlocked") {
          await store.saveMaster(me.address, claims.dev, master);
        }
      } catch (e) {
        if (e instanceof StateDirInUseError) throw new BotError("state_dir_in_use", `The state directory ${stateDir} belongs to another account; give every bot its own directory`, { cause: e });
        throw e;
      }
    } finally {
      master?.fill(0);
    }

    await this.topUp();
    // Without `historyBackup` the manager sees an empty backup store that accepts nothing: no upload, no restore.
    const backups = this.opts.historyBackup === true ? home.api.backups : NO_BACKUPS;
    const api = mlsApiOf({
      home: { backups },
      node: (domain) => this.linkFor(domain).api,
      keys: (address) => this.keysOf(address),
    });
    const mls = await openMlsManager(this.store!, {
      api,
      address: me.address,
      deviceId: claims.dev,
      homeDomain: claims.iss,
      backupDelayMs: this.opts.backupDelayMs,
      onEvent: (e) => log.debug("mls", { ...e }),
    });
    if (!mls) throw new Error("the MLS client state is missing after the device setup");
    this.mls = mls;
    if (this.opts.historyBackup !== true) return;
    // A fresh state directory reads what the bot was entitled to before (§3.2: backups work with the app token).
    const restored = await mls.restoreBackups().catch((e: unknown) => {
      log.warn("history backups could not be restored", { error: e });
      return 0;
    });
    if (restored) log.info("restored history keys from the backups", { keys: restored });
    if (mls.hasPendingBackups()) await mls.flushBackups().catch(() => undefined);
  }

  /** Device attestation and KeyPackages (idempotent; single flight). */
  private topUp(): Promise<void> {
    const me = this.me;
    const home = this.home;
    const store = this.store;
    const claims = this.claims;
    if (!me || !home || !store || !claims) return Promise.resolve();
    this.topUpRunning ??= ensureDevice({
      api: { keys: { ...home.api.keys, get: (u: string) => home.publicApi.keys.get(u) }, secretStorage: home.api.secretStorage },
      username: me.username,
      address: me.address,
      deviceId: claims.dev,
      store,
      clientName: "tavrn-bot",
    }).finally(() => {
      this.topUpRunning = null;
    });
    return this.topUpRunning;
  }

  private async maintain(): Promise<void> {
    if (this.state !== "running") return;
    await this.topUp().catch((e: unknown) => this.logger.warn("KeyPackage top-up failed", { error: e }));
    for (const link of this.links.values()) await link.renewIfExpiring();
    if (this.mls?.hasPendingBackups()) await this.mls.flushBackups().catch(() => undefined);
  }

  // ---- Nodes ----------------------------------------------------------------------------------

  /** The link of a node the bot is connected to. */
  private linkFor(domain: string): NodeLink {
    const link = this.links.get(domain);
    if (!link) throw new BotError("not_member", `The bot has no session on ${domain}`);
    return link;
  }

  /** Where another node lives: its discovery document, or the home node's resolution (SRV, development peers). */
  private resolve(domain: string): Promise<NodeEndpoints> {
    const home = this.home!;
    return resolveNode(domain, { resolve: (d) => home.publicApi.federation.resolve(d), allowInsecure: this.allowInsecure, fetchImpl: this.opts.fetchImpl });
  }

  /** Public keys of `address` from the user's home node (FEDERATION.md §3.5). */
  private async keysOf(address: string): Promise<UserKeys> {
    const at = address.lastIndexOf("@");
    const username = address.slice(0, at);
    const domain = address.slice(at + 1);
    if (at < 1 || !domain) throw new TavrnApiError({ type: "about:blank", title: "Not found", status: 404, detail: address, code: "user.not_found" });
    if (domain === this.claims?.iss) return this.home!.publicApi.keys.get(username);
    const link = this.links.get(domain);
    if (link) return link.publicApi.keys.get(username);
    let client = this.publicClients.get(domain);
    if (!client) {
      const endpoints = await this.resolve(domain);
      client = new TavrnApi({ baseUrl: endpoints.base, clientHeader: `tavrn-bot/${BOT_VERSION}`, fetchImpl: this.opts.fetchImpl });
      this.publicClients.set(domain, client);
    }
    return client.keys.get(username);
  }

  /** Federated sessions on every room node of a remote installation (§4.5). */
  private async connectInstallations(): Promise<void> {
    let entries: { node: string }[];
    try {
      entries = await this.home!.api.applications.installations();
    } catch (e) {
      this.logger.warn("installations could not be listed", { error: e });
      return;
    }
    const nodes = [...new Set(entries.map((e) => e.node))].filter((d) => d !== this.claims!.iss);
    await Promise.all(nodes.map((d) => this.connectRemote(d)));
  }

  /** A federated session and WebSocket on a room node (single flight); null when it failed (logged). */
  private connectRemote(domain: string): Promise<NodeLink | null> {
    const existing = this.links.get(domain);
    if (existing) return Promise.resolve(existing);
    let running = this.connecting.get(domain);
    if (running) return running;
    running = (async () => {
      try {
        const endpoints = await this.resolve(domain);
        const link = await NodeLink.remote(this.linkOptions(domain, endpoints), this.home!.api);
        if (this.state === "stopping" || this.state === "stopped") return null;
        this.links.set(domain, link);
        link.connect();
        await link.waitReady(READY_TIMEOUT_MS);
        await this.syncNode(link);
        this.logger.info("connected to a room node", { node: domain });
        return link;
      } catch (e) {
        this.logger.warn("could not connect to a room node", { node: domain, error: e });
        const link = this.links.get(domain);
        link?.close();
        this.links.delete(domain);
        this.emit("error", e instanceof Error ? e : new Error(String(e)));
        return null;
      } finally {
        this.connecting.delete(domain);
      }
    })();
    this.connecting.set(domain, running);
    return running;
  }

  /** After connecting or a gap: Welcomes, the rooms and their channels, eager joins and catch-up. */
  private async syncNode(link: NodeLink): Promise<void> {
    const mls = this.mls;
    if (!mls || this.state === "stopping" || this.state === "stopped") return;
    await mls.processWelcomes(link.domain).catch((e: unknown) => this.logger.warn("Welcomes could not be processed", { node: link.domain, error: e }));
    let rooms: { id: string }[];
    try {
      rooms = await link.api.rooms.list();
    } catch (e) {
      this.logger.warn("rooms could not be listed", { node: link.domain, error: e });
      return;
    }
    for (const room of rooms) await this.loadRoom(link, room.id);
    for (const q of this.channels.keys()) {
      if (q.startsWith(`${link.domain}/`) && mls.hasGroup(q)) await mls.catchUp(q).catch(() => undefined);
    }
  }

  /** Reads a room's channels (the ones the bot can view) and joins their groups when eager. */
  private async loadRoom(link: NodeLink, roomId: string): Promise<void> {
    let channels: Channel[];
    try {
      channels = (await link.api.rooms.get(roomId)).channels;
    } catch (e) {
      this.logger.warn("room could not be loaded", { node: link.domain, room: roomId, error: e });
      return;
    }
    for (const q of [...this.channels.keys()]) if (this.channels.get(q)?.roomId === roomId && q.startsWith(`${link.domain}/`)) this.channels.delete(q);
    for (const c of channels) this.rememberChannel(link.domain, c);
    if (this.opts.joinPolicy === "lazy") return;
    for (const c of channels) {
      const q = qualify(link.domain, c.id);
      if (this.eagerTarget(q)) await this.join(q, false);
    }
  }

  private rememberChannel(node: string, c: Channel) {
    this.channels.set(qualify(node, c.id), { node, roomId: c.room_id, id: c.id, kind: c.kind, encrypted: !!c.encrypted, noBots: !!c.no_bots_effective });
  }

  private eagerTarget(q: string): boolean {
    const c = this.channels.get(q);
    return !!c && c.encrypted && !c.noBots && JOINABLE_KINDS.has(c.kind) && !this.mls?.hasGroup(q);
  }

  /** Joins a conversation's group (single flight per conversation); false when there is no group or it is refused. */
  private join(q: string, canCreate: boolean): Promise<boolean> {
    const mls = this.mls;
    if (!mls) return Promise.resolve(false);
    if (mls.hasGroup(q) && !canCreate) return Promise.resolve(true);
    let running = this.joining.get(q);
    if (running) return running;
    running = mls
      .ensureJoined(q, { canCreate })
      .then(
        (r) => {
          if (r === "joined") this.logger.debug("joined encryption group", { conversation: q });
          return r === "joined";
        },
        (e: unknown) => {
          // 403 mls.forbidden ("no bots", no access) or a node that is unreachable right now: try again on need.
          this.logger.warn("could not join the encryption group", { conversation: q, code: code(e) ?? (e instanceof MlsError ? e.code : undefined) });
          return false;
        },
      )
      .finally(() => this.joining.delete(q));
    this.joining.set(q, running);
    return running;
  }

  // ---- Events ---------------------------------------------------------------------------------

  private onEvent(link: NodeLink, event: TavrnEvent): void {
    if (this.state === "stopping" || this.state === "stopped") return;
    const data = (event.data ?? {}) as Record<string, unknown>;
    const mls = this.mls;
    switch (event.type) {
      case "message.create":
        void this.track(this.onMessage(link, data as unknown as Message));
        break;
      case "mls.commit": {
        if (!mls || typeof data.conversation_id !== "string") break;
        const q = qualify(link.domain, data.conversation_id);
        if (mls.hasGroup(q)) void this.track(mls.catchUp(q).catch(() => undefined));
        else if (this.opts.joinPolicy !== "lazy" && this.eagerTarget(q)) void this.track(this.join(q, false));
        break;
      }
      case "mls.welcome":
        if (mls)
          void this.track(
            mls
              .processWelcomes(link.domain)
              .then(() => this.topUp())
              .catch((e: unknown) => this.logger.warn("Welcome failed", { node: link.domain, error: e })),
          );
        break;
      case "channel.create":
      case "channel.update": {
        const c = data as unknown as Channel;
        if (typeof c.id !== "string" || typeof c.room_id !== "string") break;
        this.rememberChannel(link.domain, c);
        const q = qualify(link.domain, c.id);
        if (this.opts.joinPolicy !== "lazy" && this.eagerTarget(q)) void this.track(this.join(q, false));
        break;
      }
      case "channel.delete":
        if (typeof data.id === "string") this.channels.delete(qualify(link.domain, data.id));
        break;
      case "identity.changed":
        if (mls && typeof data.user === "string") mls.identityChanged(data.user);
        break;
      case "devices.changed":
        if (mls && typeof data.user === "string") mls.forgetDevices(data.user);
        break;
      case "application.install":
        void this.track(this.onInstall(link, data));
        break;
      case "application.uninstall":
        this.onUninstall(link, data);
        break;
      case "application.token_expiring":
        this.emit("tokenExpiring", { applicationId: String(data.application_id ?? ""), tokenId: String(data.token_id ?? ""), expiresAt: String(data.expires_at ?? ""), days: Number(data.days ?? 0) });
        break;
      case "command.invoke":
        void this.track(this.commands.handle(data, this.invokeContext(link)));
        break;
      default:
        break;
    }
    this.emit("event", { node: link.domain, event });
  }

  private onFatal(link: NodeLink, error: BotError): void {
    this.logger.error("connection ended", { node: link.domain, code: error.code });
    this.links.delete(link.domain);
    this.emit("error", error);
    // Without the home node the bot cannot work: stop (the process decides whether to exit).
    if (link === this.home) void this.stop();
  }

  private async onInstall(link: NodeLink, data: Record<string, unknown>): Promise<void> {
    const node = typeof data.node === "string" && data.node ? data.node : link.domain;
    const roomId = String(data.room_id ?? "");
    this.logger.info("installed in a room", { node, room: roomId });
    if (node === this.claims?.iss) {
      await this.loadRoom(this.home!, roomId);
    } else {
      // A remote installation: (re-)establish the session on that node; a known link reloads the room.
      const known = this.links.get(node);
      if (known && known.connected) await this.loadRoom(known, roomId);
      else {
        if (known) {
          known.close();
          this.links.delete(node);
        }
        await this.connectRemote(node);
      }
    }
    this.emit("install", { node, roomId, roomName: String(data.room_name ?? ""), installedBy: typeof data.installed_by === "string" ? data.installed_by : null });
  }

  private onUninstall(link: NodeLink, data: Record<string, unknown>): void {
    const node = typeof data.node === "string" && data.node ? data.node : link.domain;
    const roomId = String(data.room_id ?? "");
    this.logger.info("removed from a room", { node, room: roomId, reason: data.reason });
    for (const [q, c] of [...this.channels]) if (c.node === node && c.roomId === roomId) this.channels.delete(q);
    if (node !== this.claims?.iss && ![...this.channels.values()].some((c) => c.node === node)) {
      this.links.get(node)?.close();
      this.links.delete(node);
    }
    this.emit("uninstall", { node, roomId, reason: String(data.reason ?? "removed") });
  }

  private async onMessage(link: NodeLink, m: Message): Promise<void> {
    const mls = this.mls;
    const me = this.me;
    if (!mls || !me || typeof m?.id !== "string" || typeof m.conversation_id !== "string") return;
    if (m.author === me.address || !m.device_id) return; // own messages (also of other devices) and system messages
    const q = qualify(link.domain, m.conversation_id);
    let content: Record<string, unknown>;
    let signature: PlainStatus | null = null;
    if (m.encrypted) {
      if (!mls.hasGroup(q) && !(await this.join(q, false))) {
        this.emit("undecryptable", { node: link.domain, conversation: q, messageId: m.id, author: m.author, reason: "not_member" });
        return;
      }
      const d = await mls.decrypt(q, m);
      if (!d.ok) {
        this.logger.debug("message not decrypted", { conversation: q, message: m.id, reason: d.reason });
        this.emit("undecryptable", { node: link.domain, conversation: q, messageId: m.id, author: m.author, reason: d.reason });
        return;
      }
      content = d.content;
    } else {
      if (!m.content || typeof m.content !== "object" || Array.isArray(m.content)) return;
      content = m.content as Record<string, unknown>;
      signature = await mls.verifyPlaintext(q, m).catch(() => "unverifiable" as const);
    }
    const mentions = (m.mentions ?? []).map((a) => a.toLowerCase());
    const message: BotMessage = {
      id: m.id,
      node: link.domain,
      conversationId: m.conversation_id,
      conversation: q,
      roomId: this.channels.get(q)?.roomId ?? null,
      author: m.author,
      authorKind: m.author_kind ?? "user",
      deviceId: m.device_id ?? null,
      encrypted: !!m.encrypted,
      content,
      text: typeof content.body === "string" ? content.body : "",
      mentions,
      mentionsMe: mentions.includes(me.address.toLowerCase()),
      signature,
      replyToId: m.reply_to_id ?? null,
      threadId: m.thread_id ?? null,
      createdAt: m.created_at,
      raw: m,
      reply: (c, o = {}) => this.send(q, c, { ...o, replyTo: o.replyTo ?? m.id, threadId: o.threadId !== undefined ? o.threadId : (m.thread_id ?? null) }),
      replyInThread: (c, o = {}) => this.replyInThread(q, m, typeof content.body === "string" ? content.body : "", c, o),
    };
    this.emit("message", message);
  }

  private invokeContext(link: NodeLink): InvokeContext {
    const mls = this.mls;
    const crypto: CommandCrypto | null = mls
      ? {
          hasGroup: (q) => mls.hasGroup(q),
          decrypt: (q, envelope) => mls.decrypt(q, envelope),
          encrypt: (q, content) => mls.encrypt(q, content),
          join: (q) => void this.track(this.join(q, false)),
        }
      : null;
    return {
      node: link.domain,
      request: (method, path, body) => link.api.request(method, path, body),
      appRef: `${this.claims!.iss}/${this.claims!.app}`,
      deviceId: this.claims!.dev,
      crypto,
    };
  }

  // ---- Sending --------------------------------------------------------------------------------

  /** `<node>/<id>` for a qualified id, a bare id of the home node, or a received message's conversation. */
  private qualified(conversation: string | { conversation: string }): string {
    const raw = typeof conversation === "string" ? conversation : conversation.conversation;
    const q = raw.includes("/") ? raw : qualify(this.claims!.iss, raw);
    splitQualified(q);
    return q;
  }

  /** Whether a conversation is end-to-end encrypted: known channels, else the DM itself. */
  private async isEncrypted(link: NodeLink, q: string, id: string): Promise<boolean> {
    const known = this.channels.get(q)?.encrypted ?? this.direct.get(q);
    if (known !== undefined) return known;
    try {
      const c = await link.api.conversations.get(id);
      this.direct.set(q, !!c.encrypted);
      return !!c.encrypted;
    } catch (e) {
      if (code(e) !== "conversation.not_found" && !(e instanceof TavrnApiError && e.status === 404)) throw e;
    }
    for (const room of await link.api.rooms.list()) await this.loadRoom(link, room.id);
    const after = this.channels.get(q);
    if (!after) throw new BotError("not_member", `The bot is not a member of ${q}`);
    return after.encrypted;
  }

  /**
   * Sends a message: encrypted for the conversation's MLS group where the conversation is encrypted (joining it
   * first if needed), otherwise plaintext signed by the bot device. `conversation` is a qualified id
   * (`<node>/<id>`, as in {@link BotMessage.conversation}) or the bare id of a conversation on the home node.
   * Attachments are not supported yet.
   */
  async send(conversation: string | { conversation: string }, content: ReplyContent, opts: SendOptions = {}): Promise<Message> {
    if (this.state !== "running" && this.state !== "starting") throw new BotError("stopped", "The bot is not running");
    const mls = this.mls!;
    const q = this.qualified(conversation);
    const { domain, id } = splitQualified(q);
    const link = this.linkFor(domain);
    const object = normalizeContent(content);
    const mentions = mentionList(opts.mentions);
    const replyTo = opts.replyTo ?? null;
    const threadId = opts.threadId ?? null;
    const thread = threadId ? { thread_id: threadId } : {};
    if (await this.isEncrypted(link, q, id)) {
      if (!(await this.join(q, true))) throw new BotError("not_member", `The bot could not join the encryption group of ${q}`);
      const sealed = await mls.encrypt(q, object);
      return link.api.conversations.send(id, { content: sealed.content, epoch: sealed.epoch, mentions, reply_to_id: replyTo, ...thread });
    }
    const signature = mls.signPlaintext(q, { reply_to: replyTo, thread_id: threadId, mentions_everyone: false, mentions, attachments: [] }, object);
    return link.api.conversations.send(id, { content: object, mentions, reply_to_id: replyTo, signature, ...thread });
  }

  /** {@link BotMessage.replyInThread}: the message's thread, the thread it started, or a new one from it. */
  private async replyInThread(q: string, m: Message, text: string, content: ReplyContent, opts: SendOptions & { title?: string }): Promise<Message> {
    const existing = m.thread_id ?? m.thread?.id ?? null;
    if (existing) return this.send(q, content, { ...opts, threadId: existing });
    const roomId = this.channels.get(q)?.roomId;
    if (!roomId) throw new BotError("not_member", "Threads exist in room channels only");
    const { domain, id } = splitQualified(q);
    const link = this.linkFor(domain);
    const title = threadTitle(opts.title ?? text);
    const encrypted = await this.isEncrypted(link, q, id);
    if (encrypted && !(await this.join(q, true))) throw new BotError("not_member", `The bot could not join the encryption group of ${q}`);
    const sealedTitle = encrypted ? await this.mls!.encryptThreadTitle(q, title) : { title };
    let threadId: string;
    try {
      threadId = (await link.api.threads.create(roomId, id, { ...sealedTitle, root_message_id: m.id })).id;
    } catch (e) {
      // Another member started the thread in between: write into theirs.
      const started = e instanceof TavrnApiError && e.code === "thread.exists" ? (e.problem as { meta?: { thread_id?: unknown } }).meta?.thread_id : undefined;
      if (typeof started !== "string") throw e;
      threadId = started;
    }
    return this.send(q, content, { ...opts, threadId });
  }

  // ---- Tokens ---------------------------------------------------------------------------------

  /**
   * Rotates the app token (`POST /applications/me/tokens/rotate`, §2.2): same token and device, a new secret; the
   * previous one stays valid for 24 hours. The runtime uses the new secret at once and emits `tokenRotated`: store
   * it where the next start reads `TAVRN_BOT_TOKEN` from. At most once per 24 hours (`429`).
   */
  async rotateToken(): Promise<{ secret: string; expiresAt: string }> {
    const home = this.home;
    if (!home || this.state !== "running") throw new BotError("stopped", "The bot is not running");
    const rotated = await home.api.applications.rotate();
    this.token = rotated.secret;
    if (this.claims) this.claims = appTokenClaims(rotated.secret);
    const out = { secret: rotated.secret, expiresAt: rotated.expires_at };
    this.logger.info("app token rotated", { expires_at: rotated.expires_at });
    this.emit("tokenRotated", out);
    return out;
  }

  // ---- Stop -----------------------------------------------------------------------------------

  /** Closes every WebSocket, waits for running handlers, flushes pending history backups and locks the state. */
  async stop(): Promise<void> {
    if (this.state === "stopped" || this.state === "stopping") return;
    this.state = "stopping";
    if (this.maintenance) clearInterval(this.maintenance);
    for (const link of this.links.values()) link.close();
    // Handlers may still send; give them their time (they fail fast once the bot is stopped).
    for (let i = 0; i < 5 && this.inflight.size; i++) await Promise.allSettled([...this.inflight]);
    const mls = this.mls;
    if (mls) {
      await mls.flushBackups().catch((e: unknown) => this.logger.warn("history backups could not be flushed", { error: e }));
      mls.dispose();
    }
    await this.store?.close().catch(() => undefined);
    this.links.clear();
    this.state = "stopped";
    this.logger.info("bot stopped");
  }
}
