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
import { LocalKeyMismatchError, MlsError, checkPollVote, contentAttachments, decryptAttachment, encryptAttachment, encryptPollVote, ensureDevice, localStatus, mlsApiOf, openMlsManager, parsePoll, pollContent, pollHash, pollVoteContent, qualify, signPlainPollVote, signedAttachments, splitQualified, tallyPoll, verifyPlainAttachment, type ContentAttachment, type Decrypted, type MlsManager, type PlainStatus, type Poll, type PollInput, type PollSelection, type PollTally, type VoteCheck } from "@tavrn/e2ee";
import { FileKeyStore, StateDirInUseError } from "@tavrn/e2ee/node";
import { TavrnApi, TavrnApiError, b64urlEncode, newUlid, resolveNode, type Attachment, type AuditEntry, type Ban, type Channel, type CommandDefinition, type CommandSet, type ConversationRequest, type CreateMessageRequest, type Member, type Message, type MyPresence, type NodeEndpoints, type PollVote, type Profile, type Room, type RoomDetail, type SearchQuery, type SearchResponse, type TavrnEvent, type Thread, type ThreadListQuery, type User, type UserKeys, type UserPrivate, type WellKnown } from "@tavrn/sdk";
import { threadTitle } from "./threads";
import { CommandRouter, type CommandCrypto, type CommandHandler, type InvokeContext, type ReplyContent } from "./commands";
import { BotError } from "./errors";
import { createKeyFile, defaultKeyFile, identityKeyOf, readKey } from "./keyfile";
import { consoleLogger, type BotLogger } from "./logger";
import { sealUnderPolicy, type GhostPolicy } from "./ghosts";
import { NodeLink } from "./node-link";
import { retryingFetch, type RetryOptions } from "./ratelimit";
import { MessageTracker, validReaction } from "./reactions";
import { MAX_ATTACHMENTS, asFile, uploadCategory, type BotFile, type DownloadedFile } from "./uploads";
import { activityRequest, banSubject, checkContent, presenceRequest, reason as checkReason, timeoutMinutes, ulid, voiceStatus, type ActivityInput, type PresenceInput } from "./validate";
import { appTokenClaims, type AppTokenClaims } from "./token";

export const BOT_VERSION = "0.2.1";
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
  /**
   * Unknown devices in an encrypted conversation's group (`ENCRYPTION.md` §4.6; nobody can acknowledge the warning for
   * a bot). `strict` (default): leaves of retired devices awaiting cleanup are accepted, anything else (a key never
   * attested, a changed identity key without a continuity chain, a non-member) refuses the message with
   * `BotError("ghost")`. `accept`: send anyway and log every accepted leaf as a warning.
   */
  ghostPolicy?: GhostPolicy;
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
  /**
   * `429` answers (APPLICATIONS.md §2.7): by default the runtime waits the announced `Retry-After` and repeats the
   * request (3 times, at most 30 s per wait); beyond that the caller gets the `TavrnApiError` (status 429). `false`
   * hands every `429` to the caller at once.
   */
  rateLimit?: RetryOptions | false;
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
  /** The author's id on the hosting node (for moderation: `timeout`, `kick`). */
  authorId: string;
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
  /** The files attached to the message (names and types from the encrypted content in encrypted conversations). */
  attachments: BotAttachment[];
  createdAt: string;
  /** Set when the message was edited. */
  editedAt: string | null;
  raw: Message;
  /** Answers in the same conversation (and the same thread), as a reply to this message. */
  reply(content: ReplyContent, opts?: SendOptions): Promise<Message>;
  /**
   * Answers in a thread: the message's own thread, the thread it already started, or a new thread started from it
   * (`title` defaults to the start of the message's text). Room channels only.
   */
  replyInThread(content: ReplyContent, opts?: SendOptions & { title?: string }): Promise<Message>;
  /** Adds a reaction to this message ({@link Bot.react}). */
  react(emoji: string): Promise<Message>;
  /** Downloads an attachment (the first one by default), decrypted and checked against its hash. */
  download(attachmentId?: string): Promise<DownloadedFile>;
}

/** An attachment of a received message. */
export interface BotAttachment {
  id: string;
  name: string;
  mime: string;
  size: number;
  spoiler: boolean;
}

/**
 * A reaction was added or removed (`message.update`, PROTOCOL.md §7). `user` is null while the node does not say who
 * reacted (tavrn-protocol#43); without it the change is computed from the counts of messages the bot has seen since it
 * started, so changes on older messages are reported only once the node names the user.
 */
export interface ReactionEvent {
  node: string;
  /** Qualified conversation id. */
  conversation: string;
  conversationId: string;
  roomId: string | null;
  messageId: string;
  emoji: string;
  /** The count after the change. */
  count: number;
  added: boolean;
  user: string | null;
  encrypted: boolean;
  /** The message envelope after the change (content not decrypted; use {@link Bot.messages} for it). */
  message: Message;
}

/** `message.delete`: a message was deleted (by its author or a moderator). */
export interface MessageDeleteEvent {
  node: string;
  conversation: string;
  conversationId: string;
  roomId: string | null;
  messageId: string;
}

/** `member.join` / `member.leave` (scope `members:read`). */
export interface MemberEvent {
  node: string;
  roomId: string;
  userId: string;
  /** The member's address (joins; leaves name only the id). */
  user: string | null;
  /** The public user object of a join. */
  profile: User | null;
}

/** `thread.create`, `thread.update`, `thread.delete` (PROTOCOL.md §7e). */
export interface ThreadEvent {
  node: string;
  action: "create" | "update" | "delete";
  roomId: string;
  /** Qualified id of the thread's channel. */
  conversation: string;
  threadId: string;
  /** The thread (title not decrypted; {@link Bot.thread} returns it decrypted); null for deletions. */
  thread: Thread | null;
}

/** `conversation.request`: somebody asked to open a DM with the bot (PROTOCOL.md §8a, scope `dms` to answer). */
export interface DmRequestEvent {
  node: string;
  conversation: string;
  from: string;
  request: ConversationRequest;
}

/** A thread with its title decrypted where the channel is encrypted. */
export interface BotThread {
  id: string;
  node: string;
  /** Qualified id of the thread's channel (pass it with `threadId` to `send`). */
  conversation: string;
  roomId: string;
  channelId: string;
  /** The title (decrypted); null when it cannot be read. */
  title: string | null;
  encrypted: boolean;
  rootMessageId: string | null;
  createdBy: string;
  messageCount: number;
  lastMessageAt: string;
  archived: boolean;
  locked: boolean;
  tags: string[];
  raw: Thread;
}

/** Options of {@link Bot.createThread}. */
export interface CreateThreadOptions {
  /** 1–100 characters (encrypted in encrypted channels). */
  title: string;
  /** Start the thread from this channel message (text and announcement channels). */
  rootMessageId?: string;
  /** The thread's first message; required for forum posts. */
  content?: ReplyContent;
  /** Forum posts: tag ids of the channel (at most 5). */
  tags?: string[];
  mentions?: string[];
}

/** A room on a node: a qualified id `<node>/<room id>`, a bare id of the home node, or an object naming both. */
export type RoomRef = string | { node: string; roomId: string | null };

export { threadTitle };

export interface SendOptions {
  /** Message id this one answers. */
  replyTo?: string | null;
  /** Addresses mentioned (lowercase, without duplicates). */
  mentions?: string[];
  /** Write into this thread of the channel (PROTOCOL.md §7e). */
  threadId?: string | null;
  /**
   * Files to attach (at most 10; needs `attach_files` and the channel's upload categories). Encrypted conversations
   * get the files encrypted with a fresh key each; name, type and key travel inside the encrypted message.
   */
  files?: BotFile[];
}

/** Options of {@link Bot.createPoll}. */
export interface PollOptions extends SendOptions {
  /** The plaintext close time (PROTOCOL.md §7g): 1 minute to 1 year ahead; needs `create_polls`. */
  closesAt?: string | Date | null;
}

/** A poll with its checked votes and the tally ({@link Bot.votes}). */
export interface PollResults {
  message: Message;
  poll: Poll;
  /** `poll_hash` of this version of the poll. */
  hash: string;
  closesAt: string | null;
  votes: { record: PollVote; check: VoteCheck }[];
  tally: PollTally;
}

/** `poll.vote` and `poll.vote.delete` (PROTOCOL.md §7g): call {@link Bot.votes} for the checked tally. */
export interface PollVoteEvent {
  node: string;
  /** Qualified conversation id. */
  conversation: string;
  messageId: string;
  user: string;
  /** The record (null when the vote was retracted). */
  record: PollVote | null;
  retracted: boolean;
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
  /** A member voted on a poll, changed or retracted a vote (the bot's own votes included). */
  pollVote: [PollVoteEvent];
  /** A reaction was added or removed (js #18; see {@link ReactionEvent} for what the node tells). */
  reaction: [ReactionEvent];
  /** A message the bot had seen was edited by somebody else: the new version, decrypted. */
  messageEdit: [BotMessage];
  /** A message was deleted. */
  messageDelete: [MessageDeleteEvent];
  /** Somebody joined a room the bot is in (`members:read`). */
  memberJoin: [MemberEvent];
  /** Somebody left, was kicked or banned (`members:read`). */
  memberLeave: [MemberEvent];
  /** A thread was started, changed (title, archive, lock, counters) or deleted. */
  thread: [ThreadEvent];
  /** A message request (somebody who is not the owner opened a DM with the bot): answer it with `acceptDm`/`declineDm`. */
  dmRequest: [DmRequestEvent];
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
  /** DMs: whether they are encrypted (always, on current nodes) and their members. */
  private readonly direct = new Map<string, { encrypted: boolean; members: string[] }>();
  private readonly tracker = new MessageTracker();
  /** Nodes announcing `threads.client_ids` (PROTOCOL.md §7e), per domain. */
  private readonly clientIds = new Map<string, Promise<boolean>>();
  private readonly fetchImpl: typeof fetch | undefined;
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
    this.fetchImpl = opts.rateLimit === false ? opts.fetchImpl : retryingFetch(opts.fetchImpl ?? ((input, init) => fetch(input, init)), { logger: this.logger, ...opts.rateLimit });
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
      fetchImpl: this.fetchImpl,
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
        doc = await new TavrnApi({ baseUrl: node, fetchImpl: this.fetchImpl }).node.wellKnown();
      } catch (e) {
        throw new BotError("node_invalid", `${node} is not reachable or not a tavrn node`, { cause: e });
      }
      if (doc?.domain !== issuer) throw new BotError("node_invalid", `${node} is the node ${String(doc?.domain)}, but the token was issued by ${issuer}`);
      return { domain: issuer, base: node, ws: `${node.replace(/^http/i, "ws")}/api/v1/ws`, web: typeof doc.web === "string" ? doc.web : node };
    }
    if (node.toLowerCase() !== issuer) throw new BotError("node_invalid", `The token was issued by ${issuer}, not by ${node}`);
    try {
      return await resolveNode(issuer, { allowInsecure: this.allowInsecure, fetchImpl: this.fetchImpl });
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
    return resolveNode(domain, { resolve: (d) => home.publicApi.federation.resolve(d), allowInsecure: this.allowInsecure, fetchImpl: this.fetchImpl });
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
      client = new TavrnApi({ baseUrl: endpoints.base, clientHeader: `tavrn-bot/${BOT_VERSION}`, fetchImpl: this.fetchImpl });
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
      case "poll.vote":
      case "poll.vote.delete": {
        if (typeof data.conversation_id !== "string" || typeof data.message_id !== "string" || typeof data.user !== "string") break;
        const retracted = event.type === "poll.vote.delete";
        this.emit("pollVote", { node: link.domain, conversation: qualify(link.domain, data.conversation_id), messageId: data.message_id, user: data.user, record: retracted ? null : (data as unknown as PollVote), retracted });
        break;
      }
      case "message.update":
        this.onMessageUpdate(link, data as unknown as Message);
        break;
      case "message.delete": {
        if (typeof data.conversation_id !== "string" || typeof data.id !== "string") break;
        const q = qualify(link.domain, data.conversation_id);
        this.tracker.forget(q, data.id);
        this.emit("messageDelete", { node: link.domain, conversation: q, conversationId: data.conversation_id, roomId: typeof data.room_id === "string" ? data.room_id : null, messageId: data.id });
        break;
      }
      case "member.join": {
        const user = data.user as User | undefined;
        if (typeof data.room_id !== "string" || !user || typeof user.id !== "string") break;
        this.emit("memberJoin", { node: link.domain, roomId: data.room_id, userId: user.id, user: typeof user.address === "string" ? user.address : null, profile: user });
        break;
      }
      case "member.leave":
        if (typeof data.room_id !== "string" || typeof data.user_id !== "string") break;
        this.emit("memberLeave", { node: link.domain, roomId: data.room_id, userId: data.user_id, user: typeof data.user === "string" ? data.user : null, profile: null });
        break;
      case "thread.create":
      case "thread.update":
      case "thread.delete": {
        const action = event.type.slice("thread.".length) as ThreadEvent["action"];
        const thread = action === "delete" ? null : ((data.thread ?? null) as Thread | null);
        const channelId = thread?.channel_id ?? data.channel_id;
        const threadId = thread?.id ?? data.id;
        if (typeof data.room_id !== "string" || typeof channelId !== "string" || typeof threadId !== "string") break;
        this.emit("thread", { node: link.domain, action, roomId: data.room_id, conversation: qualify(link.domain, channelId), threadId, thread });
        break;
      }
      case "conversation.request": {
        const request = data.request as ConversationRequest | undefined;
        const conv = request?.conversation;
        if (!request || !conv || typeof conv.id !== "string") break;
        this.emit("dmRequest", { node: link.domain, conversation: qualify(link.domain, conv.id), from: request.from?.address ?? "", request });
        break;
      }
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
    const me = this.me;
    if (!this.mls || !me || typeof m?.id !== "string" || typeof m.conversation_id !== "string") return;
    const q = qualify(link.domain, m.conversation_id);
    this.tracker.remember(q, m);
    if (m.author === me.address || !m.device_id) return; // own messages (also of other devices) and system messages
    const read = await this.readMessage(link, m);
    // Plaintext that is no content object is dropped silently; encrypted messages that cannot be read are announced.
    if (!("reason" in read)) this.emit("message", read);
    else if (m.encrypted) this.emit("undecryptable", { node: link.domain, conversation: q, messageId: m.id, author: m.author, reason: read.reason });
  }

  /** `message.update`: reaction changes become `reaction` events, edits of others' messages `messageEdit`. */
  private onMessageUpdate(link: NodeLink, m: Message): void {
    if (typeof m?.id !== "string" || typeof m.conversation_id !== "string") return;
    const q = qualify(link.domain, m.conversation_id);
    const changes = this.tracker.update(q, m);
    const roomId = this.channels.get(q)?.roomId ?? null;
    for (const r of changes.reactions) {
      this.emit("reaction", { node: link.domain, conversation: q, conversationId: m.conversation_id, roomId, messageId: m.id, emoji: r.emoji, count: r.count, added: r.added, user: r.user, encrypted: !!m.encrypted, message: m });
    }
    if (changes.edited && m.author !== this.me?.address && m.device_id) {
      void this.track(
        this.readMessage(link, m).then((read) => {
          if (!("reason" in read)) this.emit("messageEdit", read);
        }),
      );
    }
  }

  /** A message as the bot reads it: decrypted (joining the group if needed) or with the reason it cannot be read. */
  private async readMessage(link: NodeLink, m: Message): Promise<BotMessage | { reason: UndecryptableEvent["reason"] }> {
    const mls = this.mls!;
    const me = this.me!;
    const q = qualify(link.domain, m.conversation_id);
    let content: Record<string, unknown>;
    let signature: PlainStatus | null = null;
    let files: (BotAttachment & { crypto: ContentAttachment | null; sha256: string })[];
    if (m.encrypted) {
      if (!mls.hasGroup(q) && !(await this.join(q, false))) return { reason: "not_member" };
      const d = await mls.decrypt(q, m);
      if (!d.ok) {
        this.logger.debug("message not decrypted", { conversation: q, message: m.id, reason: d.reason });
        return { reason: d.reason };
      }
      content = d.content;
      files = contentAttachments(content, m.attachments).map((a) => ({ id: a.id, name: a.name, mime: a.mime, size: a.size, spoiler: a.spoiler === true, crypto: a, sha256: a.sha256 }));
    } else {
      if (!m.content || typeof m.content !== "object" || Array.isArray(m.content)) return { reason: "invalid" };
      content = m.content as Record<string, unknown>;
      signature = m.device_id ? await mls.verifyPlaintext(q, m).catch(() => "unverifiable" as const) : null;
      files = (m.attachments ?? []).map((a: Attachment) => ({ id: a.id, name: a.name, mime: a.mime, size: a.size, spoiler: a.spoiler === true, crypto: null, sha256: a.sha256 }));
    }
    const mentions = (m.mentions ?? []).map((a) => a.toLowerCase());
    const text = typeof content.body === "string" ? content.body : "";
    const download = async (attachmentId?: string): Promise<DownloadedFile> => {
      const f = attachmentId ? files.find((a) => a.id === attachmentId) : files[0];
      if (!f) throw new BotError("not_found", attachmentId ? `Message ${m.id} has no attachment ${attachmentId}` : `Message ${m.id} has no attachments`);
      const bytes = new Uint8Array(await (await link.api.attachments.download(f.id)).arrayBuffer());
      let data: Uint8Array;
      if (f.crypto) data = await decryptAttachment(bytes, f.crypto);
      else {
        await verifyPlainAttachment(bytes, f.sha256);
        data = bytes;
      }
      return { id: f.id, name: f.name, mime: f.mime, size: data.length, data };
    };
    return {
      id: m.id,
      node: link.domain,
      conversationId: m.conversation_id,
      conversation: q,
      roomId: this.channels.get(q)?.roomId ?? null,
      author: m.author,
      authorId: m.author_id,
      authorKind: m.author_kind ?? "user",
      deviceId: m.device_id ?? null,
      encrypted: !!m.encrypted,
      content,
      text,
      mentions,
      mentionsMe: mentions.includes(me.address.toLowerCase()),
      signature,
      replyToId: m.reply_to_id ?? null,
      threadId: m.thread_id ?? null,
      attachments: files.map(({ id, name, mime, size, spoiler }) => ({ id, name, mime, size, spoiler })),
      createdAt: m.created_at,
      editedAt: m.edited_at ?? null,
      raw: m,
      reply: (c, o = {}) => this.send(q, c, { ...o, replyTo: o.replyTo ?? m.id, threadId: o.threadId !== undefined ? o.threadId : (m.thread_id ?? null) }),
      replyInThread: (c, o = {}) => this.replyInThread(q, m, text, c, o),
      react: (emoji) => this.react(q, m.id, emoji),
      download,
    };
  }

  private invokeContext(link: NodeLink): InvokeContext {
    const mls = this.mls;
    const crypto: CommandCrypto | null = mls
      ? {
          hasGroup: (q) => mls.hasGroup(q),
          decrypt: (q, envelope) => mls.decrypt(q, envelope),
          encrypt: (q, content, opts) => this.seal(q, () => mls.encrypt(q, content, opts)),
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

  /** An encryption under the bot's ghost policy (see {@link BotOptions.ghostPolicy}). */
  private seal<T>(q: string, fn: () => Promise<T>): Promise<T> {
    return sealUnderPolicy(this.mls!, q, this.opts.ghostPolicy ?? "strict", this.logger, fn);
  }

  /** `<node>/<id>` for a qualified id, a bare id of the home node, or a received message's conversation. */
  private qualified(conversation: string | { conversation: string }): string {
    const raw = typeof conversation === "string" ? conversation : conversation.conversation;
    const q = raw.includes("/") ? raw : qualify(this.claims!.iss, raw);
    splitQualified(q);
    return q;
  }

  /** Whether a conversation is end-to-end encrypted: known channels, else the DM itself. */
  private async isEncrypted(link: NodeLink, q: string, id: string): Promise<boolean> {
    const known = this.channels.get(q)?.encrypted ?? this.direct.get(q)?.encrypted;
    if (known !== undefined) return known;
    try {
      const c = await link.api.conversations.get(id);
      this.direct.set(q, { encrypted: !!c.encrypted, members: (c.members ?? []).map((u) => u.address) });
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
   * `content` is text or a content object; text content is checked first (body length, embeds of APPLICATIONS.md
   * §6.4), `opts.files` are uploaded (encrypted where the conversation is) and attached.
   */
  async send(conversation: string | { conversation: string }, content: ReplyContent, opts: SendOptions = {}): Promise<Message> {
    return this.sendObject(conversation, normalizeContent(content), opts, {});
  }

  private running(): void {
    if (this.state !== "running" && this.state !== "starting") throw new BotError("stopped", "The bot is not running");
  }

  /** The qualified id, its node and bare id, and the link to that node. */
  private target(conversation: string | { conversation: string }): { q: string; domain: string; id: string; link: NodeLink } {
    this.running();
    const q = this.qualified(conversation);
    const { domain, id } = splitQualified(q);
    return { q, domain, id, link: this.linkFor(domain) };
  }

  /** Joins an encrypted conversation's group before writing; in DMs also adds the members' new devices (§4.2). */
  private async prepareEncrypted(q: string): Promise<void> {
    if (!(await this.join(q, true))) throw new BotError("not_member", `The bot could not join the encryption group of ${q}`);
    const dm = this.direct.get(q);
    if (dm?.members.length) await this.mls!.addMissingDevices(q, dm.members).catch((e: unknown) => this.logger.warn("devices of the DM could not be added", { conversation: q, error: e }));
  }

  /** Runs an encrypted write once more after catching up when the node says the epoch is stale (ENCRYPTION.md §5.3). */
  private async freshEpoch<T>(q: string, post: () => Promise<T>): Promise<T> {
    try {
      return await post();
    } catch (e) {
      if (!(e instanceof TavrnApiError && e.code === "mls.epoch_stale")) throw e;
      await this.mls!.catchUp(q);
      return post();
    }
  }

  /** Uploads the files of a message: plaintext as they are, encrypted as ciphertext with their keys for the content. */
  private async upload(link: NodeLink, id: string, encrypted: boolean, files: BotFile[]): Promise<{ stored: Attachment[]; keys: ContentAttachment[] }> {
    if (files.length > MAX_ATTACHMENTS) throw new RangeError(`at most ${MAX_ATTACHMENTS} files per message`);
    const stored: Attachment[] = [];
    const keys: ContentAttachment[] = [];
    for (const f of files) {
      const file = await asFile(f);
      if (!encrypted) {
        stored.push({ ...(await link.api.attachments.uploadToConversation(id, file, file.name)), spoiler: f.spoiler === true });
        continue;
      }
      // ENCRYPTION.md §6: only ciphertext leaves the bot; the category is declared (PROTOCOL.md §7a).
      const { blob, meta } = await encryptAttachment(file);
      const up = await link.api.attachments.uploadToConversation(id, blob, "", undefined, uploadCategory(file.name, file.type));
      if (up.sha256 !== meta.sha256) throw new BotError("node_invalid", "The node stored another ciphertext than the bot uploaded");
      stored.push(up);
      keys.push({ id: up.id, ...meta, ...(f.spoiler ? { spoiler: true } : {}) });
    }
    return { stored, keys };
  }

  private async sendObject(conversation: string | { conversation: string }, object: Record<string, unknown>, opts: SendOptions, extra: { poll_closes_at?: string }): Promise<Message> {
    const { q, id, link } = this.target(conversation);
    const mls = this.mls!;
    const mentions = mentionList(opts.mentions);
    const replyTo = opts.replyTo ?? null;
    const threadId = opts.threadId ?? null;
    const thread = threadId ? { thread_id: threadId } : {};
    const files = opts.files ?? [];
    if (files.length && (object.type === "text" || object.type === "action") && typeof object.body === "string" && !object.body.trim()) object = { ...object, body: "📎" };
    checkContent(object);
    const encrypted = await this.isEncrypted(link, q, id);
    if (encrypted) await this.prepareEncrypted(q);
    const { stored, keys } = files.length ? await this.upload(link, id, encrypted, files) : { stored: [], keys: [] };
    const attachments = stored.length ? { attachments: stored.map((a) => a.id) } : {};
    let sent: Message;
    if (encrypted) {
      const content = keys.length ? { ...object, attachments: keys } : object;
      // Thread and reply are signed inside the content (ENCRYPTION.md §5.2); a stale epoch (§5.3) is caught up once.
      sent = await this.freshEpoch(q, async () => {
        const sealed = await this.seal(q, () => mls.encrypt(q, content, { ctx: { thread_id: threadId, reply_to: replyTo } }));
        return link.api.conversations.send(id, { content: sealed.content, epoch: sealed.epoch, mentions, reply_to_id: replyTo, ...attachments, ...thread, ...extra });
      });
    } else {
      const spoilers = stored.filter((a) => a.spoiler).map((a) => a.id);
      const signature = mls.signPlaintext(q, { reply_to: replyTo, thread_id: threadId, mentions_everyone: false, mentions, attachments: signedAttachments(stored) }, object);
      sent = await link.api.conversations.send(id, { content: object, mentions, reply_to_id: replyTo, signature, ...attachments, ...(spoilers.length ? { spoilers } : {}), ...thread, ...extra } satisfies CreateMessageRequest);
    }
    this.tracker.remember(q, sent);
    return sent;
  }

  // ---- Polls (PROTOCOL.md §7g) ----------------------------------------------------------------------

  /**
   * Sends a poll: a {@link PollInput} (built with `pollContent`) or a ready poll content object, encrypted or signed
   * like every message, with an optional close time. Needs `create_polls` (and `messages:write`).
   */
  async createPoll(conversation: string | { conversation: string }, poll: PollInput | Record<string, unknown>, opts: PollOptions = {}): Promise<Message> {
    const content = "type" in poll ? (poll as Record<string, unknown>) : pollContent(poll as PollInput);
    if (!parsePoll(content)) throw new RangeError("invalid poll (PROTOCOL.md §7g)");
    const { closesAt, ...send } = opts;
    const extra = closesAt ? { poll_closes_at: closesAt instanceof Date ? closesAt.toISOString() : closesAt } : {};
    return this.sendObject(conversation, content, send, extra);
  }

  /** The poll message, its checked content and hash (`not_a_poll` when it is missing or cannot be read as a poll). */
  private async loadPoll(conversation: string | { conversation: string }, messageId: string): Promise<{ q: string; id: string; link: NodeLink; message: Message; poll: Poll; hash: string; encrypted: boolean }> {
    if (this.state !== "running" && this.state !== "starting") throw new BotError("stopped", "The bot is not running");
    const mls = this.mls!;
    const q = this.qualified(conversation);
    const { domain, id } = splitQualified(q);
    const link = this.linkFor(domain);
    const [message] = await link.api.conversations.messages(id, { around: messageId, limit: 1 });
    if (!message || message.id !== messageId) throw new BotError("not_a_poll", `No message ${messageId} in ${q}`);
    let content: Record<string, unknown> | null = null;
    if (message.encrypted) {
      if (!mls.hasGroup(q) && !(await this.join(q, false))) throw new BotError("not_member", `The bot is not a member of the encryption group of ${q}`);
      const d = await mls.decrypt(q, message);
      content = d.ok ? d.content : null;
    } else if (message.content && typeof message.content === "object" && !Array.isArray(message.content)) {
      content = message.content as Record<string, unknown>;
    }
    const poll = content ? parsePoll(content) : null;
    if (!content || !poll) throw new BotError("not_a_poll", `Message ${messageId} is not a readable poll`);
    return { q, id, link, message, poll, hash: await pollHash(content), encrypted: !!message.encrypted };
  }

  /** The poll's vote records, each checked against this version of the poll, and the tally (one vote per member). */
  async votes(conversation: string | { conversation: string }, messageId: string): Promise<PollResults> {
    const { q, id, link, message, poll, hash } = await this.loadPoll(conversation, messageId);
    const mls = this.mls!;
    const { items } = await link.api.polls.votes(id, messageId);
    const votes = await Promise.all(items.map(async (record) => ({ record, check: await checkPollVote(mls, q, record, poll, hash) })));
    const closesAt = message.poll_closes_at ?? null;
    const tally = tallyPoll(poll, votes.map((v) => ({ user: v.record.user, updated_at: v.record.updated_at, check: v.check })), { closesAt });
    return { message, poll, hash, closesAt, votes, tally };
  }

  /** Casts or replaces the bot's vote: option ids of a choice poll, or answers per slot of a date poll. */
  async vote(conversation: string | { conversation: string }, messageId: string, selection: PollSelection): Promise<PollVote> {
    const { q, id, link, poll, hash, encrypted } = await this.loadPoll(conversation, messageId);
    const mls = this.mls!;
    const content = pollVoteContent(poll, messageId, hash, selection);
    if (!encrypted) return link.api.polls.vote(id, messageId, { content, signature: signPlainPollVote(mls, q, content) });
    const post = async () => {
      const sealed = await this.seal(q, () => encryptPollVote(mls, q, content));
      return link.api.polls.vote(id, messageId, { content: sealed.content, epoch: sealed.epoch });
    };
    try {
      return await post();
    } catch (e) {
      if (!(e instanceof TavrnApiError && e.code === "mls.epoch_stale")) throw e;
      await mls.catchUp(q);
      return post();
    }
  }

  /** Retracts the bot's vote. */
  async retractVote(conversation: string | { conversation: string }, messageId: string): Promise<void> {
    const q = this.qualified(conversation);
    const { domain, id } = splitQualified(q);
    await this.linkFor(domain).api.polls.retract(id, messageId);
  }

  /** Listens to `poll.vote` and `poll.vote.delete` ({@link BotEvents.pollVote}); returns the unsubscribe function. */
  onPollVote(listener: (event: PollVoteEvent) => void | Promise<void>): () => void {
    return this.on("pollVote", listener);
  }

  /**
   * Closes a poll now, or moves its close time earlier (`at`, never later; PROTOCOL.md §7g). The bot must be the
   * poll's author or hold `manage_messages` (scope `moderation`).
   */
  async closePoll(conversation: string | { conversation: string }, messageId: string, at?: string | Date): Promise<Message> {
    const { id, link } = this.target(conversation);
    return link.api.polls.close(id, ulid("messageId", messageId), at instanceof Date ? at.toISOString() : at);
  }

  /** {@link BotMessage.replyInThread}: the message's thread, the thread it started, or a new one from it. */
  private async replyInThread(q: string, m: Message, text: string, content: ReplyContent, opts: SendOptions & { title?: string }): Promise<Message> {
    const existing = m.thread_id ?? m.thread?.id ?? null;
    if (existing) return this.send(q, content, { ...opts, threadId: existing });
    const { title, ...send } = opts;
    const threadId = (await this.startThread(q, { title: threadTitle(title ?? text), rootMessageId: m.id })).id;
    return this.send(q, content, { ...send, threadId });
  }

  // ---- Messages: history, edits, reactions, pins -----------------------------------------------

  /**
   * The API client with the bot's credentials on `node` (default: the home node), for routes without a helper here.
   * Requests go through the same rate-limit handling; encrypted content is the caller's to handle.
   */
  api(node?: string): TavrnApi {
    this.running();
    return this.linkFor(node ?? this.claims!.iss).api;
  }

  /** One message of a conversation (the page around it), or `not_found`. */
  private async fetchMessage(link: NodeLink, id: string, messageId: string): Promise<Message> {
    const [message] = await link.api.conversations.messages(id, { around: ulid("messageId", messageId), limit: 1 }).catch((e: unknown) => {
      if (code(e) === "message.not_found") return [];
      throw e;
    });
    if (!message || message.id !== messageId) throw new BotError("not_found", `No message ${messageId} in this conversation`);
    return message;
  }

  /**
   * A page of a conversation's history as the bot reads it (scope `messages:read`): decrypted, newest first (`after`:
   * oldest first, as the node pages). Messages the bot cannot read (sent before it joined, …) are left out; the
   * bot's own messages are included. `threadId` pages one thread.
   */
  async messages(conversation: string | { conversation: string }, query: { limit?: number; before?: string; after?: string; around?: string; threadId?: string } = {}): Promise<BotMessage[]> {
    const { q, id, link } = this.target(conversation);
    const { threadId, ...page } = query;
    if (page.limit !== undefined && !(Number.isInteger(page.limit) && page.limit >= 1 && page.limit <= 100)) throw new RangeError("limit: 1 to 100");
    const list = await link.api.conversations.messages(id, { ...page, ...(threadId ? { thread: threadId } : {}) });
    const out: BotMessage[] = [];
    for (const m of list) {
      this.tracker.remember(q, m);
      const read = await this.readMessage(link, m);
      if (!("reason" in read)) out.push(read);
    }
    return out;
  }

  /**
   * Edits one of the bot's messages. Text replaces the body and keeps the rest of the content (attachments, embeds);
   * a content object replaces the content (the attachments of an encrypted message stay unless it names its own).
   * Encrypted messages are encrypted again under the current epoch with the same signed context, plaintext ones
   * signed again. Polls cannot be edited (`message.poll_immutable`).
   */
  async edit(conversation: string | { conversation: string }, messageId: string, content: ReplyContent, opts: { mentions?: string[] } = {}): Promise<Message> {
    const { q, id, link } = this.target(conversation);
    const m = await this.fetchMessage(link, id, messageId);
    if (m.author !== this.me!.address) throw new BotError("not_author", "A bot can edit only its own messages");
    const encrypted = !!m.encrypted;
    if (encrypted) await this.prepareEncrypted(q);
    const mls = this.mls!;
    let previous: Record<string, unknown> | null = null;
    if (encrypted) {
      const d = await mls.decrypt(q, m);
      previous = d.ok ? d.content : null;
    } else if (m.content && typeof m.content === "object" && !Array.isArray(m.content)) previous = m.content as Record<string, unknown>;
    let next: Record<string, unknown>;
    if (typeof content === "string") {
      if (!previous) throw new BotError("not_found", `Message ${messageId} cannot be read, so its text cannot be replaced`);
      const { ctx: _ctx, ...rest } = previous;
      next = { ...rest, type: previous.type === "action" ? "action" : "text", body: content };
    } else {
      next = normalizeContent(content);
      if (encrypted && previous && Array.isArray(previous.attachments) && next.attachments === undefined) next = { ...next, attachments: previous.attachments };
    }
    checkContent(next);
    const mentions = opts.mentions ? mentionList(opts.mentions) : (m.mentions ?? []);
    const ctx = { thread_id: m.thread_id ?? null, reply_to: m.reply_to_id ?? null };
    let edited: Message;
    if (encrypted) {
      edited = await this.freshEpoch(q, async () => {
        const sealed = await this.seal(q, () => mls.encrypt(q, next, { ctx }));
        return link.api.conversations.edit(id, messageId, { content: sealed.content, epoch: sealed.epoch, mentions, mentions_everyone: m.mentions_everyone });
      });
    } else {
      const signature = mls.signPlaintext(q, { reply_to: ctx.reply_to, thread_id: ctx.thread_id, mentions_everyone: m.mentions_everyone, mentions, attachments: signedAttachments(m.attachments ?? []) }, next);
      edited = await link.api.conversations.edit(id, messageId, { content: next, mentions, mentions_everyone: m.mentions_everyone, signature });
    }
    this.tracker.remember(q, edited);
    return edited;
  }

  /**
   * Deletes a message: the bot's own, or anybody's with `manage_messages` (scope `moderation`). Entries of the
   * welcome channel cannot be deleted (`message.system_protected`).
   */
  async deleteMessage(conversation: string | { conversation: string }, messageId: string): Promise<void> {
    const { q, id, link } = this.target(conversation);
    await link.api.conversations.deleteMessage(id, ulid("messageId", messageId));
    this.tracker.forget(q, messageId);
  }

  /**
   * Adds a reaction (`add_reactions`, scope `messages:write`): a Unicode emoji, `:name:` of the room's custom emojis or
   * a custom emoji token `<:name:ID>`. Reactions are plaintext metadata, also in encrypted conversations.
   */
  async react(conversation: string | { conversation: string }, messageId: string, emoji: string): Promise<Message> {
    if (!validReaction(emoji)) throw new RangeError("emoji: a Unicode emoji (at most 16 characters), :name: or <:name:ID>");
    const { q, id, link } = this.target(conversation);
    const m = await link.api.conversations.react(id, ulid("messageId", messageId), emoji);
    this.tracker.update(q, m);
    return m;
  }

  /** Removes the bot's reaction. */
  async unreact(conversation: string | { conversation: string }, messageId: string, emoji: string): Promise<Message> {
    if (!validReaction(emoji)) throw new RangeError("emoji: a Unicode emoji (at most 16 characters), :name: or <:name:ID>");
    const { q, id, link } = this.target(conversation);
    const m = await link.api.conversations.unreact(id, ulid("messageId", messageId), emoji);
    this.tracker.update(q, m);
    return m;
  }

  /** The reaction counts of a message the bot has seen since it started (null otherwise; {@link messages} fetches it). */
  reactionsOf(conversation: string | { conversation: string }, messageId: string): Map<string, number> | null {
    return this.tracker.counts(this.qualified(conversation), messageId);
  }

  /** Listens to reactions ({@link BotEvents.reaction}); returns the unsubscribe function. */
  onReaction(listener: (event: ReactionEvent) => void | Promise<void>): () => void {
    return this.on("reaction", listener);
  }

  /** Pins a message (`pin_messages`, scope `messages:write`; at most 50 per conversation). */
  async pin(conversation: string | { conversation: string }, messageId: string): Promise<Message> {
    const { id, link } = this.target(conversation);
    return link.api.conversations.pin(id, ulid("messageId", messageId));
  }

  async unpin(conversation: string | { conversation: string }, messageId: string): Promise<Message> {
    const { id, link } = this.target(conversation);
    return link.api.conversations.unpin(id, ulid("messageId", messageId));
  }

  /** The pinned messages, decrypted (unreadable ones left out). */
  async pins(conversation: string | { conversation: string }): Promise<BotMessage[]> {
    const { id, link } = this.target(conversation);
    const out: BotMessage[] = [];
    for (const m of (await link.api.conversations.pins(id)).messages) {
      const read = await this.readMessage(link, m);
      if (!("reason" in read)) out.push(read);
    }
    return out;
  }

  /** Shows "… is typing" for a few seconds (scope `messages:write`); false while the connection is down. */
  typing(conversation: string | { conversation: string }): boolean {
    const { id, link } = this.target(conversation);
    return link.typing(id);
  }

  /** Moves the bot's read marker (scope `messages:write`); only needed by bots that show unread state somewhere. */
  async markRead(conversation: string | { conversation: string }, messageId: string): Promise<void> {
    const { id, link } = this.target(conversation);
    await link.api.conversations.markRead(id, ulid("messageId", messageId));
  }

  // ---- Threads (PROTOCOL.md §7e) -----------------------------------------------------------------

  /** Whether the node keeps thread ids chosen by the client (`threads.client_ids`), cached per node. */
  private nodeKeepsThreadIds(link: NodeLink): Promise<boolean> {
    let known = this.clientIds.get(link.domain);
    if (!known) {
      known = link.api.node.info().then(
        (info) => Array.isArray(info.capabilities) && info.capabilities.includes("threads.client_ids"),
        () => false,
      );
      this.clientIds.set(link.domain, known);
    }
    return known;
  }

  /** The room channel behind a conversation (threads exist in room channels only). */
  private async channelOf(link: NodeLink, q: string): Promise<ChannelInfo> {
    let c = this.channels.get(q);
    if (!c) {
      for (const room of await link.api.rooms.list()) await this.loadRoom(link, room.id);
      c = this.channels.get(q);
    }
    if (!c) throw new BotError("not_member", "Threads exist in room channels the bot can view only");
    return c;
  }

  /**
   * Creates a thread: the request with the title (sealed in encrypted channels, bound to the thread id where the node
   * keeps client ids) and the optional first message; an existing thread of the same root comes back instead.
   */
  private async startThread(q: string, o: CreateThreadOptions): Promise<Thread> {
    const { id, link } = this.target(q);
    const c = await this.channelOf(link, q);
    const title = threadTitle(o.title);
    if (!o.title.trim() || Array.from(o.title.trim()).length > 100) throw new RangeError("title: 1 to 100 characters");
    if (c.kind === "forum" && o.content === undefined) throw new RangeError("forum posts need a first message (content)");
    if (o.tags && (o.tags.length > 5 || c.kind !== "forum")) throw new RangeError("tags: forum posts only, at most 5");
    const encrypted = await this.isEncrypted(link, q, id);
    if (encrypted) await this.prepareEncrypted(q);
    const mls = this.mls!;
    const mentions = mentionList(o.mentions);
    const content = o.content === undefined ? null : normalizeContent(o.content);
    if (content) checkContent(content);
    const request = async (threadId: string | undefined) => {
      const sealedTitle = encrypted ? await this.seal(q, () => mls.encryptThreadTitle(q, title, threadId)) : { title };
      let message: CreateMessageRequest | undefined;
      if (content && encrypted) {
        const sealed = await this.seal(q, () => mls.encrypt(q, content, threadId ? { ctx: { thread_id: threadId, reply_to: null } } : {}));
        message = { content: sealed.content, epoch: sealed.epoch, mentions };
      } else if (content) {
        const signature = threadId ? mls.signPlaintext(q, { reply_to: null, thread_id: threadId, mentions_everyone: false, mentions, attachments: [] }, content) : null;
        message = { content, mentions, ...(signature ? { signature } : {}) };
      }
      return link.api.threads.create(c.roomId, id, {
        ...(threadId ? { id: threadId } : {}),
        ...sealedTitle,
        ...(o.rootMessageId ? { root_message_id: ulid("rootMessageId", o.rootMessageId) } : {}),
        ...(o.tags?.length ? { tags: o.tags } : {}),
        ...(message ? { message } : {}),
      });
    };
    // A client id binds the encrypted title and the first message's signature to the thread; a node that refuses the
    // id (clock far off, id taken) gets the request without one.
    const picked = (encrypted || content) && (await this.nodeKeepsThreadIds(link)) ? newUlid() : undefined;
    try {
      try {
        return await this.freshEpoch(q, () => request(picked));
      } catch (e) {
        if (!picked || (code(e) !== "thread.id_invalid" && code(e) !== "thread.id_taken")) throw e;
        return await this.freshEpoch(q, () => request(undefined));
      }
    } catch (e) {
      // Another member started the thread of this root in between: theirs is the thread.
      const started = code(e) === "thread.exists" ? ((e as TavrnApiError).problem as { meta?: { thread_id?: unknown } }).meta?.thread_id : undefined;
      if (typeof started !== "string") throw e;
      const thread = await link.api.threads.get(started);
      if (content) await this.send(q, content, { threadId: thread.id, mentions });
      return thread;
    }
  }

  /** A thread as the bot reads it: the title decrypted and verified in encrypted channels. */
  private async toThread(domain: string, t: Thread): Promise<BotThread> {
    const q = qualify(domain, t.channel_id);
    let title: string | null = t.title;
    if (t.encrypted) {
      const mls = this.mls!;
      if (!mls.hasGroup(q)) await this.join(q, false);
      const d = mls.hasGroup(q) ? await mls.decryptThreadTitle(q, t).catch(() => null) : null;
      title = d?.ok ? d.title : null;
    }
    return {
      id: t.id,
      node: domain,
      conversation: q,
      roomId: t.room_id,
      channelId: t.channel_id,
      title,
      encrypted: t.encrypted,
      rootMessageId: t.root_message_id ?? null,
      createdBy: t.created_by,
      messageCount: t.message_count,
      lastMessageAt: t.last_message_at,
      archived: !!t.archived_at,
      locked: t.locked,
      tags: t.tags ?? [],
      raw: t,
    };
  }

  /**
   * Starts a thread in a room channel (scope `messages:write`, `create_threads` in text and announcement channels):
   * from a channel message (`rootMessageId`), standalone, or as a forum post (`content` required, optional `tags`).
   * `content` becomes the thread's first message. Write more with `send(thread.conversation, …, { threadId })`.
   */
  async createThread(conversation: string | { conversation: string }, opts: CreateThreadOptions): Promise<BotThread> {
    const q = this.qualified(conversation);
    return this.toThread(splitQualified(q).domain, await this.startThread(q, opts));
  }

  /** Threads of a channel (scope `messages:read`): active ones by default, newest activity first. */
  async threads(conversation: string | { conversation: string }, query: ThreadListQuery = {}): Promise<{ items: BotThread[]; next: string | null }> {
    const { q, id, link } = this.target(conversation);
    const c = await this.channelOf(link, q);
    const page = await link.api.threads.list(c.roomId, id, query);
    return { items: await Promise.all(page.items.map((t) => this.toThread(link.domain, t))), next: page.next ?? null };
  }

  /** One thread; `conversation` names the node (any conversation of it, typically the channel). */
  async thread(conversation: string | { conversation: string }, threadId: string): Promise<BotThread> {
    const { link } = this.target(conversation);
    return this.toThread(link.domain, await link.api.threads.get(ulid("threadId", threadId)));
  }

  /**
   * Renames, archives, unarchives, locks or retags a thread: the bot's own, others' with `manage_threads` (scope
   * `moderation`). A new title is encrypted in encrypted channels and bound to the thread.
   */
  async updateThread(conversation: string | { conversation: string }, threadId: string, change: { title?: string; archived?: boolean; locked?: boolean; tags?: string[] }): Promise<BotThread> {
    const { link } = this.target(conversation);
    ulid("threadId", threadId);
    let title = {};
    if (change.title !== undefined) {
      const t = change.title.trim();
      if (!t || Array.from(t).length > 100) throw new RangeError("title: 1 to 100 characters");
      const current = await link.api.threads.get(threadId);
      const cq = qualify(link.domain, current.channel_id);
      if (await this.isEncrypted(link, cq, current.channel_id)) {
        await this.prepareEncrypted(cq);
        const mls = this.mls!;
        title = await this.seal(cq, () => mls.encryptThreadTitle(cq, t, threadId));
      } else title = { title: t };
    }
    const req = { ...title, ...(change.archived !== undefined ? { archived: change.archived } : {}), ...(change.locked !== undefined ? { locked: change.locked } : {}), ...(change.tags ? { tags: change.tags } : {}) };
    if (!Object.keys(req).length) throw new RangeError("updateThread: title, archived, locked or tags");
    return this.toThread(link.domain, await link.api.threads.update(threadId, req));
  }

  /** Archives a thread (it reopens with the next message unless locked). */
  archiveThread(conversation: string | { conversation: string }, threadId: string, archived = true): Promise<BotThread> {
    return this.updateThread(conversation, threadId, { archived });
  }

  /** Deletes a thread with all its messages (own threads with only own messages; else `manage_threads`). */
  async deleteThread(conversation: string | { conversation: string }, threadId: string): Promise<void> {
    const { link } = this.target(conversation);
    await link.api.threads.delete(ulid("threadId", threadId));
  }

  /** Follows or unfollows a thread (the bot follows threads it started or wrote in). */
  async followThread(conversation: string | { conversation: string }, threadId: string, follow = true): Promise<void> {
    const { link } = this.target(conversation);
    await (follow ? link.api.threads.follow(ulid("threadId", threadId)) : link.api.threads.unfollow(ulid("threadId", threadId)));
  }

  // ---- Rooms, members, moderation ------------------------------------------------------------------

  /** The node and bare id of a room reference. */
  private roomTarget(room: RoomRef): { link: NodeLink; roomId: string } {
    this.running();
    let node: string;
    let roomId: string | null;
    if (typeof room === "string") {
      const slash = room.indexOf("/");
      node = slash > 0 ? room.slice(0, slash) : this.claims!.iss;
      roomId = slash > 0 ? room.slice(slash + 1) : room;
    } else ({ node, roomId } = room);
    if (!roomId) throw new BotError("not_member", "This conversation belongs to no room (a DM)");
    return { link: this.linkFor(node), roomId: ulid("roomId", roomId) };
  }

  /** The rooms the bot is in on a node (default: the home node). */
  async rooms(node?: string): Promise<Room[]> {
    this.running();
    return this.linkFor(node ?? this.claims!.iss).api.rooms.list();
  }

  /** A room with the channels, categories and roles the bot can see (always allowed). */
  async room(room: RoomRef): Promise<RoomDetail> {
    const { link, roomId } = this.roomTarget(room);
    return link.api.rooms.get(roomId);
  }

  /** A page of the room's members (scope `members:read`), ordered by id; `after` = the last user id of the page. */
  async members(room: RoomRef, query: { limit?: number; after?: string } = {}): Promise<Member[]> {
    const { link, roomId } = this.roomTarget(room);
    return link.api.members.list(roomId, query);
  }

  /** A user's public profile (always allowed), from the bot's home node. */
  async profile(address: string): Promise<Profile> {
    this.running();
    return this.home!.api.users.profile(address.trim().toLowerCase());
  }

  /**
   * Times a member out (scope `moderation`, `moderate_members`): `minutes` 1–40320 (28 days), 0 lifts the timeout.
   * `userId` is the member's id on the room's node (`m.authorId`, `interaction.userId`).
   */
  async timeout(room: RoomRef, userId: string, minutes: number, opts: { reason?: string } = {}): Promise<Member> {
    const { link, roomId } = this.roomTarget(room);
    const r = checkReason(opts.reason);
    return link.api.members.timeout(roomId, ulid("userId", userId), { minutes: timeoutMinutes(minutes), ...(r ? { reason: r } : {}) });
  }

  /** Removes a member from the room (scope `moderation`, `kick_members`). */
  async kick(room: RoomRef, userId: string, opts: { reason?: string } = {}): Promise<void> {
    const { link, roomId } = this.roomTarget(room);
    await link.api.members.kick(roomId, ulid("userId", userId), checkReason(opts.reason));
  }

  /** Bans an address or a whole domain from the room (scope `moderation`, `ban_members`); members are removed. */
  async ban(room: RoomRef, subject: string, opts: { reason?: string } = {}): Promise<Ban> {
    const { link, roomId } = this.roomTarget(room);
    const r = checkReason(opts.reason);
    return link.api.members.ban(roomId, { subject: banSubject(subject), ...(r ? { reason: r } : {}) });
  }

  async unban(room: RoomRef, subject: string): Promise<void> {
    const { link, roomId } = this.roomTarget(room);
    await link.api.members.unban(roomId, banSubject(subject));
  }

  /** The room's bans (scope `moderation`). */
  async bans(room: RoomRef): Promise<Ban[]> {
    const { link, roomId } = this.roomTarget(room);
    return link.api.members.bans(roomId);
  }

  /** The room's audit log, newest first (scope `moderation`, `view_audit_log`). */
  async auditLog(room: RoomRef, query: { limit?: number; before?: string } = {}): Promise<AuditEntry[]> {
    const { link, roomId } = this.roomTarget(room);
    return link.api.rooms.auditLog(roomId, query);
  }

  /**
   * Searches a room's plaintext channels (scope `messages:read`, SEARCH.md): the node indexes no encrypted content, so
   * encrypted channels are not searched (`searched` in the answer tells what was).
   */
  async search(room: RoomRef, query: SearchQuery): Promise<SearchResponse> {
    const { link, roomId } = this.roomTarget(room);
    if (query.limit !== undefined && !(Number.isInteger(query.limit) && query.limit >= 1 && query.limit <= 50)) throw new RangeError("limit: 1 to 50");
    return link.api.search.room(roomId, query);
  }

  /**
   * Sets the status line of a voice channel (VOICE.md §2a; `voice_status`, which the scope `rooms:manage` unlocks):
   * plain text up to 128 characters, "" clears it.
   */
  async setVoiceStatus(room: RoomRef, channelId: string, status: string): Promise<Channel> {
    const { link, roomId } = this.roomTarget(room);
    return link.api.channels.update(roomId, ulid("channelId", channelId), { status: voiceStatus(status) });
  }

  // ---- Presence (APPLICATIONS.md §7) ------------------------------------------------------------------

  /** Runs a presence change on every node the bot is connected to (presence is kept per node, PROTOCOL.md §6a). */
  private async everyNode<T>(what: string, fn: (link: NodeLink) => Promise<T>): Promise<T> {
    this.running();
    const home = this.home!;
    const result = await fn(home);
    await Promise.all(
      [...this.links.values()]
        .filter((l) => l !== home)
        .map((l) => fn(l).catch((e: unknown) => this.logger.warn(`${what} failed on a room node`, { node: l.domain, error: e }))),
    );
    return result;
  }

  /**
   * Sets the bot's status and custom status (scope `presence`) on every connected node, e.g.
   * `{ status: "dnd", customStatus: { text: "Deploying", emoji: "🚀" } }`; `customStatus: null` clears it.
   */
  async setPresence(presence: PresenceInput): Promise<MyPresence> {
    const req = presenceRequest(presence);
    return this.everyNode("presence", (l) => l.api.presence.set(req));
  }

  /** Sets the bot's activity (scope `presence`): `{ type: "watching", name: "3 servers" }`. */
  async setActivity(activity: ActivityInput): Promise<MyPresence> {
    const req = activityRequest(activity);
    return this.everyNode("activity", (l) => l.api.presence.setActivity(req));
  }

  clearActivity(): Promise<MyPresence> {
    return this.everyNode("activity", (l) => l.api.presence.clearActivity());
  }

  // ---- DMs (PROTOCOL.md §8a) -------------------------------------------------------------------------

  /**
   * Opens (or returns) the 1:1 DM with a user of any node (scope `dms`; writing needs `messages:write`). The DM lives
   * on the bot's home node and is encrypted: the bot creates its group and adds the user's devices. People who are
   * not the owner get a message request under their own `dm_policy`. Returns the qualified conversation id.
   */
  async openDm(address: string): Promise<string> {
    this.running();
    const user = address.trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+$/.test(user)) throw new RangeError("address: user@node");
    const home = this.home!;
    const c = await home.api.conversations.create({ kind: "dm", members: [user] });
    const q = qualify(home.domain, c.id);
    this.direct.set(q, { encrypted: !!c.encrypted, members: (c.members ?? []).map((u) => u.address) });
    if (c.encrypted) await this.prepareEncrypted(q);
    return q;
  }

  /** Sends a DM ({@link openDm} plus {@link send}). */
  async dm(address: string, content: ReplyContent, opts: SendOptions = {}): Promise<Message> {
    return this.send(await this.openDm(address), content, opts);
  }

  /** Accepts a message request (`dmRequest`, scope `dms`). */
  async acceptDm(conversation: string | { conversation: string }): Promise<void> {
    const { id, link } = this.target(conversation);
    await link.api.requests.accept(id);
  }

  /** Declines a message request; `block` also blocks its sender for the bot. */
  async declineDm(conversation: string | { conversation: string }, opts: { block?: boolean; reason?: string } = {}): Promise<void> {
    const { id, link } = this.target(conversation);
    await link.api.requests.decline(id, { ...(opts.block ? { block: true } : {}), ...(opts.reason ? { reason: checkReason(opts.reason) } : {}) });
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
