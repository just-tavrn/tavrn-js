// SPDX-License-Identifier: Apache-2.0
/**
 * Application commands for bots (APPLICATIONS.md §5): `bot.command(name, handler)` registers a handler; a
 * `command.invoke` event of any node the bot is connected to runs it with an {@link Interaction} that answers
 * with `reply` / `ephemeral` / `defer` / `followUp` / `error` (§5.7). In encrypted conversations the arguments
 * arrive as ciphertext: they are decrypted with the bot's MLS state, signature-checked against the invoker's device
 * and checked for command, age and replay (§5.8); replies and follow-ups are encrypted for the conversation.
 *
 * This module only needs a way to call the node (`request`) and the conversation's encryption ({@link CommandCrypto});
 * it does not know sockets, so it is tested with recorded event frames.
 */
import { CommandArgsVerifier, qualify, type ArgsCheck, type Decrypted, type EncryptOptions, type EncryptedEnvelope } from "@tavrn/e2ee";
import { validateModal, type Modal } from "@tavrn/sdk";
import { BotError } from "./errors";
import type { BotLogger } from "./logger";
import { threadTitle } from "./threads";
import { checkContent, mentionList, normalizeContent as normalize } from "./validate";

/** `data` of the `command.invoke` event (§5.6). */
export interface CommandInvokeData {
  interaction_id: string;
  application_id: string;
  command: { id: string; name: string };
  conversation_id: string;
  room_id: string | null;
  channel_id: string | null;
  /** The thread the command was invoked in (PROTOCOL.md §7e); absent from older nodes. */
  thread_id?: string | null;
  encrypted: boolean;
  user: string;
  user_id: string;
  device_id: string | null;
  permissions: string;
  args: Record<string, unknown> | null;
  args_ciphertext: string | null;
  epoch: number | null;
  locale: string | null;
  expires_at: string;
}

/** A content object (`{ type: "text", body }`, embeds, …) or plain text. */
export type ReplyContent = string | Record<string, unknown>;

export interface ReplyOptions {
  /** Shown to the invoker only, never stored (§5.7). */
  ephemeral?: boolean;
  /** Addresses mentioned in the reply. */
  mentions?: string[];
  /**
   * Answer in this thread of the conversation (PROTOCOL.md §7e). By default the node answers in the thread the
   * command was invoked in, or in the one {@link Interaction.replyInThread} started.
   */
  threadId?: string;
}

/** The encryption of the conversations the bot is a member of (the bot's MLS session manager). */
export interface CommandCrypto {
  hasGroup(q: string): boolean;
  decrypt(q: string, envelope: EncryptedEnvelope): Promise<Decrypted>;
  /** `opts.ctx`: the signed context of an answer (thread, interaction; ENCRYPTION.md §5.2). */
  encrypt(q: string, content: Record<string, unknown>, opts?: EncryptOptions): Promise<{ content: string; epoch: number }>;
  /** Joins the conversation's group in the background (the bot was not a member yet). */
  join(q: string): void;
}

/** What one invocation needs from the node it came from. */
export interface InvokeContext {
  /** Domain of the node that delivered the invocation (it hosts the conversation). */
  node: string;
  /** A request to that node with the bot's session there (`TavrnApi.request`). */
  request<T>(method: string, path: string, body?: unknown): Promise<T>;
  /** `<home domain>/<application id>`: invoked command references are `<appRef>/<command id>`. */
  appRef: string;
  /** The bot device (its token's `dev`), named in encrypted answers. */
  deviceId: string;
  crypto: CommandCrypto | null;
}

/** A handler of one command; what it returns is ignored (so `(i) => i.reply(…)` is fine). */
export type CommandHandler = (interaction: Interaction) => unknown;

/** What a callback or follow-up returned (the node's answer, passed through). */
export type InteractionResult = Record<string, unknown> | undefined;

const ERROR_MAX = 200;


/** One invocation of a command (§5.5–§5.8). The first answer counts; `reply` after `defer` sends a follow-up. */
export class Interaction {
  readonly id: string;
  /** The command's name and id. */
  readonly command: { id: string; name: string };
  /** The invoker's address and node-local id. */
  readonly user: string;
  readonly userId: string;
  /** Domain of the node hosting the conversation. */
  readonly node: string;
  readonly conversationId: string;
  /** Qualified conversation id `<node>/<conversation id>`. */
  readonly conversation: string;
  readonly roomId: string | null;
  readonly channelId: string | null;
  /** The thread the command was invoked in (PROTOCOL.md §7e), null outside threads. Answers go there. */
  readonly threadId: string | null;
  readonly encrypted: boolean;
  /** The arguments (decrypted and checked in encrypted conversations). */
  readonly args: Record<string, unknown>;
  /** The invoker's first `Accept-Language` (e.g. `de`), or null. */
  readonly locale: string | null;
  /** The invoker's effective permissions in the channel (decimal). */
  readonly permissions: string;
  readonly expiresAt: string;
  private state: "pending" | "deferred" | "replied" | "failed" = "pending";
  private deferredEphemeral = false;
  /** The thread {@link replyInThread} started: later answers go there too. */
  private startedThread: string | null = null;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(
    data: CommandInvokeData,
    args: Record<string, unknown>,
    private readonly ctx: InvokeContext,
  ) {
    this.id = data.interaction_id;
    this.command = { id: data.command.id, name: data.command.name };
    this.user = data.user;
    this.userId = data.user_id;
    this.node = ctx.node;
    this.conversationId = data.conversation_id;
    this.conversation = qualify(ctx.node, data.conversation_id);
    this.roomId = data.room_id ?? null;
    this.channelId = data.channel_id ?? null;
    this.threadId = data.thread_id ?? null;
    this.encrypted = !!data.encrypted;
    this.args = args;
    this.locale = data.locale ?? null;
    this.permissions = data.permissions;
    this.expiresAt = data.expires_at;
  }

  /** Whether the interaction got its first answer (reply, defer or error). */
  get answered(): boolean {
    return this.state !== "pending";
  }

  /** Answers with a message (stored, `message.create`) or, with `ephemeral`, a reply only the invoker sees. */
  reply(content: ReplyContent, opts: ReplyOptions = {}): Promise<InteractionResult> {
    return this.serial(() => this.replyNow(content, opts));
  }

  /**
   * Answers in a thread: the one the command was invoked in, else a new thread of the channel (`title` defaults to
   * the start of the text, encrypted in encrypted channels); later follow-ups go there too. Room channels only.
   */
  replyInThread(content: ReplyContent, opts: ReplyOptions & { title?: string } = {}): Promise<InteractionResult> {
    return this.serial(async () => {
      const { title, ...rest } = opts;
      if (this.threadId || this.startedThread || rest.threadId) return this.replyNow(content, rest);
      if (!this.roomId || !this.channelId) throw new BotError("not_member", "Threads exist in room channels only");
      const object = normalize(content);
      const text = threadTitle(title ?? (typeof object.body === "string" ? object.body : ""));
      let sealedTitle: Record<string, unknown> = { title: text };
      if (this.encrypted) {
        if (!this.ctx.crypto) throw new BotError("not_member", "This bot has no encryption state for this conversation");
        const sealed = await this.ctx.crypto.encrypt(this.conversation, { type: "thread.title", body: text });
        sealedTitle = { title: sealed.content, title_epoch: sealed.epoch };
      }
      const path = `/rooms/${encodeURIComponent(this.roomId)}/channels/${encodeURIComponent(this.channelId)}/threads`;
      const thread = await this.ctx.request<{ id: string }>("POST", path, sealedTitle);
      this.startedThread = thread.id;
      return this.replyNow(object, rest);
    });
  }

  private async replyNow(content: ReplyContent, opts: ReplyOptions): Promise<InteractionResult> {
    if (this.state === "deferred") return this.followUpNow(content, { ephemeral: opts.ephemeral ?? this.deferredEphemeral, mentions: opts.mentions, threadId: opts.threadId });
    this.requirePending();
    const body = { type: "reply", ...(await this.seal(content, opts)), ephemeral: !!opts.ephemeral, mentions: mentionList(opts.mentions), ...this.thread(opts) };
    this.state = "replied";
    return this.callback(body);
  }

  /** `thread_id` of an answer: the one asked for, else the thread {@link replyInThread} started (else the node's default). */
  private thread(opts: ReplyOptions): { thread_id?: string } {
    const id = opts.threadId ?? this.startedThread;
    return id ? { thread_id: id } : {};
  }

  /**
   * Edits the message that carries the component (APPLICATIONS.md §5.10.3) as the first answer: component
   * interactions and modal submits that came from a component only. In encrypted conversations the new content is
   * encrypted with the message's signed context (its thread; `replyTo` when the message was a reply).
   */
  update(content: ReplyContent, opts: { mentions?: string[]; replyTo?: string | null } = {}): Promise<InteractionResult> {
    return this.serial(async () => {
      this.requirePending();
      const object = normalize(content);
      let sealed: { content: unknown; epoch?: number; device_id?: string } = { content: object };
      if (this.encrypted) {
        if (!this.ctx.crypto) throw new BotError("not_member", "This bot has no encryption state for this conversation");
        const c = await this.ctx.crypto.encrypt(this.conversation, object, { ctx: { thread_id: this.threadId, reply_to: opts.replyTo ?? null } });
        sealed = { content: c.content, epoch: c.epoch, device_id: this.ctx.deviceId };
      }
      this.state = "replied";
      return this.callback({ type: "update", ...sealed, mentions: mentionList(opts.mentions) });
    });
  }

  /**
   * Opens a modal (a form) on the invoker's device as the first answer (§5.10.3); its submit arrives as a
   * `modal.submit` interaction (`bot.modal(customId, handler)`). Not as the answer to a modal submit.
   */
  modal(modal: Modal): Promise<InteractionResult> {
    return this.serial(async () => {
      this.requirePending();
      const issue = validateModal(modal);
      if (issue) throw new TypeError(`invalid modal at ${issue.path || "the modal"}: ${issue.message}`);
      this.state = "replied";
      return this.callback({ type: "modal", modal });
    });
  }

  /** Shorthand for `reply(content, { ephemeral: true })`. */
  ephemeral(content: ReplyContent): Promise<InteractionResult> {
    return this.reply(content, { ephemeral: true });
  }

  /** "Thinking…": the answer follows with {@link followUp} (or `reply`) until the interaction expires (15 min). */
  defer(opts: { ephemeral?: boolean } = {}): Promise<InteractionResult> {
    return this.serial(async () => {
      this.requirePending();
      this.state = "deferred";
      this.deferredEphemeral = !!opts.ephemeral;
      return this.callback({ type: "defer", ephemeral: !!opts.ephemeral });
    });
  }

  /** A further message after the first answer (at most 10 per interaction, §5.7). */
  followUp(content: ReplyContent, opts: ReplyOptions = {}): Promise<InteractionResult> {
    return this.serial(async () => {
      if (this.state === "pending") throw new BotError("interaction_answered", "Answer the interaction (reply or defer) before sending follow-ups");
      return this.followUpNow(content, opts);
    });
  }

  /**
   * A short error notice shown to the invoker only (at most 200 characters). The node sees it even in encrypted
   * conversations: keep it generic there (§5.7).
   */
  error(message: string): Promise<InteractionResult> {
    return this.serial(async () => {
      this.requirePending();
      this.state = "failed";
      return this.callback({ type: "error", message: Array.from(message).slice(0, ERROR_MAX).join("") });
    });
  }

  private requirePending() {
    if (this.state !== "pending") throw new BotError("interaction_answered", `Interaction ${this.id} was already answered`);
  }

  /** Answers one at a time, in call order (a reply racing the automatic defer becomes a follow-up). */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.chain.then(fn, fn);
    this.chain = next.catch(() => undefined);
    return next;
  }

  private async followUpNow(content: ReplyContent, opts: ReplyOptions): Promise<InteractionResult> {
    const body = { ...(await this.seal(content, opts)), ephemeral: !!opts.ephemeral, mentions: mentionList(opts.mentions), ...this.thread(opts) };
    return this.ctx.request<InteractionResult>("POST", `/interactions/${encodeURIComponent(this.id)}/messages`, body);
  }

  private callback(body: Record<string, unknown>): Promise<InteractionResult> {
    return this.ctx.request<InteractionResult>("POST", `/interactions/${encodeURIComponent(this.id)}/callback`, body);
  }

  /**
   * The content as the conversation's mode wants it: a content object, or ciphertext of the bot device (§5.7) whose
   * signed context names the interaction and the thread the answer goes to (the node's default: the invocation's).
   */
  private async seal(content: ReplyContent, opts: ReplyOptions): Promise<{ content: unknown; epoch?: number; device_id?: string }> {
    const object = normalize(content);
    // Body length and embeds (APPLICATIONS.md §6.4) before anything is encrypted or sent.
    checkContent(object);
    if (!this.encrypted) return { content: object };
    if (!this.ctx.crypto) throw new BotError("not_member", "This bot has no encryption state for this conversation");
    const threadId = opts.threadId ?? this.startedThread ?? this.threadId;
    const sealed = await this.ctx.crypto.encrypt(this.conversation, object, { ctx: { thread_id: threadId, reply_to: null, interaction: this.id } });
    return { content: sealed.content, epoch: sealed.epoch, device_id: this.ctx.deviceId };
  }

  /** Internal: marks the automatic answer. */
  async autoDefer(): Promise<void> {
    if (this.state === "pending") await this.defer().catch(() => undefined);
  }
}

/** Generic notices (the node sees them in encrypted conversations, §5.7). */
/** What a command and a component interaction offer the shared handler run. */
interface Answerable {
  readonly answered: boolean;
  autoDefer(): Promise<unknown>;
  error(message: string): Promise<unknown>;
}

/**
 * Runs the handler of a command, component or modal interaction: defers automatically when it has not answered after
 * `autoDeferMs`, answers a generic notice when it throws or returns without answering, and logs both. Never throws.
 */
export async function runInteraction(
  interaction: Answerable,
  run: () => unknown,
  opts: { logger: BotLogger; autoDeferMs: number; what: string; fields: Record<string, unknown>; messages: { noAnswer: string; failed: string } },
): Promise<void> {
  const log = opts.logger;
  const timer = setTimeout(() => void interaction.autoDefer(), opts.autoDeferMs);
  try {
    await run();
    if (!interaction.answered) {
      log.warn(`${opts.what} handler returned without answering`, opts.fields);
      await interaction.error(opts.messages.noAnswer).catch(() => undefined);
    }
  } catch (e) {
    log.error(`${opts.what} handler failed`, { ...opts.fields, error: e });
    if (!interaction.answered) await interaction.error(opts.messages.failed).catch(() => undefined);
  } finally {
    clearTimeout(timer);
  }
}

/** Answers an interaction that gets no handler with a generic error notice; a failure of that is logged. */
export function answerError(ctx: InvokeContext, interactionId: string, message: string, log: BotLogger): Promise<unknown> {
  return ctx.request("POST", `/interactions/${encodeURIComponent(interactionId)}/callback`, { type: "error", message }).catch((e: unknown) => log.warn("could not answer the interaction", { interaction: interactionId, error: e }));
}

const MSG = {
  unknown: "This command is not available right now.",
  failed: "The command failed.",
  noAnswer: "The command did not answer.",
  joining: "The bot is joining this channel's encryption. Try again in a moment.",
  args: "The command's arguments could not be verified.",
};

export interface CommandRouterOptions {
  logger: BotLogger;
  /** Defer automatically when a handler has not answered after this long (default 2 s; the node waits 3 s). */
  autoDeferMs?: number;
  /** Clock (tests). */
  now?: () => number;
}

function isInvoke(data: unknown): data is CommandInvokeData {
  if (!data || typeof data !== "object") return false;
  const d = data as Record<string, unknown>;
  const cmd = d.command as Record<string, unknown> | null | undefined;
  return typeof d.interaction_id === "string" && typeof d.conversation_id === "string" && typeof d.user === "string" && !!cmd && typeof cmd.id === "string" && typeof cmd.name === "string";
}

/** The registered command handlers and the invocation flow. */
export class CommandRouter {
  private readonly handlers = new Map<string, CommandHandler>();
  private readonly verifier: CommandArgsVerifier;
  private readonly autoDeferMs: number;

  constructor(private readonly opts: CommandRouterOptions) {
    this.verifier = new CommandArgsVerifier({ now: opts.now });
    this.autoDeferMs = opts.autoDeferMs ?? 2000;
  }

  register(name: string, handler: CommandHandler): void {
    if (!/^[a-z0-9_-]{1,32}$/.test(name)) throw new TypeError(`invalid command name "${name}" (APPLICATIONS.md §5.1: [a-z0-9_-], 1–32 characters)`);
    this.handlers.set(name, handler);
  }

  names(): string[] {
    return [...this.handlers.keys()];
  }

  /**
   * Handles one `command.invoke` event. Never throws: failures are answered with a generic error notice when the
   * interaction is still open, and logged.
   */
  async handle(data: unknown, ctx: InvokeContext): Promise<Interaction | null> {
    const log = this.opts.logger;
    if (!isInvoke(data)) {
      log.warn("malformed command.invoke ignored", { node: ctx.node });
      return null;
    }
    const answer = (message: string) => answerError(ctx, data.interaction_id, message, log);
    const handler = this.handlers.get(data.command.name);
    if (!handler) {
      log.warn("command without a handler", { command: data.command.name, interaction: data.interaction_id });
      await answer(MSG.unknown);
      return null;
    }
    const args = await this.arguments(data, ctx);
    if (!args.ok) {
      await answer(args.reason === "joining" ? MSG.joining : MSG.args);
      return null;
    }
    const interaction = new Interaction(data, args.args, ctx);
    await runInteraction(interaction, () => handler(interaction), { logger: log, autoDeferMs: this.autoDeferMs, what: "command", fields: { command: data.command.name, interaction: data.interaction_id }, messages: MSG });
    return interaction;
  }

  /** The invocation's arguments: as sent in unencrypted conversations, decrypted and checked in encrypted ones. */
  private async arguments(data: CommandInvokeData, ctx: InvokeContext): Promise<{ ok: true; args: Record<string, unknown> } | { ok: false; reason: "joining" | "invalid" }> {
    const log = this.opts.logger;
    if (!data.encrypted) {
      const args = data.args && typeof data.args === "object" && !Array.isArray(data.args) ? data.args : {};
      return { ok: true, args };
    }
    const q = qualify(ctx.node, data.conversation_id);
    if (!ctx.crypto) return { ok: false, reason: "invalid" };
    // §5.8: a bot that is not yet a member answers with an error and joins.
    if (!ctx.crypto.hasGroup(q)) {
      ctx.crypto.join(q);
      return { ok: false, reason: "joining" };
    }
    if (typeof data.args_ciphertext !== "string" || !data.device_id) {
      log.warn("encrypted invocation without argument ciphertext", { interaction: data.interaction_id });
      return { ok: false, reason: "invalid" };
    }
    const decrypted = await ctx.crypto.decrypt(q, { id: `interaction:${data.interaction_id}`, author: data.user, device_id: data.device_id, epoch: data.epoch, content: data.args_ciphertext });
    if (!decrypted.ok) {
      log.warn("command arguments could not be decrypted", { interaction: data.interaction_id, reason: decrypted.reason });
      return { ok: false, reason: "invalid" };
    }
    const check: ArgsCheck = this.verifier.check(decrypted.content, `${ctx.appRef}/${data.command.id}`);
    if (!check.ok) {
      log.warn("command arguments refused", { interaction: data.interaction_id, reason: check.reason });
      return { ok: false, reason: "invalid" };
    }
    return { ok: true, args: check.args };
  }
}
