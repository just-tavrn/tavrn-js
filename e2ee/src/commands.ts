// SPDX-License-Identifier: MPL-2.0
/**
 * Command arguments in encrypted conversations (protocol/APPLICATIONS.md §5.8). The invoker's client encrypts
 * a `command.args` content object for the conversation's MLS group (the bot is a member); the node sees only
 * which command was invoked. The application decrypts it like a message (the content signature is checked
 * against the invoker's attested device by the session manager) and then runs {@link CommandArgsVerifier}:
 * the payload must name the invoked command, be fresh and carry a nonce it has not seen, so a node can neither
 * replay arguments nor move them to another command.
 */
import { b64urlEncode } from "@tavrn/sdk";

export const COMMAND_ARGS_TYPE = "command.args";
/** Arguments older than this are refused. */
export const ARGS_MAX_AGE_MS = 5 * 60 * 1000;
/** Nonces are remembered this long (the lifetime of an interaction). */
export const ARGS_NONCE_KEEP_MS = 15 * 60 * 1000;
/** Clock skew tolerated for arguments from the future. */
export const ARGS_MAX_SKEW_MS = 60 * 1000;

/** The content object of encrypted command arguments. */
export interface CommandArgsContent {
  type: typeof COMMAND_ARGS_TYPE;
  /** The invoked command's reference `<application ref>/<command id>`. */
  command: string;
  /** base64url of 16 random bytes. */
  nonce: string;
  issued_at: string;
  args: Record<string, unknown>;
}

/** Builds the `command.args` content for `commandRef` with a fresh nonce. */
export function commandArgsContent(commandRef: string, args: Record<string, unknown>, now: Date = new Date()): CommandArgsContent {
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);
  return { type: COMMAND_ARGS_TYPE, command: commandRef, nonce: b64urlEncode(nonce), issued_at: now.toISOString(), args };
}

/** What encrypts a content object for a conversation (the session manager's `encrypt`). */
export interface ContentEncryptor {
  encrypt(conversationId: string, content: Record<string, unknown>): Promise<{ content: string; epoch: number }>;
}

/** Encrypts the arguments of an invocation: the `args_ciphertext` and `epoch` of `POST …/interactions`. */
export async function encryptCommandArgs(
  mls: ContentEncryptor,
  conversationId: string,
  commandRef: string,
  args: Record<string, unknown>,
  now?: Date,
): Promise<{ args_ciphertext: string; epoch: number }> {
  const sealed = await mls.encrypt(conversationId, { ...commandArgsContent(commandRef, args, now) });
  return { args_ciphertext: sealed.content, epoch: sealed.epoch };
}

export type ArgsRejection = "invalid" | "command" | "stale" | "future" | "replay";

export type ArgsCheck = { ok: true; args: Record<string, unknown> } | { ok: false; reason: ArgsRejection };

const NONCE = /^[A-Za-z0-9_-]{22}$/;

/**
 * The application's checks of decrypted arguments (§5.8): type and shape, the invoked command, age at most five
 * minutes (and not from the future), a nonce not seen in the last 15 minutes.
 */
export class CommandArgsVerifier {
  private readonly seen = new Map<string, number>();
  private readonly now: () => number;
  private readonly maxAgeMs: number;
  private readonly keepMs: number;
  private readonly maxSkewMs: number;

  constructor(opts: { now?: () => number; maxAgeMs?: number; keepMs?: number; maxSkewMs?: number } = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.maxAgeMs = opts.maxAgeMs ?? ARGS_MAX_AGE_MS;
    this.keepMs = opts.keepMs ?? ARGS_NONCE_KEEP_MS;
    this.maxSkewMs = opts.maxSkewMs ?? ARGS_MAX_SKEW_MS;
  }

  check(content: unknown, invokedRef: string): ArgsCheck {
    const now = this.now();
    for (const [nonce, at] of this.seen) {
      if (now - at > this.keepMs) this.seen.delete(nonce);
    }
    if (!content || typeof content !== "object" || Array.isArray(content)) return { ok: false, reason: "invalid" };
    const c = content as Record<string, unknown>;
    if (c.type !== COMMAND_ARGS_TYPE || typeof c.nonce !== "string" || !NONCE.test(c.nonce) || typeof c.issued_at !== "string") return { ok: false, reason: "invalid" };
    const args = c.args;
    if (!args || typeof args !== "object" || Array.isArray(args)) return { ok: false, reason: "invalid" };
    if (c.command !== invokedRef) return { ok: false, reason: "command" };
    const issued = Date.parse(c.issued_at);
    if (!Number.isFinite(issued)) return { ok: false, reason: "invalid" };
    if (now - issued > this.maxAgeMs) return { ok: false, reason: "stale" };
    if (issued - now > this.maxSkewMs) return { ok: false, reason: "future" };
    if (this.seen.has(c.nonce)) return { ok: false, reason: "replay" };
    this.seen.set(c.nonce, now);
    return { ok: true, args: args as Record<string, unknown> };
  }
}
