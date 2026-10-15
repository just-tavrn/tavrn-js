// SPDX-License-Identifier: Apache-2.0
/** Errors of the bot runtime with stable codes (log them, branch on `code`, never on the message). */
import { MlsError } from "@tavrn/e2ee";

export type BotErrorCode =
  /** The token is not an app token of a bot (`typ` ≠ `app`, malformed, or the account is no bot). */
  | "token_invalid"
  /** The token's `exp` has passed: the owner resets it, or the bot rotated too late (APPLICATIONS.md §2.2). */
  | "token_expired"
  /** The node refused the token while running (revoked, reset, application disabled): WebSocket close `4001`. */
  | "token_refused"
  /** A newer connection of the same token replaced this one (close code `4004`, do not reconnect). */
  | "replaced"
  /** The account has an identity key but the process has no key (APPLICATIONS.md §3.1). */
  | "key_missing"
  /** The configured key does not belong to the published identity key of the bot. */
  | "key_mismatch"
  /** The key (`key` option or the key file) cannot be parsed. */
  | "key_invalid"
  /** The state directory holds the data of another account (one bot account and device per directory). */
  | "state_dir_in_use"
  /** The state directory cannot be written any more (several writes in a row failed): the bot stopped. */
  | "state_unwritable"
  /** The node of `node` cannot be used (unreachable, not a tavrn node, domain differs from the token issuer). */
  | "node_invalid"
  /** The conversation is not known to the bot or the bot is not a member of its encryption group. */
  | "not_member"
  /** An interaction was answered twice, or answered after it expired. */
  | "interaction_answered"
  /** The bot was stopped (or not started yet). */
  | "stopped"
  /** The message is not a poll the bot can read (PROTOCOL.md §7g): missing, undecryptable or no valid poll. */
  | "not_a_poll"
  /** The message or attachment does not exist where the bot looked (or the bot cannot see it). */
  | "not_found"
  /** Only the author may do this (editing a message). */
  | "not_author"
  /**
   * Not sent: the conversation's encryption group has a device the bot's `ghostPolicy` does not accept (a key never
   * attested, a changed identity key without a continuity chain, a non-member; ENCRYPTION.md §4.6).
   */
  | "ghost"
  /**
   * The conversation's encryption could not be brought up to date before sending (the handshake log could not be
   * processed, a concurrent change won, the state is busy): nothing was sent; try again. `cause` has the details.
   */
  | "encryption_unavailable"
  /**
   * Not sent: the node reports the conversation as unencrypted, but it is end-to-end encrypted for the bot (a DM or
   * group DM, which is always encrypted; a conversation whose encryption group the bot holds or that it saw encrypted
   * in this session). The bot never writes plaintext there, whatever the node says.
   */
  | "encryption_downgrade";

export class BotError extends Error {
  constructor(
    readonly code: BotErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "BotError";
  }
}

/**
 * Errors of the session manager at the runtime's boundary: `BotError` (`not_member`, `encryption_unavailable`) with
 * the `MlsError` as `cause`; anything else passes unchanged (refusals of the node stay `TavrnApiError`).
 */
export function botErrorOf(e: unknown, conversation: string): unknown {
  if (!(e instanceof MlsError)) return e;
  switch (e.code) {
    case "not_joined":
    case "no_group":
      return new BotError("not_member", `The bot is not a member of the encryption group of ${conversation}`, { cause: e });
    case "invalid_id":
      return new RangeError(`conversation: ${conversation} is no qualified id <node>/<id>`, { cause: e });
    default:
      return new BotError("encryption_unavailable", `The encryption of ${conversation} could not be brought up to date (${e.code}); nothing was sent, try again`, { cause: e });
  }
}
