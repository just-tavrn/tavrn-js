// SPDX-License-Identifier: Apache-2.0
/**
 * Reactions for bots (PROTOCOL.md §6, §7, §7b). Reactions are plaintext metadata next to a message, also in encrypted
 * conversations. The node announces a change as `message.update` with the message's new `reactions` list
 * (`[{ emoji, count, me }]`, `me` always false in events) and the change itself, `reaction: { emoji, user, user_id,
 * added }`, which works for messages the bot has never seen. For older nodes that send only the counts, the runtime
 * remembers the counts of the messages it has seen ({@link MessageTracker}) and computes the change from them (the
 * reacting user is then unknown).
 */

/** A custom emoji name: 2–32 of `a-z 0-9 _`. */
const EMOJI_NAME = /^[a-z0-9_]{2,32}$/;
/** `<:name:ID>` or `<:name:ID@host>` (PROTOCOL.md §7b). */
const EMOJI_TOKEN = /^<:([a-z0-9_]{2,32}):([0-9A-HJKMNP-TV-Z]{26})(?:@([a-z0-9.-]{1,253}(?::\d{1,5})?))?>$/;

/**
 * Whether the node accepts `emoji` as a reaction: a Unicode emoji (1–16 characters, no whitespace, control
 * characters or angle brackets), `:name:` (a custom emoji of the room) or a custom emoji token `<:name:ID[@host]>`.
 */
export function validReaction(emoji: string): boolean {
  if (typeof emoji !== "string") return false;
  if (emoji.startsWith("<")) return EMOJI_TOKEN.test(emoji);
  if (emoji.length > 2 && emoji.startsWith(":") && emoji.endsWith(":") && EMOJI_NAME.test(emoji.slice(1, -1))) return true;
  const chars = Array.from(emoji);
  // eslint-disable-next-line no-control-regex
  return chars.length >= 1 && chars.length <= 16 && !/[\s<>\u0000-\u001f\u007f-\u009f]/u.test(emoji);
}

/** One change of a reaction count. */
export interface ReactionChange {
  emoji: string;
  /** The count after the change. */
  count: number;
  /** `true`: somebody added it; `false`: somebody took it back. */
  added: boolean;
  /** The reacting user's address (null only from older nodes that do not name it). */
  user: string | null;
  /** The reacting user's id on the node hosting the conversation (null like `user`). */
  userId: string | null;
}

interface Tracked {
  reactions: Map<string, number>;
  editedAt: string | null;
}

/** What a `message.update` changed against the remembered state of the message. */
export interface MessageChanges {
  reactions: ReactionChange[];
  /** `edited_at` moved: the content was edited. */
  edited: boolean;
}

interface UpdatedMessage {
  id: string;
  reactions?: { emoji: string; count: number }[] | null;
  edited_at?: string | null;
  /** The reaction change that caused this update (PROTOCOL.md §6), absent for edits, pins and older nodes. */
  reaction?: unknown;
}

function countsOf(list: UpdatedMessage["reactions"]): Map<string, number> {
  const out = new Map<string, number>();
  for (const r of Array.isArray(list) ? list : []) {
    if (r && typeof r.emoji === "string" && Number.isSafeInteger(r.count) && r.count > 0) out.set(r.emoji, r.count);
  }
  return out;
}

/** The reaction the node names in the event (PROTOCOL.md §6), or null. */
function namedReaction(m: UpdatedMessage, counts: Map<string, number>): ReactionChange | null {
  const r = m.reaction;
  if (!r || typeof r !== "object" || Array.isArray(r)) return null;
  const { emoji, user, user_id: userId, added } = r as Record<string, unknown>;
  if (typeof emoji !== "string" || typeof user !== "string" || typeof added !== "boolean") return null;
  return { emoji, user: user.toLowerCase(), userId: typeof userId === "string" ? userId : null, added, count: counts.get(emoji) ?? 0 };
}

/**
 * The reaction counts and edit times of recently seen messages (at most `max`, the oldest are forgotten), keyed by the
 * qualified conversation id and the message id.
 */
export class MessageTracker {
  private readonly seen = new Map<string, Tracked>();

  constructor(private readonly max = 5000) {}

  private key(q: string, id: string): string {
    return `${q}\u0000${id}`;
  }

  private put(key: string, t: Tracked) {
    this.seen.delete(key);
    this.seen.set(key, t);
    while (this.seen.size > this.max) {
      const oldest = this.seen.keys().next().value;
      if (oldest === undefined) break;
      this.seen.delete(oldest);
    }
  }

  /** Remembers a message as it is now (created, sent, read from the history). */
  remember(q: string, m: UpdatedMessage): void {
    if (typeof m?.id !== "string") return;
    this.put(this.key(q, m.id), { reactions: countsOf(m.reactions), editedAt: m.edited_at ?? null });
  }

  /**
   * The changes a `message.update` brings and the new state remembered. Without an earlier state only a reaction the
   * node names is reported (counts alone cannot tell what changed).
   */
  update(q: string, m: UpdatedMessage): MessageChanges {
    const key = this.key(q, m.id);
    const before = this.seen.get(key);
    const counts = countsOf(m.reactions);
    this.put(key, { reactions: counts, editedAt: m.edited_at ?? null });
    const named = namedReaction(m, counts);
    if (!before) return { reactions: named ? [named] : [], edited: false };
    const edited = (m.edited_at ?? null) !== before.editedAt && m.edited_at != null;
    if (named) return { reactions: [named], edited };
    const reactions: ReactionChange[] = [];
    for (const [emoji, count] of counts) {
      const old = before.reactions.get(emoji) ?? 0;
      if (count !== old) reactions.push({ emoji, count, added: count > old, user: null, userId: null });
    }
    for (const [emoji] of before.reactions) if (!counts.has(emoji)) reactions.push({ emoji, count: 0, added: false, user: null, userId: null });
    return { reactions, edited };
  }

  /** The remembered reaction counts of a message (null when it is not remembered). */
  counts(q: string, id: string): Map<string, number> | null {
    const t = this.seen.get(this.key(q, id));
    return t ? new Map(t.reactions) : null;
  }

  forget(q: string, id: string): void {
    this.seen.delete(this.key(q, id));
  }
}
