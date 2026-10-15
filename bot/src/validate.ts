// SPDX-License-Identifier: Apache-2.0
/**
 * Input checks of the bot helpers with the protocol's limits, so a mistake fails before anything is sent (and before
 * anything is encrypted). The node checks the same limits again; these are for clear, early errors (`RangeError` /
 * `TypeError`), never a security boundary.
 */
import { assertEmbeds } from "@tavrn/e2ee";
import type { Activity, PresenceRequest } from "@tavrn/sdk";

/** `body` of text content (PROTOCOL.md §7). */
export const MAX_TEXT_CHARS = 4000;
/** Presence (PROTOCOL.md §6a): chosen status, custom status text, activity texts. */
export const PRESENCE_STATUSES = ["online", "idle", "dnd", "invisible"] as const;
export const ACTIVITY_TYPES = ["playing", "listening", "watching", "streaming", "competing"] as const;
export const MAX_PRESENCE_TEXT = 128;
export const MAX_STATUS_EMOJI = 32;
/** Custom status expiry and activity end at most this far ahead. */
export const MAX_CUSTOM_STATUS_MS = 30 * 24 * 3600 * 1000;
export const MAX_ACTIVITY_MS = 7 * 24 * 3600 * 1000;
/** Timeouts (MODERATION.md): 0 clears, at most 28 days. */
export const MAX_TIMEOUT_MINUTES = 40_320;
/** Reasons of kicks, bans and timeouts (audit log). */
export const MAX_REASON_CHARS = 500;
/** Voice channel status (VOICE.md §2a). */
export const MAX_VOICE_STATUS = 128;

export type PresenceStatus = (typeof PRESENCE_STATUSES)[number];
export type ActivityType = (typeof ACTIVITY_TYPES)[number];

function chars(s: string): number {
  return Array.from(s).length;
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

function text(name: string, value: unknown, max: number, opts: { empty?: boolean } = {}): string {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string`);
  const v = value.trim();
  if (!opts.empty && !v) throw new RangeError(`${name} must not be empty`);
  if (chars(v) > max) throw new RangeError(`${name}: at most ${max} characters`);
  if (CONTROL.test(v)) throw new RangeError(`${name} must not contain control characters`);
  return v;
}

function time(name: string, value: string | Date): { iso: string; ms: number } {
  const ms = value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(ms)) throw new RangeError(`${name} must be a date (RFC 3339)`);
  return { iso: new Date(ms).toISOString(), ms };
}

/**
 * A content object the node accepts as a message: text and `action` content with a body of at most 4000 characters
 * (empty only with embeds or attachments) and valid embeds (APPLICATIONS.md §6.4; `EmbedsInvalidError`, code
 * `message.embeds_invalid`). Reserved types are refused; other types pass unchanged (polls are checked by `createPoll`,
 * the node checks the rest).
 */
export function checkContent(content: Record<string, unknown>): void {
  const type = content.type;
  if (typeof type !== "string" || !type) throw new TypeError("content.type must be a string");
  if (type.startsWith("system.") || type === "command.args" || type === "poll.vote") throw new RangeError(`content type ${type} is reserved`);
  if (type !== "text" && type !== "action") return;
  if (typeof content.body !== "string") throw new TypeError("content.body must be a string");
  if (chars(content.body) > MAX_TEXT_CHARS) throw new RangeError(`content.body: at most ${MAX_TEXT_CHARS} characters`);
  assertEmbeds(content);
  if (!content.body.trim() && !(Array.isArray(content.embeds) && content.embeds.length) && !(Array.isArray(content.attachments) && content.attachments.length)) {
    throw new RangeError("content.body must not be empty (except with embeds or attachments)");
  }
}

/** Options of {@link presenceRequest}. */
export interface PresenceInput {
  /** The chosen status; `idle` applies to the bot's device on that node only. */
  status?: PresenceStatus;
  /** Custom status: text and/or emoji, optional expiry (at most 30 days). `null` clears it. */
  customStatus?: { text?: string; emoji?: string | null; expiresAt?: string | Date | null } | null;
}

/** `PUT /users/me/presence` body (PROTOCOL.md §6a). */
export function presenceRequest(p: PresenceInput, now = Date.now()): PresenceRequest {
  const out: PresenceRequest = {};
  if (p.status !== undefined) {
    if (!(PRESENCE_STATUSES as readonly string[]).includes(p.status)) throw new RangeError(`status: one of ${PRESENCE_STATUSES.join(", ")}`);
    out.status = p.status;
  }
  if (p.customStatus === null) out.custom_status = null;
  else if (p.customStatus !== undefined) {
    const t = text("customStatus.text", p.customStatus.text ?? "", MAX_PRESENCE_TEXT, { empty: true });
    const emoji = p.customStatus.emoji ? text("customStatus.emoji", p.customStatus.emoji, MAX_STATUS_EMOJI) : null;
    if (!t && !emoji) throw new RangeError("customStatus needs a text or an emoji");
    let expires: string | null = null;
    if (p.customStatus.expiresAt) {
      const at = time("customStatus.expiresAt", p.customStatus.expiresAt);
      if (at.ms <= now || at.ms - now > MAX_CUSTOM_STATUS_MS) throw new RangeError("customStatus.expiresAt: in the future, at most 30 days ahead");
      expires = at.iso;
    }
    out.custom_status = { text: t, emoji, expires_at: expires };
  }
  if (out.status === undefined && out.custom_status === undefined) throw new RangeError("presence: status or customStatus");
  return out;
}

/** An activity of the bot (APPLICATIONS.md §7.1–§7.2): `{ type: "watching", name: "3 servers" }`. */
export interface ActivityInput {
  type: ActivityType;
  name: string;
  details?: string | null;
  state?: string | null;
  startedAt?: string | Date | null;
  /** A countdown: after `startedAt`, at most 7 days ahead. */
  endsAt?: string | Date | null;
}

/** `PUT /users/me/activity` body; `application` is set only by the local bridge (§7.3), never by a bot. */
export function activityRequest(a: ActivityInput, now = Date.now()): Activity {
  if (!(ACTIVITY_TYPES as readonly string[]).includes(a.type)) throw new RangeError(`activity.type: one of ${ACTIVITY_TYPES.join(", ")}`);
  const out: Activity = { type: a.type, name: text("activity.name", a.name, MAX_PRESENCE_TEXT) };
  if (a.details) out.details = text("activity.details", a.details, MAX_PRESENCE_TEXT);
  if (a.state) out.state = text("activity.state", a.state, MAX_PRESENCE_TEXT);
  let started = now;
  if (a.startedAt) {
    const s = time("activity.startedAt", a.startedAt);
    if (s.ms > now + 60_000) throw new RangeError("activity.startedAt must not be in the future");
    started = s.ms;
    out.started_at = s.iso;
  }
  if (a.endsAt) {
    const e = time("activity.endsAt", a.endsAt);
    if (e.ms <= started || e.ms - now > MAX_ACTIVITY_MS) throw new RangeError("activity.endsAt: after startedAt, at most 7 days ahead");
    out.ends_at = e.iso;
  }
  return out;
}

/** Timeout minutes: an integer 0 (clear) to 40320 (28 days). */
export function timeoutMinutes(minutes: number): number {
  if (!Number.isInteger(minutes) || minutes < 0 || minutes > MAX_TIMEOUT_MINUTES) throw new RangeError(`minutes: an integer from 0 (clear) to ${MAX_TIMEOUT_MINUTES}`);
  return minutes;
}

/** A moderation reason (empty = none): at most 500 characters. */
export function reason(r: string | undefined): string | undefined {
  if (r === undefined) return undefined;
  const v = text("reason", r, MAX_REASON_CHARS, { empty: true });
  return v || undefined;
}

/** A ban subject: an address (`user@node`) or a domain (bans everybody of that node). */
export function banSubject(subject: string): string {
  const s = typeof subject === "string" ? subject.trim().toLowerCase() : "";
  if (!/^([a-z0-9._-]+@)?[a-z0-9.-]+(:\d{1,5})?$/.test(s) || s.length > 300) throw new RangeError("subject: an address (user@node) or a domain");
  return s;
}

/** A voice channel status (VOICE.md §2a): plain text, at most 128 characters, "" clears it. */
export function voiceStatus(status: string): string {
  return text("status", status, MAX_VOICE_STATUS, { empty: true });
}

/** The states of a report (MODERATION.md §1.4). */
export const REPORT_STATUSES = ["open", "resolved", "dismissed"] as const;
export type ReportStatus = (typeof REPORT_STATUSES)[number];

/** The inbox query of `Bot.reports` (MODERATION.md §1.4): a status, `limit` 1–100, `before` a report id. */
export function reportQuery(q: { status?: string; limit?: number; before?: string }): { status?: ReportStatus; limit?: number; before?: string } {
  const out: { status?: ReportStatus; limit?: number; before?: string } = {};
  if (q.status !== undefined) {
    if (!REPORT_STATUSES.includes(q.status as ReportStatus)) throw new RangeError(`status: one of ${REPORT_STATUSES.join(", ")}`);
    out.status = q.status as ReportStatus;
  }
  if (q.limit !== undefined) {
    if (!Number.isInteger(q.limit) || q.limit < 1 || q.limit > 100) throw new RangeError("limit: an integer from 1 to 100");
    out.limit = q.limit;
  }
  if (q.before !== undefined) out.before = ulid("before", q.before);
  return out;
}

/** A ULID in canonical form (ids of messages, users, rooms, threads). */
export function ulid(name: string, id: string): string {
  if (typeof id !== "string" || !/^[0-9A-HJKMNP-TV-Z]{26}$/.test(id)) throw new RangeError(`${name} must be an id (ULID)`);
  return id;
}
