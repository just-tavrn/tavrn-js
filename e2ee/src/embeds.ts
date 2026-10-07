// SPDX-License-Identifier: MPL-2.0
/**
 * Embeds in `text` content (protocol/APPLICATIONS.md §6.4): the client half of the shared content codec. The node
 * checks plaintext content with the same rules (`server/src/embeds.rs`); encrypted content is invisible to it, so
 * senders check before encrypting ({@link assertEmbeds}) and receivers drop invalid embeds after decrypting
 * ({@link withValidEmbeds}). {@link readEmbeds} gives a renderer the checked embeds of any content object.
 *
 * Embeds carry text, one `https://` link and a colour, never images: clients never load anything from foreign
 * hosts for them.
 */

export const MAX_EMBEDS = 10;
export const MAX_EMBED_CHARS = 6000;
export const MAX_EMBED_TITLE = 256;
export const MAX_EMBED_DESCRIPTION = 4096;
export const MAX_EMBED_URL = 2048;
export const MAX_EMBED_FIELDS = 25;
export const MAX_EMBED_FIELD_NAME = 256;
export const MAX_EMBED_FIELD_VALUE = 1024;
export const MAX_EMBED_FOOTER = 2048;
export const MAX_EMBED_COLOR = 0xffffff;

export interface EmbedField {
  name: string;
  value: string;
  inline?: boolean;
}

/** A checked embed. */
export interface MessageEmbed {
  title?: string;
  /** Markdown subset, rendered through the same sanitizer as message bodies. */
  description?: string;
  /** `https://` only. */
  url?: string;
  /** 0–16777215 (`0xRRGGBB`). */
  color?: number;
  fields?: EmbedField[];
  footer?: string;
  /** RFC 3339. */
  timestamp?: string;
}

/** Thrown by {@link assertEmbeds} (the node answers `400 message.embeds_invalid` for plaintext). */
export class EmbedsInvalidError extends Error {
  readonly code = "message.embeds_invalid";
  constructor(detail: string) {
    super(detail);
    this.name = "EmbedsInvalidError";
  }
}

/** Characters as the node counts them (Unicode scalar values). */
const chars = (s: string) => Array.from(s).length;

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/i;

/** `https://` with a host, without credentials or whitespace, at most 2048 characters. */
export function validEmbedUrl(url: unknown): url is string {
  if (typeof url !== "string" || url.length > MAX_EMBED_URL || !url.startsWith("https://") || /\s/.test(url)) return false;
  try {
    const u = new URL(url);
    return u.protocol === "https:" && !!u.hostname && !u.username && !u.password;
  } catch {
    return false;
  }
}

/** Why `embeds` is invalid, or `null` when it follows §6.4. */
export function embedsProblem(embeds: unknown): string | null {
  if (!Array.isArray(embeds)) return "embeds must be an array";
  if (embeds.length > MAX_EMBEDS) return `at most ${MAX_EMBEDS} embeds`;
  let total = 0;
  for (const raw of embeds) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return "every embed is an object";
    const e = raw as Record<string, unknown>;
    const text = (key: string, max: number): number | string => {
      const v = e[key];
      if (v === undefined || v === null) return 0;
      if (typeof v !== "string") return `${key} must be a string`;
      const n = chars(v);
      return n > max ? `${key} has at most ${max} characters` : n;
    };
    const title = text("title", MAX_EMBED_TITLE);
    const description = text("description", MAX_EMBED_DESCRIPTION);
    const footer = text("footer", MAX_EMBED_FOOTER);
    for (const t of [title, description, footer]) if (typeof t === "string") return t;
    total += (title as number) + (description as number) + (footer as number);
    if (e.url !== undefined && e.url !== null && !validEmbedUrl(e.url)) return "url must be an https:// URL without credentials";
    if (e.color !== undefined && e.color !== null && !(Number.isInteger(e.color) && (e.color as number) >= 0 && (e.color as number) <= MAX_EMBED_COLOR)) return "color is an integer from 0 to 16777215";
    if (e.timestamp !== undefined && e.timestamp !== null && !(typeof e.timestamp === "string" && e.timestamp.length <= 64 && RFC3339.test(e.timestamp) && !Number.isNaN(Date.parse(e.timestamp)))) return "timestamp must be an RFC 3339 time";
    let hasFields = false;
    if (e.fields !== undefined && e.fields !== null) {
      if (!Array.isArray(e.fields)) return "fields must be an array";
      if (e.fields.length > MAX_EMBED_FIELDS) return `at most ${MAX_EMBED_FIELDS} fields`;
      for (const f of e.fields) {
        if (!f || typeof f !== "object" || Array.isArray(f)) return "every field is an object";
        const field = f as Record<string, unknown>;
        if (typeof field.name !== "string" || typeof field.value !== "string") return "fields need a name and a value";
        const [n, v] = [chars(field.name), chars(field.value)];
        if (n === 0 || v === 0) return "fields need a name and a value";
        if (n > MAX_EMBED_FIELD_NAME || v > MAX_EMBED_FIELD_VALUE) return "field too long";
        if (field.inline !== undefined && field.inline !== null && typeof field.inline !== "boolean") return "inline must be a boolean";
        total += n + v;
      }
      hasFields = e.fields.length > 0;
    }
    if ((title as number) + (description as number) + (footer as number) === 0 && !hasFields) return "an embed needs a title, a description, fields or a footer";
  }
  return total > MAX_EMBED_CHARS ? `at most ${MAX_EMBED_CHARS} characters in total` : null;
}

/**
 * Sender side: throws {@link EmbedsInvalidError} when a `text` content object carries invalid embeds (or another
 * type carries any). Content without `embeds` passes.
 */
export function assertEmbeds(content: Record<string, unknown>): void {
  if (content.embeds === undefined || content.embeds === null) return;
  if (content.type !== "text") throw new EmbedsInvalidError("only text content carries embeds");
  const problem = embedsProblem(content.embeds);
  if (problem) throw new EmbedsInvalidError(problem);
}

/** Receiver side: the content without its `embeds` when they are invalid (they are then never shown). */
export function withValidEmbeds<T extends Record<string, unknown>>(content: T): T {
  if (content.embeds === undefined) return content;
  if (content.type === "text" && embedsProblem(content.embeds) === null) return content;
  const { embeds: _dropped, ...rest } = content;
  return rest as T;
}

/** The checked embeds of a content object for rendering (none when invalid); only known fields are kept. */
export function readEmbeds(content: unknown): MessageEmbed[] {
  if (!content || typeof content !== "object") return [];
  const c = content as Record<string, unknown>;
  if (c.type !== "text" || !Array.isArray(c.embeds) || c.embeds.length === 0 || embedsProblem(c.embeds) !== null) return [];
  return (c.embeds as Record<string, unknown>[]).map((e) => {
    const out: MessageEmbed = {};
    if (typeof e.title === "string" && e.title) out.title = e.title;
    if (typeof e.description === "string" && e.description) out.description = e.description;
    if (typeof e.url === "string") out.url = e.url;
    if (typeof e.color === "number") out.color = e.color;
    if (Array.isArray(e.fields)) out.fields = (e.fields as Record<string, unknown>[]).map((f) => ({ name: f.name as string, value: f.value as string, ...(f.inline === true ? { inline: true } : {}) }));
    if (typeof e.footer === "string" && e.footer) out.footer = e.footer;
    if (typeof e.timestamp === "string") out.timestamp = e.timestamp;
    return out;
  });
}
