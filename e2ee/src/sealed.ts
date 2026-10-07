// SPDX-License-Identifier: MPL-2.0
/**
 * Write-only webhooks in encrypted channels (APPLICATIONS.md §6.1a, ENCRYPTION.md §5b): the stored form of a
 * sealed webhook message and the checks of the payload inside the box. The box itself is opened by
 * `Client.openSealed` with the inbox key derived from the epoch's content key ({@link MlsManager.decrypt}).
 */
import { withValidEmbeds } from "./embeds";

/** Who sealed the message: the posting service itself, or the node (which then saw the text once). */
export type SealedBy = "sender" | "node";

/** The `content` of a sealed webhook message: `{ type: "webhook.sealed", epoch, sealed, sealed_by }`. */
export interface SealedContent {
  epoch: number;
  /** `crypto_box_seal` output, base64url. */
  sealed: string;
  sealedBy: SealedBy;
}

/** Longest text body (PROTOCOL.md §7, the node's limit for plaintext messages). */
const MAX_BODY = 4000;
const B64URL = /^[A-Za-z0-9_-]+$/;

/** The sealed form of a message `content`, or null for anything else (ordinary ciphertext, plaintext). */
export function sealedContent(content: unknown): SealedContent | null {
  if (!content || typeof content !== "object" || Array.isArray(content)) return null;
  const c = content as Record<string, unknown>;
  if (c.type !== "webhook.sealed") return null;
  if (typeof c.epoch !== "number" || !Number.isSafeInteger(c.epoch) || c.epoch < 0) return null;
  if (typeof c.sealed !== "string" || !B64URL.test(c.sealed)) return null;
  return { epoch: c.epoch, sealed: c.sealed, sealedBy: c.sealed_by === "node" ? "node" : "sender" };
}

/** The node's rules for a webhook `username` (APPLICATIONS.md §6.1): 1–32 characters, no `@ # :`, no controls. */
export function validWebhookName(name: unknown): name is string {
  if (typeof name !== "string") return false;
  const n = name.trim();
  const len = Array.from(n).length;
  if (len === 0 || len > 32 || /[@#:]/.test(n) || /[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/.test(n)) return false;
  return !["everyone", "here"].includes(n.toLowerCase());
}

/**
 * The payload inside a sealed box, checked like a webhook's plaintext payload: `{ content: { type: "text", body,
 * embeds? }, username? }`. Only these fields survive (no attachments, GIFs or previews: webhooks have none);
 * invalid embeds are dropped, an invalid username is ignored. Null when the payload is not a text payload.
 */
export function webhookPayload(json: string): { content: Record<string, unknown>; username?: string } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const p = parsed as Record<string, unknown>;
  const c = p.content as Record<string, unknown> | null | undefined;
  if (!c || typeof c !== "object" || Array.isArray(c) || c.type !== "text" || typeof c.body !== "string") return null;
  if (Array.from(c.body).length > MAX_BODY) return null;
  const content = withValidEmbeds(Array.isArray(c.embeds) ? { type: "text", body: c.body, embeds: c.embeds } : { type: "text", body: c.body });
  const hasEmbeds = Array.isArray(content.embeds) && content.embeds.length > 0;
  if (!c.body.trim() && !hasEmbeds) return null;
  return validWebhookName(p.username) ? { content, username: p.username.trim() } : { content };
}
