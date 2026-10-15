// SPDX-License-Identifier: MPL-2.0
/**
 * Component values and modal input in encrypted conversations (protocol/APPLICATIONS.md §5.10.2, §5.10.4). The
 * invoker's client encrypts a `component.values` (a button click or a select choice) or `modal.values` (a submitted
 * form) content object for the conversation's MLS group, exactly like command arguments (`./commands.ts`); the node
 * only sees which component of which message was used. The application decrypts it like a message (the content
 * signature is checked against the invoker's attested device by the session manager) and then runs
 * {@link ComponentValuesVerifier}: the payload must name the interaction's message and component (or modal), be fresh
 * and carry a nonce it has not seen, so a node can neither replay values nor move them to another component.
 */
import { b64urlEncode } from "@tavrn/sdk";
import { ARGS_MAX_AGE_MS, ARGS_MAX_SKEW_MS, ARGS_NONCE_KEEP_MS, type ContentEncryptor } from "./commands";
import { NonceWindow } from "./lru";

export const COMPONENT_VALUES_TYPE = "component.values";
export const MODAL_VALUES_TYPE = "modal.values";

/** The content object of an encrypted component interaction. */
export interface ComponentValuesContent {
  type: typeof COMPONENT_VALUES_TYPE;
  /** The message that carries the component. */
  message_id: string;
  custom_id: string;
  /** null for buttons, the selected option values for selects. */
  values: string[] | null;
  /** base64url of 16 random bytes. */
  nonce: string;
  issued_at: string;
}

/** The content object of an encrypted modal submit. */
export interface ModalValuesContent {
  type: typeof MODAL_VALUES_TYPE;
  /** The interaction that answered with the modal. */
  interaction: string;
  /** The modal's `custom_id`. */
  custom_id: string;
  /** Input `custom_id` → text. */
  values: Record<string, string>;
  nonce: string;
  issued_at: string;
}

function nonce(): string {
  const n = new Uint8Array(16);
  crypto.getRandomValues(n);
  return b64urlEncode(n);
}

/** Builds the `component.values` content with a fresh nonce. */
export function componentValuesContent(messageId: string, customId: string, values: string[] | null, now: Date = new Date()): ComponentValuesContent {
  return { type: COMPONENT_VALUES_TYPE, message_id: messageId, custom_id: customId, values, nonce: nonce(), issued_at: now.toISOString() };
}

/** Builds the `modal.values` content with a fresh nonce. */
export function modalValuesContent(interactionId: string, customId: string, values: Record<string, string>, now: Date = new Date()): ModalValuesContent {
  return { type: MODAL_VALUES_TYPE, interaction: interactionId, custom_id: customId, values, nonce: nonce(), issued_at: now.toISOString() };
}

/** Encrypts a component interaction: the `values_ciphertext` and `epoch` of `POST …/messages/{id}/interactions`. */
export async function encryptComponentValues(
  mls: ContentEncryptor,
  conversationId: string,
  messageId: string,
  customId: string,
  values: string[] | null,
  now?: Date,
): Promise<{ values_ciphertext: string; epoch: number }> {
  const sealed = await mls.encrypt(conversationId, { ...componentValuesContent(messageId, customId, values, now) });
  return { values_ciphertext: sealed.content, epoch: sealed.epoch };
}

/** Encrypts a modal submit: the `values_ciphertext` and `epoch` of `POST /interactions/{id}/submit`. */
export async function encryptModalValues(
  mls: ContentEncryptor,
  conversationId: string,
  interactionId: string,
  customId: string,
  values: Record<string, string>,
  now?: Date,
): Promise<{ values_ciphertext: string; epoch: number }> {
  const sealed = await mls.encrypt(conversationId, { ...modalValuesContent(interactionId, customId, values, now) });
  return { values_ciphertext: sealed.content, epoch: sealed.epoch };
}

export type ValuesRejection = "invalid" | "message" | "interaction" | "custom_id" | "stale" | "future" | "replay";

export type ComponentValuesCheck = { ok: true; values: string[] | null } | { ok: false; reason: ValuesRejection };
export type ModalValuesCheck = { ok: true; values: Record<string, string> } | { ok: false; reason: ValuesRejection };

const NONCE = /^[A-Za-z0-9_-]{22}$/;
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/**
 * The application's checks of decrypted component values and modal input (§5.10.2, §5.10.4, like §5.8): type and
 * shape, the interaction's message and component (or modal interaction and modal), age at most five minutes (and not
 * from the future), a nonce not seen in the last 15 minutes. Whether the values fit the component is the
 * application's own check (it knows the message it sent; `validateComponentValues` of `@tavrn/sdk`).
 */
export class ComponentValuesVerifier {
  private readonly seen: NonceWindow;
  private readonly now: () => number;
  private readonly maxAgeMs: number;
  private readonly maxSkewMs: number;

  constructor(opts: { now?: () => number; maxAgeMs?: number; keepMs?: number; maxSkewMs?: number } = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.maxAgeMs = opts.maxAgeMs ?? ARGS_MAX_AGE_MS;
    this.seen = new NonceWindow(opts.keepMs ?? ARGS_NONCE_KEEP_MS);
    this.maxSkewMs = opts.maxSkewMs ?? ARGS_MAX_SKEW_MS;
  }

  /** `component.values` of the interaction on `expected.messageId` / `expected.customId`. */
  checkComponent(content: unknown, expected: { messageId: string; customId: string }): ComponentValuesCheck {
    const c = this.shape(content, COMPONENT_VALUES_TYPE);
    if (!c) return { ok: false, reason: "invalid" };
    const values = c.values;
    if (values !== null && !(Array.isArray(values) && values.every((v) => typeof v === "string"))) return { ok: false, reason: "invalid" };
    if (c.message_id !== expected.messageId) return { ok: false, reason: "message" };
    if (c.custom_id !== expected.customId) return { ok: false, reason: "custom_id" };
    const fresh = this.fresh(c);
    return fresh ? { ok: false, reason: fresh } : { ok: true, values: values as string[] | null };
  }

  /** `modal.values` of the submit of the modal `expected.customId` that interaction `expected.interactionId` opened. */
  checkModal(content: unknown, expected: { interactionId: string; customId: string }): ModalValuesCheck {
    const c = this.shape(content, MODAL_VALUES_TYPE);
    if (!c) return { ok: false, reason: "invalid" };
    const values = c.values;
    if (!isObj(values) || !Object.values(values).every((v) => typeof v === "string")) return { ok: false, reason: "invalid" };
    if (c.interaction !== expected.interactionId) return { ok: false, reason: "interaction" };
    if (c.custom_id !== expected.customId) return { ok: false, reason: "custom_id" };
    const fresh = this.fresh(c);
    return fresh ? { ok: false, reason: fresh } : { ok: true, values: values as Record<string, string> };
  }

  private shape(content: unknown, type: string): Record<string, unknown> | null {
    if (!isObj(content)) return null;
    if (content.type !== type || typeof content.nonce !== "string" || !NONCE.test(content.nonce) || typeof content.issued_at !== "string") return null;
    if (!Number.isFinite(Date.parse(content.issued_at))) return null;
    return content;
  }

  /** Age, skew and replay; the nonce is remembered only when everything else passed. */
  private fresh(c: Record<string, unknown>): "stale" | "future" | "replay" | null {
    const now = this.now();
    const issued = Date.parse(c.issued_at as string);
    if (now - issued > this.maxAgeMs) return "stale";
    if (issued - now > this.maxSkewMs) return "future";
    const key = c.nonce as string;
    if (this.seen.has(key, now)) return "replay";
    this.seen.remember(key, now);
    return null;
  }
}
