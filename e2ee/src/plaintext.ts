// SPDX-License-Identifier: MPL-2.0
/**
 * Device signatures on plaintext messages (FEDERATION.md §10.3): the envelope fields the signature
 * covers, the nonce inside the `signature` value and how a verification result is shown. Signing and
 * verifying themselves run in the MLS session manager (device key, attested devices).
 */
import { b64urlDecode, b64urlEncode, type Attachment } from "@tavrn/sdk";

/** One attachment as covered by the signature. */
export interface SignedAttachment {
  id: string;
  size: number;
  sha256: string;
}

/** The envelope fields covered by the signature, in the JSON form `@tavrn/crypto` expects. */
export interface SignedFields {
  /** Qualified conversation id `<node domain>/<ulid>`. */
  conversation: string;
  author: string;
  device_id: string;
  reply_to: string | null;
  thread_id: string | null;
  mentions_everyone: boolean;
  mentions: string[];
  attachments: SignedAttachment[];
}

/** The parts of an envelope needed to check its signature. */
export interface PlainEnvelope {
  id: string;
  author: string;
  device_id?: string | null;
  reply_to_id?: string | null;
  thread_id?: string | null;
  mentions?: string[];
  mentions_everyone?: boolean;
  attachments?: Pick<Attachment, "id" | "size" | "sha256">[];
  content: unknown;
  signature?: string | null;
}

/** Signed attachment entries in envelope order (the node lists attachments sorted by id). */
export function signedAttachments(list: Pick<Attachment, "id" | "size" | "sha256">[]): SignedAttachment[] {
  return [...list].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map((a) => ({ id: a.id, size: a.size, sha256: a.sha256 }));
}

/** The covered fields of a received envelope; null for messages without a device (system messages). */
export function envelopeFields(conversation: string, m: PlainEnvelope): SignedFields | null {
  if (!m.device_id) return null;
  return {
    conversation,
    author: m.author,
    device_id: m.device_id,
    reply_to: m.reply_to_id ?? null,
    thread_id: m.thread_id ?? null,
    mentions_everyone: !!m.mentions_everyone,
    mentions: m.mentions ?? [],
    // Envelope order as received: the signer used the same order (sorted by id).
    attachments: (m.attachments ?? []).map((a) => ({ id: a.id, size: a.size, sha256: a.sha256 })),
  };
}

/** The nonce (base64url) inside a `signature` value, or null if it is not 80 bytes of base64url. */
export function signatureNonce(signature: string): string | null {
  if (signature.length !== 107 || !/^[A-Za-z0-9_-]+$/.test(signature)) return null;
  try {
    const bytes = b64urlDecode(signature);
    return bytes.length === 80 ? b64urlEncode(bytes.slice(0, 16)) : null;
  } catch {
    return null;
  }
}

/**
 * Result of checking a plaintext message:
 * - `valid`: signed by an attested device of the author;
 * - `unsigned`: no signature (older clients, bots, API accounts without a device key);
 * - `unverifiable`: signed, but the device key is unknown here (e.g. users of other nodes) or the
 *   input could not be checked;
 * - `invalid`: the signature does not match: the node or someone else changed the message;
 * - `replay`: the nonce was already used by another message of the conversation.
 */
export type PlainStatus = "valid" | "unsigned" | "unverifiable" | "invalid" | "replay";

/**
 * How a message with this status is shown: normally (`null`), with a small "unverified" marker, or
 * with its content hidden behind "could not be verified" (FEDERATION.md §10.3). Unknown status
 * (not checked yet, or this device cannot check: locked) shows nothing.
 */
export function plainMarker(status: PlainStatus | undefined): null | "unverified" | "hidden" {
  switch (status) {
    case "unsigned":
    case "unverifiable":
      return "unverified";
    case "invalid":
    case "replay":
      return "hidden";
    default:
      return null;
  }
}
