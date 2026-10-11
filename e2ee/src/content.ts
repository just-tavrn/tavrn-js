// SPDX-License-Identifier: MPL-2.0
/**
 * Encrypted attachments (ENCRYPTION.md §6) and validation of decrypted content objects. The node only
 * sees the ciphertext of a file; name, type, size and the file key travel inside the encrypted message.
 */
import { decryptFile, encryptFile } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode, type Attachment } from "@tavrn/sdk";
import { ensureCrypto } from "./wasm";

/** One entry of `content.attachments` in an encrypted message. */
export interface ContentAttachment {
  id: string;
  name: string;
  mime: string;
  /** Plaintext size in bytes. */
  size: number;
  key: string;
  nonce: string;
  /** base64url SHA-256 of the uploaded ciphertext. */
  sha256: string;
  /** Shown blurred until clicked (design note 4.13); absent = false. */
  spoiler?: boolean;
}

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const MIME = /^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/;

/** File name for display and download: no control characters or path separators, at most 255 characters. */
export function safeFileName(name: string): string {
  const cleaned = Array.from(name)
    .filter((c) => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) !== 0x7f)
    .map((c) => (c === "/" || c === "\\" ? "_" : c))
    .join("")
    .trim()
    .replace(/^\.+/, "")
    .slice(0, 255);
  return cleaned || "file";
}

function isB64(s: unknown, bytes: number): s is string {
  if (typeof s !== "string") return false;
  try {
    return b64urlDecode(s).length === bytes;
  } catch {
    return false;
  }
}

/**
 * The attachments of a decrypted content object that match the envelope: same blob id and ciphertext
 * hash, well-formed key and nonce. Anything else is dropped (a member cannot point others at blobs
 * that are not part of the message).
 */
export function contentAttachments(content: Record<string, unknown>, envelope: Attachment[] | undefined): ContentAttachment[] {
  const list = Array.isArray(content.attachments) ? content.attachments : [];
  const out: ContentAttachment[] = [];
  for (const raw of list.slice(0, 10)) {
    if (!raw || typeof raw !== "object") continue;
    const a = raw as Record<string, unknown>;
    if (typeof a.id !== "string" || !ULID.test(a.id)) continue;
    const env = envelope?.find((e) => e.id === a.id);
    if (!env || env.sha256 !== a.sha256) continue;
    if (!isB64(a.key, 32) || !isB64(a.nonce, 12) || !isB64(a.sha256, 32)) continue;
    const mime = typeof a.mime === "string" && MIME.test(a.mime.toLowerCase()) ? a.mime.toLowerCase() : "application/octet-stream";
    const size = typeof a.size === "number" && Number.isSafeInteger(a.size) && a.size >= 0 ? a.size : 0;
    const entry: ContentAttachment = { id: a.id, name: safeFileName(typeof a.name === "string" ? a.name : ""), mime, size, key: a.key, nonce: a.nonce, sha256: a.sha256 };
    if (a.spoiler === true) entry.spoiler = true;
    out.push(entry);
  }
  return out;
}

/** Encrypts a file for upload: the ciphertext blob and the metadata for the content (without the blob id). */
export async function encryptAttachment(file: File): Promise<{ blob: Blob; meta: Omit<ContentAttachment, "id"> }> {
  await ensureCrypto();
  const plain = new Uint8Array(await file.arrayBuffer());
  const f = encryptFile(plain);
  plain.fill(0);
  try {
    const key = f.key;
    const meta = { name: safeFileName(file.name), mime: file.type || "application/octet-stream", size: file.size, key: b64urlEncode(key), nonce: b64urlEncode(f.nonce), sha256: b64urlEncode(f.sha256) };
    key.fill(0);
    return { blob: new Blob([f.ciphertext as Uint8Array<ArrayBuffer>], { type: "application/octet-stream" }), meta };
  } finally {
    f.free();
  }
}

export class AttachmentIntegrityError extends Error {
  constructor() {
    super("attachment hash mismatch");
    this.name = "AttachmentIntegrityError";
  }
}

/**
 * Checks the bytes of a plaintext attachment against its `sha256` (base64url), which a signed plaintext message covers
 * (FEDERATION.md §10.3): throws {@link AttachmentIntegrityError} when the node served other bytes.
 */
export async function verifyPlainAttachment(bytes: Uint8Array, sha256: string): Promise<void> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>));
  if (b64urlEncode(digest) !== sha256) throw new AttachmentIntegrityError();
}

/** Checks the SHA-256 of the downloaded ciphertext (§6 step 4), then decrypts it. */
export async function decryptAttachment(ciphertext: Uint8Array, a: Pick<ContentAttachment, "key" | "nonce" | "sha256">): Promise<Uint8Array> {
  await ensureCrypto();
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ciphertext as Uint8Array<ArrayBuffer>));
  if (b64urlEncode(digest) !== a.sha256) throw new AttachmentIntegrityError();
  const key = b64urlDecode(a.key);
  try {
    return decryptFile(ciphertext, key, b64urlDecode(a.nonce), digest);
  } finally {
    key.fill(0);
  }
}
