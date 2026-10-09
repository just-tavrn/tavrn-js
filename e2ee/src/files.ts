// SPDX-License-Identifier: MPL-2.0
/**
 * End-to-end encrypted files channels (FILES.md §8, ENCRYPTION.md §5c).
 *
 * Content: every file gets a random 32-byte file key; its content (part `content`) and its client-made thumbnail
 * (part `thumbnail`) are encrypted in chunks of 1 MiB with AES-256-GCM under
 * `part_key = HKDF-SHA256(file_key, salt = 32 zero bytes, info = "tavrn file chunk v1" || 0x00 || part)`, nonce
 * `u32(0) || u64(index)` and `aad = "tavrn file chunk v1" || 0x00 || u8(last)`. Everything here is WebCrypto, so it
 * runs in browsers, workers and Node.js without the WebAssembly module; chunks are processed one at a time
 * (bounded memory: a Blob of encrypted chunks for uploads, a TransformStream for downloads).
 *
 * Records: the name, type and file key travel in an entry record, content format 1 (ENCRYPTION.md §5.2) of
 * `{ type: "files.entry", v: 1, entry, kind, name, mime?, size?, key?, thumbnail? }` under the channel's current
 * epoch. Encrypting goes through {@link MlsManager.encrypt} (forwarded to the tab that owns the MLS state);
 * decrypting stays local ({@link MlsManager.decrypt}).
 */
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import type { DecryptFailure, MlsManager } from "./mls";

export const FILE_CHUNK = 1 << 20;
export const FILE_TAG = 16;
export const FILE_CHUNK_LABEL = "tavrn file chunk v1";
export type FilePart = "content" | "thumbnail";
export const FILE_RECORD_TYPE = "files.entry";
/** Longest name in characters (FILES.md §2). */
export const MAX_ENTRY_NAME = 255;

const enc = new TextEncoder();
const subtle = (): SubtleCrypto => globalThis.crypto.subtle;
const buf = (b: Uint8Array): Uint8Array<ArrayBuffer> => (b.buffer instanceof ArrayBuffer && b.byteOffset === 0 && b.byteLength === b.buffer.byteLength ? (b as Uint8Array<ArrayBuffer>) : new Uint8Array(b));

/** A fresh random file key. */
export function newFileKey(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

/** The AES-256-GCM key of one part of a file. */
export async function filePartKey(fileKey: Uint8Array, part: FilePart): Promise<CryptoKey> {
  if (fileKey.length !== 32) throw new RangeError("file keys have 32 bytes");
  const ikm = await subtle().importKey("raw", buf(fileKey), "HKDF", false, ["deriveKey"]);
  const info = new Uint8Array([...enc.encode(FILE_CHUNK_LABEL), 0, ...enc.encode(part)]);
  return subtle().deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info }, ikm, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

/** `u32(0) || u64(index)`. */
export function chunkNonce(index: number): Uint8Array {
  if (!Number.isSafeInteger(index) || index < 0) throw new RangeError("chunk index");
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(4, BigInt(index));
  return n;
}

/** `"tavrn file chunk v1" || 0x00 || u8(last)`. */
export function chunkAad(last: boolean): Uint8Array {
  return new Uint8Array([...enc.encode(FILE_CHUNK_LABEL), 0, last ? 1 : 0]);
}

/** Number of chunks of a part with `n` plaintext bytes (an empty part is one empty chunk). */
export function chunkCount(n: number): number {
  return Math.max(1, Math.ceil(n / FILE_CHUNK));
}

/** Stored (ciphertext) size of a part with `n` plaintext bytes. */
export function encryptedSize(n: number): number {
  return n + FILE_TAG * chunkCount(n);
}

/** Plaintext size of a stored part, or null when no plaintext size encrypts to `stored` bytes. */
export function plaintextSize(stored: number): number | null {
  if (!Number.isSafeInteger(stored) || stored < FILE_TAG) return null;
  const chunks = Math.max(1, Math.ceil(stored / (FILE_CHUNK + FILE_TAG)));
  const n = stored - FILE_TAG * chunks;
  if (n < 0 || (chunks > 1 && n <= (chunks - 1) * FILE_CHUNK)) return null;
  return n;
}

export async function encryptChunk(key: CryptoKey, index: number, last: boolean, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: buf(chunkNonce(index)), additionalData: buf(chunkAad(last)), tagLength: 128 }, key, buf(data)));
}

export class FileDecryptError extends Error {
  constructor(message = "file chunk does not decrypt") {
    super(message);
    this.name = "FileDecryptError";
  }
}

export async function decryptChunk(key: CryptoKey, index: number, last: boolean, data: Uint8Array): Promise<Uint8Array> {
  try {
    return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: buf(chunkNonce(index)), additionalData: buf(chunkAad(last)), tagLength: 128 }, key, buf(data)));
  } catch {
    throw new FileDecryptError();
  }
}

/** Encrypts a whole part held in memory (thumbnails, tests). */
export async function encryptFileBytes(fileKey: Uint8Array, part: FilePart, plain: Uint8Array): Promise<Uint8Array> {
  const key = await filePartKey(fileKey, part);
  const chunks = chunkCount(plain.length);
  const out = new Uint8Array(encryptedSize(plain.length));
  for (let i = 0; i < chunks; i++) {
    const c = await encryptChunk(key, i, i === chunks - 1, plain.subarray(i * FILE_CHUNK, (i + 1) * FILE_CHUNK));
    out.set(c, i * (FILE_CHUNK + FILE_TAG));
  }
  return out;
}

/** Decrypts a whole part held in memory. */
export async function decryptFileBytes(fileKey: Uint8Array, part: FilePart, stored: Uint8Array): Promise<Uint8Array> {
  const n = plaintextSize(stored.length);
  if (n === null) throw new FileDecryptError("invalid ciphertext size");
  const key = await filePartKey(fileKey, part);
  const chunks = chunkCount(n);
  const out = new Uint8Array(n);
  for (let i = 0; i < chunks; i++) {
    const from = i * (FILE_CHUNK + FILE_TAG);
    const p = await decryptChunk(key, i, i === chunks - 1, stored.subarray(from, Math.min(from + FILE_CHUNK + FILE_TAG, stored.length)));
    out.set(p, i * FILE_CHUNK);
  }
  return out;
}

/**
 * Encrypts a file for upload chunk by chunk (one chunk in memory at a time): the ciphertext as a Blob of encrypted
 * chunks, the file key (caller zeroes it after writing the record) and the plaintext size.
 */
export async function encryptFileStream(file: Blob, opts: { fileKey?: Uint8Array; part?: FilePart; onProgress?: (fraction: number) => void; signal?: AbortSignal } = {}): Promise<{ blob: Blob; key: Uint8Array; size: number }> {
  const fileKey = opts.fileKey ?? newFileKey();
  const key = await filePartKey(fileKey, opts.part ?? "content");
  const chunks = chunkCount(file.size);
  const parts: BlobPart[] = [];
  for (let i = 0; i < chunks; i++) {
    if (opts.signal?.aborted) throw new DOMException("aborted", "AbortError");
    const plain = new Uint8Array(await file.slice(i * FILE_CHUNK, (i + 1) * FILE_CHUNK).arrayBuffer());
    parts.push(buf(await encryptChunk(key, i, i === chunks - 1, plain)));
    plain.fill(0);
    opts.onProgress?.((i + 1) / chunks);
  }
  return { blob: new Blob(parts, { type: "application/octet-stream" }), key: fileKey, size: file.size };
}

/**
 * A stream that decrypts the stored chunks `firstChunk … endChunk` (default: to the end) of a part with `storedSize`
 * ciphertext bytes, whatever the network's chunking. The input starts at the first byte of `firstChunk` (a range
 * request, see {@link ciphertextRange}); a stream that ends early or carries a damaged chunk errors with
 * {@link FileDecryptError}.
 */
export function decryptFileChunks(fileKey: Uint8Array, part: FilePart, storedSize: number, firstChunk = 0, endChunk?: number): TransformStream<Uint8Array, Uint8Array> {
  const n = plaintextSize(storedSize);
  const lastIndex = n === null ? -1 : chunkCount(n) - 1;
  const stopAt = Math.min(endChunk ?? lastIndex, lastIndex);
  const keyP = filePartKey(fileKey, part);
  // Received bytes not decrypted yet, as a list (no quadratic copying of small network pieces).
  let parts: Uint8Array[] = [];
  let buffered = 0;
  let index = firstChunk;
  const sizeOf = (i: number) => (i === lastIndex ? storedSize - i * (FILE_CHUNK + FILE_TAG) : FILE_CHUNK + FILE_TAG);
  const take = (size: number): Uint8Array => {
    const out = new Uint8Array(size);
    let at = 0;
    while (at < size) {
      const head = parts[0]!;
      const n = Math.min(head.length, size - at);
      out.set(head.subarray(0, n), at);
      at += n;
      if (n === head.length) parts.shift();
      else parts[0] = head.subarray(n);
    }
    buffered -= size;
    return out;
  };
  const drain = async (controller: TransformStreamDefaultController<Uint8Array>, flush: boolean) => {
    const key = await keyP;
    while (index <= stopAt && buffered >= sizeOf(index)) {
      const size = sizeOf(index);
      controller.enqueue(await decryptChunk(key, index, index === lastIndex, take(size)));
      index++;
    }
    if (flush && buffered > 0) throw new FileDecryptError("trailing bytes");
  };
  return new TransformStream<Uint8Array, Uint8Array>({
    start() {
      if (n === null) throw new FileDecryptError("invalid ciphertext size");
    },
    async transform(chunk, controller) {
      if (chunk.length === 0) return;
      parts.push(chunk);
      buffered += chunk.length;
      await drain(controller, false);
    },
    async flush(controller) {
      await drain(controller, true);
      parts = [];
      if (firstChunk <= stopAt && index !== stopAt + 1) throw new FileDecryptError("the file ends early");
    },
  });
}

/**
 * The stored byte range (inclusive) that holds the plaintext bytes `[from, to]` of a part, the first and last chunk
 * index and how many plaintext bytes to skip in the first chunk. `null` when the range is outside the part.
 */
export function ciphertextRange(from: number, to: number, storedSize: number): { start: number; end: number; firstChunk: number; lastChunk: number; skip: number } | null {
  const n = plaintextSize(storedSize);
  if (n === null || from < 0 || to < from || from >= n) return null;
  const last = Math.min(to, n - 1);
  const firstChunk = Math.floor(from / FILE_CHUNK);
  const lastChunk = Math.floor(last / FILE_CHUNK);
  return {
    start: firstChunk * (FILE_CHUNK + FILE_TAG),
    end: Math.min((lastChunk + 1) * (FILE_CHUNK + FILE_TAG), storedSize) - 1,
    firstChunk,
    lastChunk,
    skip: from - firstChunk * FILE_CHUNK,
  };
}

// ---- Entry records (FILES.md §8.4) --------------------------------------------------------------

export interface FileThumbnailMeta {
  mime: string;
  width: number;
  height: number;
}

/** A checked record. Files carry `mime`, `size` (plaintext bytes) and `key`; folders only the name. */
export interface FileRecord {
  entry: string;
  kind: "file" | "folder";
  name: string;
  mime: string;
  size: number;
  key: string;
  thumbnail?: FileThumbnailMeta;
}

/** What a record is checked against: the entry as the node lists it. */
export interface RecordEntry {
  id: string;
  kind: string;
  /** Stored (ciphertext) size. */
  size: number;
  record?: string | null;
  record_epoch?: number | null;
  record_author?: string | null;
  record_device_id?: string | null;
  record_at?: string | null;
}

const MIME = /^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/;
const RASTER = /^image\/(png|jpeg|gif|webp|avif|bmp)$/;
// Bidirectional controls that can disguise an extension (FILES.md §2).
const BIDI = /[‎‏‪-‮⁦-⁩؜]/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** The rules of FILES.md §2 for a name: NFC, trimmed, 1–255 characters, no `/`, `\`, controls or bidi controls, not `.`/`..`. */
export function validEntryName(name: unknown): name is string {
  if (typeof name !== "string") return false;
  const n = name.normalize("NFC").trim();
  if (n !== name || !n || Array.from(n).length > MAX_ENTRY_NAME) return false;
  if (n.includes("/") || n.includes("\\") || CONTROL.test(n) || BIDI.test(n)) return false;
  return n !== "." && n !== "..";
}

/** Normalises a name for a record (NFC, trimmed) and checks it; null when it breaks FILES.md §2. */
export function entryName(raw: string): string | null {
  const n = raw.normalize("NFC").trim();
  return validEntryName(n) ? n : null;
}

/** The JSON object of a record (written by the uploader or a renaming member). */
export function fileRecordContent(r: FileRecord): Record<string, unknown> {
  if (!validEntryName(r.name)) throw new RangeError("invalid entry name");
  if (r.kind === "folder") return { type: FILE_RECORD_TYPE, v: 1, entry: r.entry, kind: "folder", name: r.name };
  const out: Record<string, unknown> = { type: FILE_RECORD_TYPE, v: 1, entry: r.entry, kind: "file", name: r.name, mime: MIME.test(r.mime) ? r.mime : "application/octet-stream", size: r.size, key: r.key };
  if (r.thumbnail) out.thumbnail = { mime: r.thumbnail.mime, width: r.thumbnail.width, height: r.thumbnail.height };
  return out;
}

/** Checks a decrypted record against its entry (FILES.md §8.4); null when the record must be refused. */
export function parseFileRecord(content: Record<string, unknown>, entry: Pick<RecordEntry, "id" | "kind" | "size">): FileRecord | null {
  if (content.type !== FILE_RECORD_TYPE || content.v !== 1) return null;
  if (content.entry !== entry.id || content.kind !== entry.kind) return null;
  if (!validEntryName(content.name)) return null;
  if (content.kind === "folder") return { entry: entry.id, kind: "folder", name: content.name, mime: "", size: 0, key: "" };
  if (content.kind !== "file") return null;
  const size = content.size;
  if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0 || encryptedSize(size) !== entry.size) return null;
  if (typeof content.key !== "string") return null;
  try {
    if (b64urlDecode(content.key).length !== 32) return null;
  } catch {
    return null;
  }
  const mime = typeof content.mime === "string" && MIME.test(content.mime) ? content.mime : "application/octet-stream";
  const out: FileRecord = { entry: entry.id, kind: "file", name: content.name, mime, size, key: content.key };
  const t = content.thumbnail as Record<string, unknown> | undefined;
  if (t && typeof t === "object" && typeof t.mime === "string" && RASTER.test(t.mime)) {
    const w = Number(t.width);
    const h = Number(t.height);
    if (Number.isSafeInteger(w) && Number.isSafeInteger(h) && w > 0 && h > 0 && w <= 4096 && h <= 4096) out.thumbnail = { mime: t.mime, width: w, height: h };
  }
  return out;
}

/** Encrypts a record under the channel's current epoch (forwarded to the owning tab like every state change). */
export async function encryptFileRecord(mls: Pick<MlsManager, "encrypt">, conversationId: string, r: FileRecord): Promise<{ record: string; record_epoch: number }> {
  const { content, epoch } = await mls.encrypt(conversationId, fileRecordContent(r));
  return { record: content, record_epoch: epoch };
}

export type FileRecordResult = { ok: true; record: FileRecord } | { ok: false; reason: DecryptFailure | "withheld" };

/**
 * Decrypts and checks the record of an entry (local). `withheld`: the node serves no record (outside the history
 * window or none written); the other reasons are those of message content.
 */
export async function decryptFileRecord(mls: Pick<MlsManager, "decrypt">, conversationId: string, e: RecordEntry): Promise<FileRecordResult> {
  if (!e.record || !e.record_author || !e.record_device_id || typeof e.record_epoch !== "number") return { ok: false, reason: "withheld" };
  const r = await mls.decrypt(conversationId, { id: `files-entry:${e.id}`, author: e.record_author, device_id: e.record_device_id, epoch: e.record_epoch, content: e.record, created_at: e.record_at ?? null });
  if (!r.ok) return r;
  const record = parseFileRecord(r.content, e);
  return record ? { ok: true, record } : { ok: false, reason: "invalid" };
}

/**
 * Entries with records as the message samples of history key checks (ENCRYPTION.md §7b, FILES.md §8.7): a files
 * channel has no messages, a shared epoch key is checked against an entry record of that epoch instead.
 */
export function recordSamples(entries: RecordEntry[]): { author: string; device_id: string; epoch: number; content: string; encrypted: true }[] {
  const out: { author: string; device_id: string; epoch: number; content: string; encrypted: true }[] = [];
  for (const e of entries) {
    if (e.record && e.record_author && e.record_device_id && typeof e.record_epoch === "number") out.push({ author: e.record_author, device_id: e.record_device_id, epoch: e.record_epoch, content: e.record, encrypted: true });
  }
  return out;
}

/** The file key of a record as bytes (caller zeroes it). */
export function recordKey(r: FileRecord): Uint8Array {
  return b64urlDecode(r.key);
}

export { b64urlEncode as fileKeyText };
