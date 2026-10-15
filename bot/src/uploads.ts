// SPDX-License-Identifier: Apache-2.0
/**
 * Attachments of bot messages (PROTOCOL.md §7, §7a, ENCRYPTION.md §6). Plaintext conversations upload the file as it
 * is and the node classifies it; encrypted ones upload only ciphertext, so the bot declares the upload category
 * (`Tavrn-Upload-Category`) from the file's first bytes, name and type with the table of §7a (cooperative, like every
 * client; the table is the SDK's `classifyUpload`).
 */
import { UPLOAD_HEAD_BYTES, classifyUpload, declaredCategory, type UploadCategoryName } from "@tavrn/sdk";

/** A file to attach to a message. */
export interface BotFile {
  /** File name shown to readers (at most 255 characters; path separators and control characters are replaced). */
  name: string;
  data: Uint8Array | Blob;
  /** MIME type (default: `application/octet-stream`). */
  mime?: string;
  /** Shown blurred until clicked (PROTOCOL.md §7b). */
  spoiler?: boolean;
}

/** A downloaded attachment (decrypted in encrypted conversations). */
export interface DownloadedFile {
  id: string;
  name: string;
  mime: string;
  size: number;
  data: Uint8Array;
}

/** At most this many attachments per message (PROTOCOL.md §7). */
export const MAX_ATTACHMENTS = 10;

export type UploadCategory = UploadCategoryName | "executable";

/**
 * The upload category to declare for a file (PROTOCOL.md §7a): the SDK's classification (`classifyUpload`, the node's
 * table and order: content when `head` is given, then the last extension, then the MIME type); executables and
 * scripts are `executable` (refused unless the node allows them). SVG is a document.
 */
export function uploadCategory(name: string, mime = "", head?: Uint8Array): UploadCategory {
  return declaredCategory(classifyUpload(name, mime, head));
}

/** The file's bytes as a `File` (name and type kept) for the upload and the encryption codecs, and its category. */
export async function asFile(f: BotFile): Promise<{ file: File; category: UploadCategory }> {
  const type = f.mime?.trim() || (f.data instanceof Blob && f.data.type) || "application/octet-stream";
  const bytes = f.data instanceof Blob ? new Uint8Array(await f.data.arrayBuffer()) : f.data;
  return { file: new File([bytes as BlobPart], f.name, { type }), category: uploadCategory(f.name, type, bytes.subarray(0, UPLOAD_HEAD_BYTES)) };
}
