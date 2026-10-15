// SPDX-License-Identifier: Apache-2.0
/**
 * Attachments of bot messages (PROTOCOL.md §7, §7a, ENCRYPTION.md §6). Plaintext conversations upload the file as it
 * is and the node classifies it; encrypted ones upload only ciphertext, so the bot declares the upload category
 * (`Tavrn-Upload-Category`) from the file name and type with the table of §7a (cooperative, like every client).
 */

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

export type UploadCategory = "images" | "audio" | "video" | "documents" | "archives" | "other" | "executable";

const EXTENSIONS: Record<Exclude<UploadCategory, "other" | "executable">, string[]> = {
  images: "png jpg jpeg jfif gif webp avif bmp ico tif tiff heic heif".split(" "),
  audio: "mp3 ogg oga opus wav flac m4a aac weba mid midi".split(" "),
  video: "mp4 m4v mov webm mkv avi ogv wmv flv 3gp".split(" "),
  documents: "pdf txt md markdown csv tsv json xml yaml yml toml ini cfg conf log rtf doc docx odt xls xlsx ods ppt pptx odp epub srt vtt svg svgz".split(" "),
  archives: "zip 7z rar tar gz tgz bz2 tbz2 xz txz zst lz lzma".split(" "),
};

const DANGEROUS = new Set(
  (
    "exe msi msix msp appx appxbundle bat cmd com pif scr cpl hta reg lnk url inf ps1 psm1 psd1 vbs vbe js jse mjs wsf wsh wsc sct jar class " +
    "apk aab xapk ipa dmg pkg mpkg app command sh bash zsh csh ksh fish run bin elf deb rpm snap flatpakref appimage iso img vhd vhdx xll docm " +
    "xlsm pptm dotm xltm potm ppam xlam gadget msc application scf dll sys drv ocx py pyw pl rb php desktop workflow action website settingcontent-ms"
  ).split(" "),
);

function extensionOf(name: string): string {
  const clean = name.trim().replace(/[. ]+$/, "");
  const dot = clean.lastIndexOf(".");
  if (dot <= 0 || dot === clean.length - 1) return "";
  return clean.slice(dot + 1).toLowerCase();
}

/**
 * The upload category of a file (PROTOCOL.md §7a) by its name's last extension, then its MIME type; executables and
 * scripts by extension or type are `executable` (refused unless the node allows them). SVG is a document.
 */
export function uploadCategory(name: string, mime = ""): UploadCategory {
  const ext = extensionOf(name);
  const type = mime.split(";")[0]!.trim().toLowerCase();
  if (DANGEROUS.has(ext) || /^application\/(x-msdownload|x-sh|x-executable|java-archive|vnd\.android\.package-archive|(x-)?javascript)$/.test(type) || type === "text/javascript") return "executable";
  for (const [cat, list] of Object.entries(EXTENSIONS)) if (list.includes(ext)) return cat as UploadCategory;
  const [top, sub = ""] = type.split("/");
  if (top === "image") return sub === "svg+xml" ? "documents" : "images";
  if (top === "audio") return "audio";
  if (top === "video") return "video";
  if (top === "text") return "documents";
  if (top === "application") {
    if (["pdf", "json", "xml", "rtf", "epub+zip", "msword", "vnd.ms-excel", "vnd.ms-powerpoint"].includes(sub)) return "documents";
    if (sub.startsWith("vnd.openxmlformats-officedocument.") || sub.startsWith("vnd.oasis.opendocument.")) return "documents";
    if (["zip", "x-7z-compressed", "vnd.rar", "x-rar-compressed", "x-tar", "gzip", "x-gzip", "x-bzip2", "x-xz", "zstd"].includes(sub)) return "archives";
  }
  return "other";
}

/** The file's bytes as a `File` (name and type kept) for the upload and the encryption codecs. */
export async function asFile(f: BotFile): Promise<File> {
  const type = f.mime?.trim() || (f.data instanceof Blob && f.data.type) || "application/octet-stream";
  const bytes = f.data instanceof Blob ? new Uint8Array(await f.data.arrayBuffer()) : f.data;
  return new File([bytes as BlobPart], f.name, { type });
}
