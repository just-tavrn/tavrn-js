// SPDX-License-Identifier: Apache-2.0
/**
 * Upload categories (PROTOCOL.md §7a): the classification table every client shares with the node. Plaintext
 * uploads are classified by the node anyway; encrypted uploads are ciphertext, so the client classifies the file the
 * same way and declares the result in `Tavrn-Upload-Category`. The rules, in the node's order: content (magic bytes,
 * when the first bytes are given), then the file name's last extension, then the declared type; executables and other
 * dangerous types count as `other` and are flagged by content, extension or type alone. The protocol's
 * `testvectors/upload_categories.json` pins the behaviour for every implementation.
 */

export const UPLOAD_CATEGORIES = ["images", "audio", "video", "documents", "archives", "other"] as const;
export type UploadCategoryName = (typeof UPLOAD_CATEGORIES)[number];

/** A classified upload: its category and whether it is an executable (then always `other`). */
export interface ClassifiedUpload {
  category: UploadCategoryName;
  executable: boolean;
}

/** Bytes the classification looks at: ISO 9660 images carry their signature at 32–36 KiB. */
export const UPLOAD_HEAD_BYTES = 0x9001 + 5;

/** File extensions that run code when opened (Windows, macOS, Linux, Android, Java, Office macros), by kind. */
const KIND_OF_EXTENSION: Record<string, ExecutableKind> = Object.fromEntries(
  (
    [
      ["windows", "exe com pif scr cpl msc gadget application xll"],
      ["installer", "msi msix msp appx appxbundle deb rpm snap flatpakref appimage pkg mpkg"],
      ["script", "bat cmd ps1 psm1 psd1 vbs vbe js jse mjs wsf wsh wsc sct hta reg inf scf sh bash zsh csh ksh fish command py pyw pl rb php workflow action"],
      ["shortcut", "lnk url website settingcontent-ms desktop"],
      ["java", "jar class"],
      ["mobile_app", "apk aab xapk ipa"],
      ["disk_image", "dmg iso img vhd vhdx"],
      ["macro_document", "docm xlsm pptm dotm xltm potm ppam xlam"],
      ["library", "dll sys drv ocx"],
      ["macos", "app"],
      ["program", "run bin elf"],
    ] as const
  ).flatMap(([kind, list]) => list.split(" ").map((ext) => [ext, kind])),
);

/** Every dangerous extension of §7a. */
export const DANGEROUS_EXTENSIONS: ReadonlySet<string> = new Set(Object.keys(KIND_OF_EXTENSION));

/** Executable content types (prefixes of the lowercased `Content-Type`), by kind. */
const KIND_OF_TYPE: readonly [string, ExecutableKind][] = [
  ["application/x-msdownload", "windows"],
  ["application/x-msdos-program", "windows"],
  ["application/x-ms-installer", "installer"],
  ["application/x-executable", "program"],
  ["application/x-sh", "script"],
  ["application/x-bat", "script"],
  ["application/java-archive", "java"],
  ["application/vnd.android.package-archive", "mobile_app"],
  ["application/x-apple-diskimage", "disk_image"],
  ["application/x-iso9660-image", "disk_image"],
  ["application/javascript", "script"],
  ["text/javascript", "script"],
  ["application/hta", "script"],
  ["application/x-ms-shortcut", "shortcut"],
];

const EXTENSIONS: Record<Exclude<UploadCategoryName, "other">, readonly string[]> = {
  images: "png jpg jpeg jfif gif webp avif bmp ico tif tiff heic heif".split(" "),
  audio: "mp3 ogg oga opus wav flac m4a aac weba mid midi".split(" "),
  video: "mp4 m4v mov webm mkv avi ogv wmv flv 3gp".split(" "),
  // SVG can carry scripts: a document (download only), never an image (design note 4.12).
  documents: "pdf txt md markdown csv tsv json xml yaml yml toml ini cfg conf log rtf doc docx odt xls xlsx ods ppt pptx odp epub srt vtt svg svgz".split(" "),
  archives: "zip 7z rar tar gz tgz bz2 tbz2 xz txz zst lz lzma".split(" "),
};

/** The extensions of a category (for file pickers). */
export function extensionsOf(category: UploadCategoryName): readonly string[] {
  return category === "other" ? [] : EXTENSIONS[category];
}

/** What kind of program a file is (a download warning names it). */
export type ExecutableKind = "windows" | "linux" | "macos" | "java" | "mobile_app" | "script" | "shortcut" | "installer" | "disk_image" | "macro_document" | "library" | "program";

/** Lowercase last extension (`"a.tar.gz"` → `gz`), empty without one; trailing dots and spaces are ignored like on Windows. */
export function extensionOf(name: string): string {
  const clean = name.trim().replace(/[. ]+$/, "");
  const dot = clean.lastIndexOf(".");
  if (dot <= 0 || dot === clean.length - 1) return "";
  const ext = clean.slice(dot + 1);
  return ext.length <= 24 ? asciiLower(ext) : "";
}

function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

function categoryOfExtension(ext: string): UploadCategoryName | null {
  for (const [cat, list] of Object.entries(EXTENSIONS)) if (list.includes(ext)) return cat as UploadCategoryName;
  return null;
}

function categoryOfType(type: string): UploadCategoryName | null {
  const t = asciiLower(type.split(";")[0]!.trim());
  const slash = t.indexOf("/");
  if (slash < 0) return null;
  const top = t.slice(0, slash);
  const sub = t.slice(slash + 1);
  if (top === "image") return sub === "svg+xml" ? "documents" : "images";
  if (top === "audio") return "audio";
  if (top === "video") return "video";
  if (top === "text") return "documents";
  if (top === "application") {
    if (["pdf", "json", "xml", "rtf", "epub+zip", "msword", "vnd.ms-excel", "vnd.ms-powerpoint"].includes(sub)) return "documents";
    if (sub.startsWith("vnd.openxmlformats-officedocument.") || sub.startsWith("vnd.oasis.opendocument.")) return "documents";
    if (["zip", "x-7z-compressed", "vnd.rar", "x-rar-compressed", "x-tar", "gzip", "x-gzip", "x-bzip2", "x-xz", "zstd"].includes(sub)) return "archives";
  }
  return null;
}

type Sniffed = { executable: ExecutableKind } | { category: UploadCategoryName } | { zip: true };

/** SVG markup in the first KiB (`<svg`, possibly after an XML declaration, comments or a doctype). */
function looksLikeSvg(head: Uint8Array): boolean {
  const text = asciiLower(new TextDecoder().decode(head.subarray(0, 1024)));
  const trimmed = text.replace(/^﻿+/, "").trimStart();
  return trimmed.startsWith("<") && trimmed.includes("<svg");
}

/** What the magic bytes say (the node's `sniff`). */
function sniff(d: Uint8Array): Sniffed | null {
  const at = (offset: number, ...b: number[]) => offset + b.length <= d.length && b.every((v, i) => d[offset + i] === v);
  const text = (offset: number, s: string) => at(offset, ...[...s].map((c) => c.charCodeAt(0)));
  // Executables and scripts.
  if (text(0, "MZ")) return { executable: "windows" };
  if (at(0, 0x7f, 0x45, 0x4c, 0x46)) return { executable: "linux" };
  if (text(0, "#!")) return { executable: "script" };
  // Java class files and universal Mach-O binaries share this one.
  if (at(0, 0xca, 0xfe, 0xba, 0xbe)) return { executable: "java" };
  if (text(0, "dex\n")) return { executable: "mobile_app" };
  if (at(0, 0xfe, 0xed, 0xfa, 0xce) || at(0, 0xfe, 0xed, 0xfa, 0xcf) || at(0, 0xce, 0xfa, 0xed, 0xfe) || at(0, 0xcf, 0xfa, 0xed, 0xfe)) return { executable: "macos" };
  if (at(0, 0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0x00)) return { executable: "shortcut" };
  if (text(0x8001, "CD001") || text(0x8801, "CD001") || text(0x9001, "CD001") || text(0, "koly")) return { executable: "disk_image" };
  // Images.
  const ftyp = text(4, "ftyp");
  if (
    at(0, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a) ||
    at(0, 0xff, 0xd8, 0xff) ||
    text(0, "GIF87a") ||
    text(0, "GIF89a") ||
    (text(0, "RIFF") && text(8, "WEBP")) ||
    (text(0, "BM") && d.length > 26 && at(14, 40, 0, 0, 0)) ||
    (ftyp && (text(8, "avif") || text(8, "heic") || text(8, "mif1")))
  )
    return { category: "images" };
  // Audio.
  const ogg = text(0, "OggS");
  let theora = false;
  if (ogg) for (let i = 0; i < 128 && i + 6 <= d.length && !theora; i++) theora = text(i, "theora");
  if (
    text(0, "ID3") ||
    text(0, "fLaC") ||
    (text(0, "RIFF") && text(8, "WAVE")) ||
    (ogg && !theora) ||
    (d.length > 2 && d[0] === 0xff && (d[1]! & 0xe0) === 0xe0 && (d[1]! & 0x06) !== 0) ||
    (ftyp && (text(8, "M4A ") || text(8, "M4B "))) ||
    text(0, "MThd")
  )
    return { category: "audio" };
  // Video (ISO base media that is not an image or audio, Matroska/WebM, AVI, Ogg Theora).
  if (ftyp || at(0, 0x1a, 0x45, 0xdf, 0xa3) || (text(0, "RIFF") && text(8, "AVI ")) || ogg) return { category: "video" };
  if (text(0, "%PDF-") || looksLikeSvg(d)) return { category: "documents" };
  if (at(0, 0x50, 0x4b, 0x03, 0x04) || at(0, 0x50, 0x4b, 0x05, 0x06)) return { zip: true };
  if (
    at(0, 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c) ||
    text(0, "Rar!\u001a\u0007") ||
    at(0, 0x1f, 0x8b) ||
    text(0, "BZh") ||
    at(0, 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00) ||
    at(0, 0x28, 0xb5, 0x2f, 0xfd) ||
    text(257, "ustar")
  )
    return { category: "archives" };
  return null;
}

/**
 * Is a file an executable, a script or another type that runs code when opened, and which kind? Content (when `head`
 * is given) first, then the extension, then the type. Archives are not executables; ZIP-based apps (jar, apk) and
 * macro documents are, by their extension.
 */
export function executableKind(name: string, type: string, head?: Uint8Array): ExecutableKind | null {
  const sniffed = head ? sniff(head) : null;
  if (sniffed && "executable" in sniffed) return sniffed.executable;
  const ext = extensionOf(name);
  if (Object.prototype.hasOwnProperty.call(KIND_OF_EXTENSION, ext)) return KIND_OF_EXTENSION[ext]!;
  const t = asciiLower(type);
  return KIND_OF_TYPE.find(([prefix]) => t.startsWith(prefix))?.[1] ?? null;
}

/**
 * The category of a file by its name, type and, if given, its first bytes ({@link UPLOAD_HEAD_BYTES} are enough), with
 * the node's rules (PROTOCOL.md §7a).
 */
export function classifyUpload(name: string, type = "", head?: Uint8Array): ClassifiedUpload {
  const sniffed = head ? sniff(head) : null;
  if (sniffed && "executable" in sniffed) return { category: "other", executable: true };
  if (executableKind(name, type) !== null) return { category: "other", executable: true };
  const ext = extensionOf(name);
  let category: UploadCategoryName;
  if (sniffed && "category" in sniffed) category = sniffed.category;
  else if (sniffed) category = categoryOfExtension(ext) === "documents" ? "documents" : "archives";
  else category = categoryOfExtension(ext) ?? categoryOfType(type) ?? "other";
  return { category, executable: false };
}

/** The value of `Tavrn-Upload-Category` for an encrypted upload: the category, or `executable`. */
export function declaredCategory(c: ClassifiedUpload): UploadCategoryName | "executable" {
  return c.executable ? "executable" : c.category;
}
