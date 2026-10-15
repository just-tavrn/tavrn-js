// SPDX-License-Identifier: Apache-2.0
/**
 * Files channels for bots (protocol/FILES.md §3 "Bots", §8; APPLICATIONS.md §2.4): browsing and downloads with the scope
 * `messages:read`, folders, uploads and deletes with `messages:write` (the channel's `attach_files`; others' entries
 * only with `manage_files`, which `rooms:manage` unlocks). The storage backend is closed to bots.
 *
 * Unencrypted channels upload the file as it is (the node checks the name and classifies the content). End-to-end
 * encrypted channels work like the web client, with the functions of `@tavrn/e2ee`: every file gets a fresh file key,
 * the content is encrypted in chunks, and name, type and key travel in an entry record encrypted under the channel's
 * current epoch, written by the bot device as a member of the channel's MLS group. The node never sees a name or a
 * byte of content. Records the bot cannot open (written before it could read the channel, damaged) are listed as
 * `locked` entries with their size and dates only.
 */
import { openAsBlob } from "node:fs";
import { basename } from "node:path";
import { decryptFileChunks, decryptFileRecord, encryptFileRecord, encryptFileStream, entryName, fileKeyText, newFileKey, recordKey, type FileRecord, type MlsManager } from "@tavrn/e2ee";
import { TavrnApiError, newUlid, type DeleteResult, type FileEntry, type TavrnApi } from "@tavrn/sdk";
import { BotError } from "./errors";
import { uploadCategory, type DownloadedFile } from "./uploads";

/** An entry of a files channel as the bot sees it (decrypted in encrypted channels). */
export interface BotFileEntry {
  id: string;
  /** The room node. */
  node: string;
  /** Qualified id of the files channel (`<node>/<channel id>`). */
  conversation: string;
  roomId: string;
  channelId: string;
  kind: "file" | "folder";
  /** The name (`""` for a locked entry). */
  name: string;
  /** Content type (`""` for folders and locked entries). */
  mime: string;
  /** Plaintext bytes (0 for folders; the stored ciphertext size for a locked entry). */
  size: number;
  /** The folder it is in, `null` at the top level. */
  parentId: string | null;
  /** User id of the uploader or creator (`null` after the account was deleted). */
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
  encrypted: boolean;
  /**
   * Encrypted channels: the record cannot be opened by the bot (written before it could read the channel, outside its
   * history window, or damaged). Such an entry has no name or type; its owner can still delete it.
   */
  locked: boolean;
  raw: FileEntry;
}

/** A file to upload into a files channel: the bytes (`data`) or a file on disk (`path`). */
export interface BotFileUpload {
  /** Name shown in the channel (FILES.md §2: 1–255 characters, no `/`, `\` or control characters); default: the base name of `path`. */
  name?: string;
  data?: Uint8Array | Blob;
  /** A file read from disk as a stream (not held in memory as a whole in unencrypted channels). */
  path?: string;
  /** Content type (default: the Blob's type or `application/octet-stream`). */
  mime?: string;
  /** The folder (id or entry; absent or `null`: the top level). */
  folder?: FolderRef;
  /** A taken name becomes `name (2).ext` instead of failing with `409 files.name_taken`. */
  rename?: boolean;
}

/** `files.update` (FILES.md §3): the content of a folder changed; list it again. */
export interface FilesEvent {
  node: string;
  conversation: string;
  roomId: string;
  channelId: string;
  /** The folder whose content changed, `null` for the top level. */
  folderId: string | null;
}

export type FolderRef = string | Pick<BotFileEntry, "id"> | null | undefined;
type ChannelRef = string | { conversation: string };
type EntryRef = BotFileEntry | { conversation: string; id: string };

/** What the runtime gives the files helpers (the bot's links, channels and encryption state). */
export interface FilesHost {
  /** The qualified id, the room node and the bare id of a channel, with the API client on that node. */
  target(channel: ChannelRef): { q: string; domain: string; id: string; api: TavrnApi };
  /** The channel as the bot knows it (`BotError("not_member")` when it cannot view it). */
  channel(q: string): Promise<{ roomId: string; kind: string; encrypted: boolean }>;
  /** Joins the channel's group (`create`: create it if there is none yet); false when that is refused. */
  join(q: string, create: boolean): Promise<boolean>;
  mls(): MlsManager;
  /** An encryption under the bot's ghost policy. */
  seal<T>(q: string, fn: () => Promise<T>): Promise<T>;
  /** Runs an encrypted write once more after catching up when the node answers `mls.epoch_stale`. */
  freshEpoch<T>(q: string, fn: () => Promise<T>): Promise<T>;
  /** The bot's download cap in bytes (`maxDownloadBytes`). */
  maxDownloadBytes(): number;
}

const PAGE = 200;

function folderId(folder: FolderRef): string | null {
  if (folder === undefined || folder === null) return null;
  return typeof folder === "string" ? folder : folder.id;
}

function checkedName(raw: string): string {
  const name = entryName(raw);
  if (!name) throw new RangeError("invalid name (FILES.md §2: 1–255 characters, no / or \\, no control characters, not . or ..)");
  return name;
}

/** `name (n).ext`, the node's numbering of `Tavrn-Conflict: rename` (FILES.md §3). */
function numbered(name: string, n: number): string {
  const dot = name.lastIndexOf(".");
  const ext = dot > 0 ? name.slice(dot + 1) : "";
  return ext && ext.length <= 16 ? `${name.slice(0, dot)} (${n}).${ext}` : `${name} (${n})`;
}

function nameTaken(name: string): TavrnApiError {
  return new TavrnApiError({ type: "about:blank", title: "Conflict", status: 409, code: "files.name_taken", detail: `"${name}" already exists in this folder` });
}

/** The files helpers of a bot (`bot.files`). */
export class BotFiles {
  /** The decrypted records of the entries handed out (kept off the entry objects, so no file key is ever logged). */
  private readonly records = new WeakMap<BotFileEntry, FileRecord>();

  constructor(private readonly host: FilesHost) {}

  private async open(channel: ChannelRef) {
    const t = this.host.target(channel);
    const c = await this.host.channel(t.q);
    if (c.kind !== "files") throw new BotError("not_found", `${t.q} is not a files channel`);
    return { ...t, roomId: c.roomId, encrypted: c.encrypted };
  }

  private entry(ch: { q: string; domain: string; id: string; roomId: string; encrypted: boolean }, raw: FileEntry, record: FileRecord | null): BotFileEntry {
    const kind = raw.kind === "folder" ? "folder" : "file";
    const locked = ch.encrypted && !record;
    const e: BotFileEntry = {
      id: raw.id,
      node: ch.domain,
      conversation: ch.q,
      roomId: ch.roomId,
      channelId: ch.id,
      kind,
      name: ch.encrypted ? (record?.name ?? "") : raw.name,
      mime: ch.encrypted ? (record?.mime ?? "") : raw.mime,
      size: record && kind === "file" ? record.size : raw.size,
      parentId: raw.parent_id ?? null,
      createdBy: raw.created_by ?? null,
      createdAt: raw.created_at,
      updatedAt: raw.updated_at,
      encrypted: ch.encrypted,
      locked,
      raw,
    };
    if (record) this.records.set(e, record);
    return e;
  }

  /** The record of an entry in an encrypted channel, or null when the bot cannot open it. */
  private async openRecord(q: string, raw: FileEntry): Promise<FileRecord | null> {
    const r = await decryptFileRecord(this.host.mls(), q, raw).catch(() => null);
    return r?.ok ? r.record : null;
  }

  private async entries(ch: Awaited<ReturnType<BotFiles["open"]>>, raws: FileEntry[]): Promise<BotFileEntry[]> {
    const out: BotFileEntry[] = [];
    for (const raw of raws) out.push(this.entry(ch, raw, ch.encrypted ? await this.openRecord(ch.q, raw) : null));
    return out;
  }

  /**
   * The entries of a folder (absent or `null`: the top level), every page: folders first, then by name (encrypted
   * channels sort after decrypting; locked entries come last).
   */
  async list(channel: ChannelRef, folder?: FolderRef): Promise<BotFileEntry[]> {
    const ch = await this.open(channel);
    if (ch.encrypted) await this.host.join(ch.q, false);
    const raws: FileEntry[] = [];
    let after: string | null = null;
    do {
      const page = await ch.api.files.list(ch.roomId, ch.id, { parent: folderId(folder), limit: PAGE, after });
      raws.push(...page.entries);
      after = page.next_after ?? null;
    } while (after);
    const list = await this.entries(ch, raws);
    if (!ch.encrypted) return list;
    const rank = (e: BotFileEntry) => (e.locked ? 2 : e.kind === "folder" ? 0 : 1);
    return list.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  }

  /** One entry of a channel by id. */
  async get(channel: ChannelRef, entryId: string): Promise<BotFileEntry> {
    const ch = await this.open(channel);
    if (ch.encrypted) await this.host.join(ch.q, false);
    const { entry } = await ch.api.files.get(ch.roomId, ch.id, entryId);
    return (await this.entries(ch, [entry]))[0]!;
  }

  private async resolve(ref: EntryRef): Promise<BotFileEntry> {
    if ("raw" in ref && this.records.has(ref)) return ref;
    if ("raw" in ref && !ref.encrypted) return ref;
    return this.get(ref.conversation, ref.id);
  }

  /** Downloads a file (decrypted in encrypted channels). */
  async download(entry: EntryRef): Promise<DownloadedFile> {
    const e = await this.resolve(entry);
    if (e.kind !== "file") throw new RangeError("folders cannot be downloaded");
    const { api } = this.host.target(e.conversation);
    // Downloads are held in memory: at most the bot's cap, and never more than the entry's stored size.
    const max = this.host.maxDownloadBytes();
    if (e.raw.size > max) throw new TavrnApiError({ type: "about:blank", title: "Response too large", status: 0, detail: `${e.raw.size} bytes, at most ${max} accepted`, code: "response.too_large" });
    if (!e.encrypted) {
      const blob = await api.files.download(e.roomId, e.channelId, e.id, { maxBytes: e.raw.size });
      return { id: e.id, name: e.name, mime: e.mime, size: blob.size, data: new Uint8Array(await blob.arrayBuffer()) };
    }
    const record = this.records.get(e);
    if (!record) throw new BotError("not_member", `The bot cannot open the record of ${e.id} (no key for its epoch)`);
    const resp = await api.files.downloadResponse(e.roomId, e.channelId, e.id);
    if (!resp.body) throw new BotError("node_invalid", "The node sent an empty download");
    const key = recordKey(record);
    try {
      const parts: Uint8Array[] = [];
      let size = 0;
      const reader = resp.body.pipeThrough(decryptFileChunks(key, "content", e.raw.size)).getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        parts.push(value);
        size += value.length;
      }
      const data = new Uint8Array(size);
      let at = 0;
      for (const p of parts) {
        data.set(p, at);
        at += p.length;
      }
      return { id: e.id, name: record.name, mime: record.mime, size, data };
    } finally {
      key.fill(0);
    }
  }

  /** In encrypted channels the node cannot check names: the bot checks the decrypted folder (FILES.md §8.5). */
  private async freeName(ch: Awaited<ReturnType<BotFiles["open"]>>, parent: string | null, name: string, rename: boolean): Promise<string> {
    const taken = new Set((await this.list(ch.q, parent)).filter((e) => !e.locked).map((e) => e.name.toLowerCase()));
    if (!taken.has(name.toLowerCase())) return name;
    if (!rename) throw nameTaken(name);
    for (let n = 2; n <= 1000; n++) {
      const candidate = numbered(name, n);
      if (Array.from(candidate).length <= 255 && !taken.has(candidate.toLowerCase())) return candidate;
    }
    throw nameTaken(name);
  }

  /** Joins the channel's group before writing (creating it when the bot is the first writer). */
  private async writable(q: string): Promise<void> {
    if (!(await this.host.join(q, true))) throw new BotError("not_member", `The bot could not join the encryption group of ${q}`);
  }

  /** Creates a folder (needs `messages:write` and the channel's `attach_files`). */
  async createFolder(channel: ChannelRef, name: string, parent?: FolderRef): Promise<BotFileEntry> {
    const ch = await this.open(channel);
    const parentId = folderId(parent);
    let clean = checkedName(name);
    if (!ch.encrypted) return this.entry(ch, await ch.api.files.createFolder(ch.roomId, ch.id, clean, parentId), null);
    await this.writable(ch.q);
    clean = await this.freeName(ch, parentId, clean, false);
    const id = newUlid();
    const record: FileRecord = { entry: id, kind: "folder", name: clean, mime: "", size: 0, key: "" };
    const raw = await this.host.freshEpoch(ch.q, async () => {
      const sealed = await this.host.seal(ch.q, () => encryptFileRecord(this.host.mls(), ch.q, record));
      return ch.api.files.createFolderEncrypted(ch.roomId, ch.id, { id, ...sealed, parent_id: parentId });
    });
    return this.entry(ch, raw, record);
  }

  /**
   * Uploads a file (needs `messages:write`, the channel's `attach_files` and the upload category; the bot account's
   * upload size applies). Encrypted channels: chunked encryption with a fresh file key, the record under the current
   * epoch, the category declared from the name and type (PROTOCOL.md §7a).
   */
  async upload(channel: ChannelRef, file: BotFileUpload): Promise<BotFileEntry> {
    if ((file.data === undefined) === (file.path === undefined)) throw new TypeError("give either data or path");
    const raw = file.name ?? (file.path !== undefined ? basename(file.path) : "");
    const name = checkedName(raw);
    const ch = await this.open(channel);
    const parentId = folderId(file.folder);
    const given = file.mime?.trim();
    let blob: Blob = file.path !== undefined ? await openAsBlob(file.path) : file.data instanceof Blob ? file.data : new Blob([file.data as Uint8Array<ArrayBuffer>]);
    const mime = (given || blob.type || "application/octet-stream").toLowerCase();
    if (blob.type !== mime) blob = blob.slice(0, blob.size, mime);
    if (!ch.encrypted) return this.entry(ch, await ch.api.files.upload(ch.roomId, ch.id, blob, name, { parentId, rename: file.rename === true }), null);

    await this.writable(ch.q);
    const finalName = await this.freeName(ch, parentId, name, file.rename === true);
    const fileKey = newFileKey();
    try {
      const { blob: ciphertext, size } = await encryptFileStream(blob, { fileKey });
      const id = newUlid();
      const record: FileRecord = { entry: id, kind: "file", name: finalName, mime, size, key: fileKeyText(fileKey) };
      const category = uploadCategory(finalName, mime);
      const entry = await this.host.freshEpoch(ch.q, async () => {
        const sealed = await this.host.seal(ch.q, () => encryptFileRecord(this.host.mls(), ch.q, record));
        return ch.api.files.uploadEncrypted(ch.roomId, ch.id, ciphertext, { id, record: sealed.record, recordEpoch: sealed.record_epoch, category, parentId });
      });
      return this.entry(ch, entry, record);
    } finally {
      fileKey.fill(0);
    }
  }

  /**
   * Deletes an entry, a folder with everything inside (the bot's own entries; others' and folders holding them need
   * `manage_files`, i.e. `rooms:manage`). Locked entries can be deleted too.
   */
  async delete(entry: EntryRef): Promise<DeleteResult> {
    const { api } = this.host.target(entry.conversation);
    const roomId = "roomId" in entry ? entry.roomId : (await this.open(entry.conversation)).roomId;
    const channelId = "channelId" in entry ? entry.channelId : this.host.target(entry.conversation).id;
    return api.files.delete(roomId, channelId, entry.id);
  }
}
