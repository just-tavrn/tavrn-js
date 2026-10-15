// SPDX-License-Identifier: MPL-2.0
/**
 * File-based {@link KeyStore} for Node.js (bots, APPLICATIONS.md §3.3): one state directory per account
 * and device holding a single encrypted state file, `state.json`:
 *
 * ```json
 * { "v": 1, "account": "bot@node.example", "device_id": "01J…", "iv": "<base64url>", "data": "<base64url>" }
 * ```
 *
 * `data` is AES-256-GCM (16-byte tag appended) over the JSON `{ "master": …, "secrets": { name: … } }`
 * (values base64url) with additional data `"tavrn local v1" 0x00 account 0x00 "state"`, under the
 * device's local storage key `MasterSecret.localStorageKey(device_id)` (ENCRYPTION.md §2.1). The key is
 * never stored: the process unlocks the store with the master secret (from the bot key file) on every
 * start, so the state directory alone is useless to a thief.
 *
 * Every change rewrites the file atomically (temporary file with mode 0600, fsync, rename, directory
 * fsync); writes are serialized. The directory is created with mode 0700. One process per directory:
 * two processes sharing it would overwrite each other's MLS state.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { join } from "node:path";
import { b64urlDecode } from "@tavrn/sdk";
import { LocalKeyMismatchError, localAad, localStorageKey, type CryptoStatus, type KeyStore } from "../keystore";

/** Name of the state file inside the directory. */
export const STATE_FILE = "state.json";
const ENTRY = "state";
const TAG = 16;

interface Header {
  v: 1;
  account: string;
  device_id: string;
  iv: string;
  data: string;
}

interface Open {
  account: string;
  deviceId: string;
  key: Buffer;
  master: Uint8Array;
  secrets: Map<string, Uint8Array>;
}

/** Thrown when the state directory holds the data of another account. */
export class StateDirInUseError extends Error {
  constructor() {
    super("The state directory belongs to another account");
    this.name = "state_dir_in_use";
  }
}

function isHeader(v: unknown): v is Header {
  if (!v || typeof v !== "object") return false;
  const h = v as Record<string, unknown>;
  return h.v === 1 && typeof h.account === "string" && typeof h.device_id === "string" && typeof h.iv === "string" && typeof h.data === "string";
}

export class FileKeyStore implements KeyStore {
  private current: Open | null = null;
  private writing: Promise<void> = Promise.resolve();
  private readonly file: string;

  constructor(readonly dir: string) {
    this.file = join(dir, STATE_FILE);
  }

  /** The header of the state file, or null if there is none. Malformed files are an error (never overwritten silently). */
  private async header(): Promise<Header | null> {
    await this.writing;
    let text: string;
    try {
      text = await readFile(this.file, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
    if (!isHeader(parsed)) throw new Error(`unreadable state file ${this.file}`);
    return parsed;
  }

  async status(account: string): Promise<CryptoStatus> {
    if (this.current?.account === account) return "unlocked";
    return (await this.header())?.account === account ? "locked" : "none";
  }

  async deviceIdOf(account: string): Promise<string | null> {
    const h = await this.header();
    return h?.account === account ? h.device_id : null;
  }

  /** There is no persisted key: the store opens only with the master secret ({@link unlockWithMaster}). */
  async resume(account: string): Promise<boolean> {
    return this.isUnlocked(account);
  }

  async saveMaster(account: string, deviceId: string, master: Uint8Array): Promise<void> {
    const h = await this.header();
    if (h && h.account !== account) throw new StateDirInUseError();
    const raw = await localStorageKey(master, deviceId);
    const key = Buffer.from(raw);
    raw.fill(0);
    this.setCurrent({ account, deviceId, key, master: master.slice(), secrets: new Map() });
    await this.flush();
  }

  async unlockWithMaster(account: string, master: Uint8Array): Promise<void> {
    const h = await this.header();
    if (!h || h.account !== account) throw new Error("no local data for this account");
    const raw = await localStorageKey(master, h.device_id);
    const key = Buffer.from(raw);
    raw.fill(0);
    let plain: Buffer;
    try {
      const sealed = b64urlDecode(h.data);
      if (sealed.length < TAG) throw new Error("short");
      const d = createDecipheriv("aes-256-gcm", key, b64urlDecode(h.iv));
      d.setAAD(localAad(account, ENTRY));
      d.setAuthTag(sealed.subarray(sealed.length - TAG));
      plain = Buffer.concat([d.update(sealed.subarray(0, sealed.length - TAG)), d.final()]);
    } catch {
      key.fill(0);
      throw new LocalKeyMismatchError();
    }
    try {
      const body = JSON.parse(plain.toString("utf8")) as { master?: unknown; secrets?: unknown };
      if (typeof body.master !== "string" || !body.secrets || typeof body.secrets !== "object") throw new Error(`unreadable state file ${this.file}`);
      const secrets = new Map<string, Uint8Array>();
      for (const [name, value] of Object.entries(body.secrets as Record<string, unknown>)) if (typeof value === "string") secrets.set(name, b64urlDecode(value));
      this.setCurrent({ account, deviceId: h.device_id, key, master: master.slice(), secrets });
    } finally {
      plain.fill(0);
    }
  }

  isUnlocked(account?: string): boolean {
    return !!this.current && (account === undefined || this.current.account === account);
  }

  lock(): void {
    this.setCurrent(null);
  }

  /** Waits for every queued write, then locks (process shutdown). */
  async close(): Promise<void> {
    await this.writing;
    this.lock();
  }

  async wipe(account: string): Promise<void> {
    if (this.current?.account === account) this.lock();
    const h = await this.header();
    if (h?.account !== account) return;
    await unlink(this.file).catch((e: NodeJS.ErrnoException) => {
      if (e.code !== "ENOENT") throw e;
    });
  }

  account(): string | null {
    return this.current?.account ?? null;
  }

  private require(): Open {
    if (!this.current) throw new Error("crypto store is locked");
    return this.current;
  }

  deviceId(): string {
    return this.require().deviceId;
  }

  masterSecret(): Uint8Array {
    return this.require().master.slice();
  }

  async putSecret(name: string, value: Uint8Array): Promise<void> {
    const cur = this.require();
    cur.secrets.get(name)?.fill(0);
    cur.secrets.set(name, value.slice());
    await this.flush();
  }

  async getSecret(name: string): Promise<Uint8Array | null> {
    return this.require().secrets.get(name)?.slice() ?? null;
  }

  async deleteSecret(name: string): Promise<void> {
    const cur = this.require();
    cur.secrets.get(name)?.fill(0);
    cur.secrets.delete(name);
    await this.flush();
  }

  private setCurrent(next: Open | null) {
    const prev = this.current;
    if (prev && prev !== next) {
      prev.key.fill(0);
      prev.master.fill(0);
      for (const v of prev.secrets.values()) v.fill(0);
    }
    this.current = next;
  }

  /**
   * Seals the open state now and queues the atomic write (writes happen in call order). While a write runs, the
   * changes that arrive are coalesced: the queued write takes the newest sealed state, and every caller waiting for it
   * resolves when the file holds its change (one file rewrite with two fsyncs per burst, not per secret).
   */
  private flush(): Promise<void> {
    const cur = this.require();
    const b64 = (v: Uint8Array) => Buffer.from(v.buffer, v.byteOffset, v.byteLength).toString("base64url");
    const body = JSON.stringify({ master: b64(cur.master), secrets: Object.fromEntries([...cur.secrets].map(([k, v]) => [k, b64(v)])) });
    const plain = Buffer.from(body, "utf8");
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", cur.key, iv);
    c.setAAD(localAad(cur.account, ENTRY));
    const sealed = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
    plain.fill(0);
    const header: Header = { v: 1, account: cur.account, device_id: cur.deviceId, iv: b64(iv), data: b64(sealed) };
    const content = `${JSON.stringify(header)}\n`;
    if (this.queued) {
      this.queued.content = content;
      return this.queued.done;
    }
    const slot: { content: string; done: Promise<void> } = { content, done: Promise.resolve() };
    slot.done = this.writing.then(() => {
      if (this.queued === slot) this.queued = null;
      return this.writeAtomic(slot.content);
    });
    this.queued = slot;
    this.writing = slot.done.catch(() => undefined);
    return slot.done;
  }

  /** The write that has not started yet (it takes the state of every later change until it starts). */
  private queued: { content: string; done: Promise<void> } | null = null;
  /** Atomic file writes so far (the tests check that bursts are coalesced). */
  private filesWritten = 0;

  private async writeAtomic(content: string): Promise<void> {
    this.filesWritten++;
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    const tmp = join(this.dir, `.${STATE_FILE}.${randomBytes(8).toString("hex")}.tmp`);
    // "wx": never follow or reuse an existing file; 0600 before any byte is written.
    const fh = await open(tmp, "wx", 0o600);
    try {
      await fh.writeFile(content, "utf8");
      await fh.sync();
    } finally {
      await fh.close();
    }
    try {
      await rename(tmp, this.file);
    } catch (e) {
      await unlink(tmp).catch(() => undefined);
      throw e;
    }
    // Make the rename durable (best effort: not every platform can open or sync a directory).
    const dir = await open(this.dir, "r").catch(() => null);
    if (dir) {
      await dir.sync().catch(() => undefined);
      await dir.close();
    }
  }
}
