// SPDX-License-Identifier: Apache-2.0
/**
 * The bot key file (APPLICATIONS.md §3.1, ENCRYPTION.md §2.2): the bot's master secret as `tavrn-key-<username>.txt`
 * (a `key:` line with version `0x01` and a checksum, plus the 24 words). It is the only backup of the bot's identity:
 * bots have no recovery key and no secret storage. The runtime reads it from the `key` option (`TAVRN_BOT_KEY`, the
 * compact `key:` value or the whole file) or from the file at `keyFile` (`TAVRN_BOT_KEY_FILE`), and creates the file
 * on the first start (mode 0600, never overwriting an existing file).
 */
import { mkdir, open, readFile, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { MasterSecret } from "@tavrn/crypto";
import { ensureCrypto } from "@tavrn/e2ee";
import { BotError } from "./errors";
import type { BotLogger } from "./logger";

/** Largest key file accepted (ENCRYPTION.md §2.2 parsing rules). */
const MAX_KEY_TEXT = 4096;

/** The default key file of a bot: `./tavrn-key-<username>.txt` in the working directory. */
export function defaultKeyFile(username: string): string {
  return resolve(`tavrn-key-${username}.txt`);
}

/** Parses a key file text, its `key:` value or its word list into the 32 raw bytes of the master secret. */
export async function parseKey(text: string): Promise<Uint8Array> {
  await ensureCrypto();
  if (text.length > MAX_KEY_TEXT) throw new BotError("key_invalid", "The key is longer than a key file can be");
  let master: MasterSecret;
  try {
    master = MasterSecret.fromKeyFile(text);
  } catch (e) {
    const reason = e instanceof Error && e.name ? e.name : "malformed";
    throw new BotError("key_invalid", `The bot key cannot be read (${reason}); it must be the bot's key file or its key: line`, { cause: e });
  }
  try {
    return master.toBytes();
  } finally {
    master.free();
  }
}

/**
 * The configured master secret: the `key` text if given, else the key file at `path`; null when neither exists.
 * Warns when the key file is readable by other users.
 */
export async function readKey(opts: { key?: string | null; path: string; logger: BotLogger }): Promise<Uint8Array | null> {
  if (opts.key && opts.key.trim()) return parseKey(opts.key.trim());
  let text: string;
  try {
    const info = await stat(opts.path);
    if (!info.isFile()) throw new BotError("key_invalid", `The key file path ${opts.path} is not a file`);
    if (info.size > MAX_KEY_TEXT) throw new BotError("key_invalid", `The key file ${opts.path} is too large to be a key file`);
    if (process.platform !== "win32" && (info.mode & 0o077) !== 0) {
      opts.logger.warn("the bot key file is readable by other users; restrict it with chmod 600", { path: opts.path });
    }
    text = await readFile(opts.path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
  return parseKey(text);
}

/**
 * Creates a new master secret and writes its key file for `account` at `path` (mode 0600, the file must not exist:
 * an existing file is never replaced). Returns the raw secret; the caller zeroes it after use.
 */
export async function createKeyFile(path: string, account: string): Promise<Uint8Array> {
  await ensureCrypto();
  const master = MasterSecret.generate();
  try {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const text = master.toKeyFile(account);
    // "wx": fail if the file exists (never overwrite a key), 0600 before any byte is written.
    const fh = await open(path, "wx", 0o600);
    try {
      await fh.writeFile(text, "utf8");
      await fh.sync();
    } finally {
      await fh.close();
    }
    return master.toBytes();
  } finally {
    master.free();
  }
}

/** The identity public key (base64url-free raw bytes) derived from a master secret. */
export async function identityKeyOf(master: Uint8Array): Promise<Uint8Array> {
  await ensureCrypto();
  const m = MasterSecret.fromBytes(master);
  try {
    return m.identityPublicKey();
  } finally {
    m.free();
  }
}
