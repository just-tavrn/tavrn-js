// SPDX-License-Identifier: Apache-2.0
import { mkdtemp, readFile, rm, stat, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MasterSecret, RecoveryKey } from "@tavrn/crypto";
import { ensureCrypto } from "@tavrn/e2ee";
import { createKeyFile, parseKey, readKey } from "../src/keyfile";
import { silentLogger, type BotLogger } from "../src/logger";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "tavrn-bot-key-"));
});
afterEach(() => rm(dir, { recursive: true, force: true }));

describe("bot key file (APPLICATIONS.md §3.1, ENCRYPTION.md §2.2)", () => {
  it("creates the key file with mode 0600, never overwrites it, and reads it back", async () => {
    const path = join(dir, "keys", "tavrn-key-weatherbot.txt");
    const secret = await createKeyFile(path, "weatherbot@h.test");
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    const text = await readFile(path, "utf8");
    expect(text).toContain("Account: weatherbot@h.test");
    expect(text).toMatch(/^key: /m);
    expect(await readKey({ path, logger: silentLogger })).toEqual(secret);
    await expect(createKeyFile(path, "weatherbot@h.test")).rejects.toMatchObject({ code: "EEXIST" });
    expect(await readFile(path, "utf8")).toBe(text);
  });

  it("prefers the key option (whole file or the key: value) and returns null without any key", async () => {
    await ensureCrypto();
    const m = MasterSecret.generate();
    const file = m.toKeyFile("bot@h.test");
    const bytes = m.toBytes();
    m.free();
    const keyLine = file.split("\n").find((l) => l.startsWith("key:"))!;
    expect(await readKey({ key: keyLine.slice(4).trim(), path: join(dir, "missing.txt"), logger: silentLogger })).toEqual(bytes);
    expect(await readKey({ key: file, path: join(dir, "missing.txt"), logger: silentLogger })).toEqual(bytes);
    expect(await readKey({ path: join(dir, "missing.txt"), logger: silentLogger })).toBeNull();
  });

  it("refuses malformed keys, recovery keys and oversized files; warns about loose permissions", async () => {
    await expect(parseKey("key: AAAA")).rejects.toMatchObject({ code: "key_invalid" });
    await expect(parseKey("x".repeat(5000))).rejects.toMatchObject({ code: "key_invalid" });
    await ensureCrypto();
    const recovery = RecoveryKey.generate();
    await expect(parseKey(recovery.toCompact())).rejects.toMatchObject({ code: "key_invalid" });
    recovery.free();
    const big = join(dir, "big.txt");
    await writeFile(big, "#".repeat(5000));
    await expect(readKey({ path: big, logger: silentLogger })).rejects.toMatchObject({ code: "key_invalid" });
    const loose = join(dir, "loose.txt");
    await createKeyFile(loose, "bot@h.test");
    await chmod(loose, 0o644);
    const warnings: string[] = [];
    const logger: BotLogger = { ...silentLogger, warn: (m) => warnings.push(m) };
    await readKey({ path: loose, logger });
    expect(warnings.join()).toMatch(/readable by other users/);
  });
});
