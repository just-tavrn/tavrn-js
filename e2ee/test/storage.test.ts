// SPDX-License-Identifier: MPL-2.0
// The KeyStore contract for the in-memory and the file store, and what only the file store promises:
// encrypted at rest, mode 0600, atomic and serialized writes, one account per directory.
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MasterSecret } from "@tavrn/crypto";
import { b64urlEncode } from "@tavrn/sdk";
import { LocalKeyMismatchError, MemoryKeyStore, ensureCrypto, localStorageKey, readJsonSecret, withBackupKey, writeJsonSecret, type KeyStore } from "../src/index";
import { FileKeyStore, STATE_FILE, StateDirInUseError } from "../src/node";

const ALICE = "alice@t.local";
const BOB = "bob@t.local";
const DEV = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
const master = (fill = 7) => new Uint8Array(32).fill(fill);

const root = mkdtempSync(join(tmpdir(), "tavrn-e2ee-store-"));
let n = 0;
const freshDir = () => join(root, `s${++n}`);

beforeAll(() => ensureCrypto());
afterAll(() => rmSync(root, { recursive: true, force: true }));

const kinds: [string, () => { store: KeyStore; reopen: () => KeyStore }][] = [
  [
    "memory",
    () => {
      const store = new MemoryKeyStore();
      return { store, reopen: () => store };
    },
  ],
  [
    "file",
    () => {
      const dir = freshDir();
      return { store: new FileKeyStore(dir), reopen: () => new FileKeyStore(dir) };
    },
  ],
];

describe.each(kinds)("KeyStore contract (%s)", (_kind, make) => {
  it("starts empty, stores the master secret and named secrets, and locks", async () => {
    const { store } = make();
    expect(await store.status(ALICE)).toBe("none");
    expect(await store.deviceIdOf(ALICE)).toBeNull();
    expect(store.isUnlocked()).toBe(false);
    expect(() => store.masterSecret()).toThrow(/locked/);
    await expect(store.getSecret("x")).rejects.toThrow(/locked/);

    await store.saveMaster(ALICE, DEV, master());
    expect(store.isUnlocked(ALICE)).toBe(true);
    expect(store.isUnlocked(BOB)).toBe(false);
    expect(store.account()).toBe(ALICE);
    expect(store.deviceId()).toBe(DEV);
    expect(await store.status(ALICE)).toBe("unlocked");
    expect(await store.deviceIdOf(ALICE)).toBe(DEV);
    expect(store.masterSecret()).toEqual(master());

    await store.putSecret("mls-client", new Uint8Array([1, 2, 3]));
    expect(await store.getSecret("mls-client")).toEqual(new Uint8Array([1, 2, 3]));
    expect(await store.getSecret("missing")).toBeNull();
    await writeJsonSecret(store, "pins", { [BOB]: { key: "k" } });
    expect(await readJsonSecret(store, "pins", {})).toEqual({ [BOB]: { key: "k" } });
    await store.deleteSecret("mls-client");
    expect(await store.getSecret("mls-client")).toBeNull();

    store.lock();
    expect(await store.status(ALICE)).toBe("locked");
    expect(withBackupKey(store, () => 1)).toBeNull();
    await writeJsonSecret(store, "pins", {}); // no-op while locked
  });

  it("returned values are copies: zeroing them does not touch the stored data", async () => {
    const { store } = make();
    await store.saveMaster(ALICE, DEV, master());
    await store.putSecret("s", new Uint8Array([9, 9]));
    (await store.getSecret("s"))!.fill(0);
    store.masterSecret().fill(0);
    expect(await store.getSecret("s")).toEqual(new Uint8Array([9, 9]));
    expect(store.masterSecret()).toEqual(master());
  });

  it("unlocks with the right master secret only and keeps the secrets", async () => {
    const { store, reopen } = make();
    await store.saveMaster(ALICE, DEV, master());
    await store.putSecret("mls-client", new Uint8Array([4, 5]));
    store.lock();
    const again = reopen();
    await expect(again.unlockWithMaster(ALICE, master(8))).rejects.toBeInstanceOf(LocalKeyMismatchError);
    expect(again.isUnlocked()).toBe(false);
    await expect(again.unlockWithMaster(BOB, master())).rejects.toThrow(/no local data/);
    await again.unlockWithMaster(ALICE, master());
    expect(again.isUnlocked(ALICE)).toBe(true);
    expect(await again.getSecret("mls-client")).toEqual(new Uint8Array([4, 5]));
  });

  it("saveMaster replaces earlier data of the account; wipe deletes it", async () => {
    const { store } = make();
    await store.saveMaster(ALICE, DEV, master());
    await store.putSecret("old", new Uint8Array([1]));
    await store.saveMaster(ALICE, DEV, master(9));
    expect(await store.getSecret("old")).toBeNull();
    expect(store.masterSecret()).toEqual(master(9));
    await store.wipe(BOB); // someone else's: nothing happens
    expect(store.isUnlocked(ALICE)).toBe(true);
    await store.wipe(ALICE);
    expect(store.isUnlocked()).toBe(false);
    expect(await store.status(ALICE)).toBe("none");
  });

  it("derives the backup key from the master secret", async () => {
    const { store } = make();
    await store.saveMaster(ALICE, DEV, master());
    const ms = MasterSecret.fromBytes(master());
    expect(withBackupKey(store, (k) => b64urlEncode(k))).toBe(b64urlEncode(ms.backupKey()));
    ms.free();
  });
});

describe("FileKeyStore", () => {
  it("writes one encrypted state file with mode 0600 in a 0700 directory, without plaintext secrets", async () => {
    const dir = freshDir();
    const store = new FileKeyStore(dir);
    const secret = new TextEncoder().encode("very secret client state");
    await store.saveMaster(ALICE, DEV, master());
    await store.putSecret("mls-client", secret);
    expect(readdirSync(dir)).toEqual([STATE_FILE]); // no temporary files left behind
    if (process.platform !== "win32") {
      expect(statSync(join(dir, STATE_FILE)).mode & 0o777).toBe(0o600);
      expect(statSync(dir).mode & 0o777).toBe(0o700);
    }
    const raw = readFileSync(join(dir, STATE_FILE), "utf8");
    const header = JSON.parse(raw) as Record<string, unknown>;
    expect(Object.keys(header).sort()).toEqual(["account", "data", "device_id", "iv", "v"]);
    expect(header).toMatchObject({ v: 1, account: ALICE, device_id: DEV });
    for (const plain of [b64urlEncode(master()), b64urlEncode(secret), "very secret", "mls-client", Buffer.from(master()).toString("base64")]) expect(raw).not.toContain(plain);
    const key = await localStorageKey(master(), DEV);
    expect(raw).not.toContain(b64urlEncode(key));
  });

  it("never resumes without the master secret (no key on disk)", async () => {
    const dir = freshDir();
    await new FileKeyStore(dir).saveMaster(ALICE, DEV, master());
    const again = new FileKeyStore(dir);
    expect(await again.status(ALICE)).toBe("locked");
    expect(await again.resume(ALICE)).toBe(false);
    expect(await again.deviceIdOf(ALICE)).toBe(DEV);
  });

  it("refuses a tampered state file and a file of another device id", async () => {
    const dir = freshDir();
    const store = new FileKeyStore(dir);
    await store.saveMaster(ALICE, DEV, master());
    await store.putSecret("x", new Uint8Array([1]));
    const file = join(dir, STATE_FILE);
    const header = JSON.parse(readFileSync(file, "utf8")) as { data: string; device_id: string };
    const flipped = header.data.slice(0, 10) + (header.data[10] === "A" ? "B" : "A") + header.data.slice(11);
    writeFileSync(file, JSON.stringify({ ...header, data: flipped }));
    await expect(new FileKeyStore(dir).unlockWithMaster(ALICE, master())).rejects.toBeInstanceOf(LocalKeyMismatchError);
    // Another device id derives another local key.
    writeFileSync(file, JSON.stringify({ ...header, device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1" }));
    await expect(new FileKeyStore(dir).unlockWithMaster(ALICE, master())).rejects.toBeInstanceOf(LocalKeyMismatchError);
    // Another account in the header changes the additional data.
    writeFileSync(file, JSON.stringify({ ...header, account: BOB }));
    await expect(new FileKeyStore(dir).unlockWithMaster(BOB, master())).rejects.toBeInstanceOf(LocalKeyMismatchError);
  });

  it("refuses a malformed state file instead of overwriting it", async () => {
    const dir = freshDir();
    await new FileKeyStore(dir).saveMaster(ALICE, DEV, master());
    writeFileSync(join(dir, STATE_FILE), "{not json");
    const store = new FileKeyStore(dir);
    await expect(store.status(ALICE)).rejects.toThrow(/unreadable state file/);
    await expect(store.saveMaster(ALICE, DEV, master())).rejects.toThrow(/unreadable state file/);
    expect(readFileSync(join(dir, STATE_FILE), "utf8")).toBe("{not json");
  });

  it("holds one account per directory", async () => {
    const dir = freshDir();
    await new FileKeyStore(dir).saveMaster(ALICE, DEV, master());
    const store = new FileKeyStore(dir);
    expect(await store.status(BOB)).toBe("none");
    await expect(store.saveMaster(BOB, DEV, master())).rejects.toBeInstanceOf(StateDirInUseError);
    expect(await store.status(ALICE)).toBe("locked");
  });

  it("serializes concurrent writes: the file ends with every change", async () => {
    const dir = freshDir();
    const store = new FileKeyStore(dir);
    await store.saveMaster(ALICE, DEV, master());
    await Promise.all(Array.from({ length: 25 }, (_, i) => store.putSecret(`k${i}`, new Uint8Array([i]))));
    await store.deleteSecret("k3");
    const again = new FileKeyStore(dir);
    await again.unlockWithMaster(ALICE, master());
    for (let i = 0; i < 25; i++) expect(await again.getSecret(`k${i}`)).toEqual(i === 3 ? null : new Uint8Array([i]));
    expect(readdirSync(dir)).toEqual([STATE_FILE]);
  });

  it("coalesces a burst of changes into few file writes, each caller resolved once its change is on disk", async () => {
    const dir = freshDir();
    const store = new FileKeyStore(dir);
    await store.saveMaster(ALICE, DEV, master());
    const files = () => (store as unknown as { filesWritten: number }).filesWritten;
    const before = files();
    await Promise.all(Array.from({ length: 25 }, (_, i) => store.putSecret(`k${i}`, new Uint8Array([i]))));
    // The first change starts a write, the other 24 share the next one (was: 25 rewrites with 50 fsyncs).
    expect(files() - before).toBeLessThanOrEqual(2);
    const again = new FileKeyStore(dir);
    await again.unlockWithMaster(ALICE, master());
    for (let i = 0; i < 25; i++) expect(await again.getSecret(`k${i}`)).toEqual(new Uint8Array([i]));
  });

  it("close() waits for pending writes and locks", async () => {
    const dir = freshDir();
    const store = new FileKeyStore(dir);
    await store.saveMaster(ALICE, DEV, master());
    void store.putSecret("late", new Uint8Array([7]));
    await store.close();
    expect(store.isUnlocked()).toBe(false);
    const again = new FileKeyStore(dir);
    await again.unlockWithMaster(ALICE, master());
    expect(await again.getSecret("late")).toEqual(new Uint8Array([7]));
  });
});
