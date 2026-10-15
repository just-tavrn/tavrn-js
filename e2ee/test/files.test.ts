// SPDX-License-Identifier: MPL-2.0
// End-to-end encrypted files channels (FILES.md §8): the chunked file encryption against the protocol's test
// vectors, streaming in both directions, ranges, size arithmetic, the entry record checks of the vectors and a
// record round trip through real session managers.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { Client, MasterSecret } from "@tavrn/crypto";
import { MlsManager, qualify } from "../src/mls";
import { epochKeyOpens, pickSample } from "../src/history";
import {
  FILE_CHUNK,
  FileDecryptError,
  chunkAad,
  chunkNonce,
  ciphertextRange,
  decryptFileBytes,
  decryptFileChunks,
  decryptFileRecord,
  encryptFileBytes,
  encryptFileRecord,
  encryptFileStream,
  encryptedSize,
  entryName,
  filePartKey,
  parseFileRecord,
  plaintextSize,
  recordSamples,
  validEntryName,
  type FilePart,
} from "../src/files";
import { Network, domainOf } from "./fake-node";

/** A session manager of `user` on t.local in the network (as in mls.test.ts). */
function device(net: Network, user: string, deviceId: string): MlsManager {
  const address = `${user}@t.local`;
  const home = net.node(domainOf(address));
  const master = MasterSecret.generate();
  home.addUser(user, master);
  const record = home.users.get(user)!;
  const client = Client.create(address, deviceId);
  record.devices.set(deviceId, { pk: b64urlEncode(client.devicePublicKey), sig: b64urlEncode(master.attestDevice(address, deviceId, client.devicePublicKey)) });
  record.kps.set(deviceId, [b64urlEncode(client.createKeyPackage()), b64urlEncode(client.createKeyPackage())]);
  return new MlsManager({
    api: net.api(address, deviceId),
    client,
    address,
    deviceId,
    homeDomain: "t.local",
    persist: async () => undefined,
    backupKey: () => master.backupKey(),
    ownIdentityKey: () => b64urlEncode(master.identityPublicKey()),
    pins: {},
    savePins: async () => undefined,
    meta: { convs: {} },
    saveMeta: async () => undefined,
    backupDelayMs: 60_000,
  });
}

beforeAll(() => ensureCrypto());

const vectors = JSON.parse(readFileSync(new URL("../../protocol/testvectors/encryption.json", import.meta.url), "utf8"));
const v = vectors.file_chunks;
const rv = vectors.file_record;
const key = b64urlDecode(v.key);

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** A stream of `bytes` in pieces of `size` (network chunking unrelated to the 1 MiB chunks). */
function pieces(bytes: Uint8Array, size: number): ReadableStream<Uint8Array> {
  let at = 0;
  return new ReadableStream({
    pull(c) {
      if (at >= bytes.length) return c.close();
      c.enqueue(bytes.slice(at, at + size));
      at += size;
    },
  });
}

/** Byte equality without the deep-equality machinery (megabytes). */
const same = (a: Uint8Array, b: Uint8Array) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

const big = () => Uint8Array.from({ length: v.cases[3].plaintext_size }, (_, i) => i % 251);

describe("chunked file encryption (test vectors)", () => {
  it("derives the published part keys, nonces and AADs", async () => {
    for (const part of ["content", "thumbnail"] as FilePart[]) {
      const k = await filePartKey(key, part);
      expect(b64urlEncode(new Uint8Array(await crypto.subtle.exportKey("raw", k)))).toBe(v.part_keys[part]);
    }
    expect(b64urlEncode(chunkNonce(1))).toBe(v.nonce_1);
    expect(b64urlEncode(chunkAad(true))).toBe(v.aad_last);
    expect(b64urlEncode(chunkAad(false))).toBe(v.aad_not_last);
  });

  it("encrypts and decrypts the small cases byte for byte", async () => {
    for (const c of v.cases.slice(0, 3)) {
      const plain = b64urlDecode(c.plaintext);
      const ct = await encryptFileBytes(key, c.part, plain);
      expect(b64urlEncode(ct), c.name).toBe(c.ciphertext);
      expect(await decryptFileBytes(key, c.part, ct)).toEqual(plain);
      // The other part's key does not open it.
      await expect(decryptFileBytes(key, c.part === "content" ? "thumbnail" : "content", ct)).rejects.toBeInstanceOf(FileDecryptError);
    }
  });

  it("matches the three-chunk vector when streaming in both directions", async () => {
    const c = v.cases[3];
    const plain = big();
    const { blob, size } = await encryptFileStream(new Blob([plain]), { fileKey: key });
    expect(size).toBe(c.plaintext_size);
    const ct = new Uint8Array(await blob.arrayBuffer());
    expect(ct.length).toBe(c.ciphertext_size);
    expect(createHash("sha256").update(ct).digest("base64url")).toBe(c.ciphertext_sha256);
    const end = (i: number) => Math.min((i + 1) * (FILE_CHUNK + 16), ct.length);
    expect([0, 1, 2].map((i) => b64urlEncode(ct.subarray(end(i) - 16, end(i))))).toEqual(c.tags);
    expect(b64urlEncode(ct.subarray(2 * (FILE_CHUNK + 16)))).toBe(c.last_chunk);
    for (const piece of [1000, 65536, 3_000_000]) {
      const out = await readAll(pieces(ct, piece).pipeThrough(decryptFileChunks(key, "content", ct.length)));
      expect(out.length).toBe(plain.length);
      expect(same(out, plain)).toBe(true);
    }
  });

  it("refuses truncation, reordering and trailing bytes", async () => {
    const ct = await encryptFileBytes(key, "content", big());
    const first = ct.subarray(0, FILE_CHUNK + 16);
    // The first chunk alone: "not last" in its AAD, so it is not a complete file.
    await expect(decryptFileBytes(key, "content", first)).rejects.toBeInstanceOf(FileDecryptError);
    await expect(readAll(pieces(ct.subarray(0, 2 * (FILE_CHUNK + 16)), 70000).pipeThrough(decryptFileChunks(key, "content", ct.length)))).rejects.toBeInstanceOf(FileDecryptError);
    const swapped = new Uint8Array(ct);
    swapped.set(ct.subarray(FILE_CHUNK + 16, 2 * (FILE_CHUNK + 16)), 0);
    swapped.set(first, FILE_CHUNK + 16);
    await expect(decryptFileBytes(key, "content", swapped)).rejects.toBeInstanceOf(FileDecryptError);
    await expect(decryptFileBytes(key, "content", new Uint8Array([...ct, 0]))).rejects.toBeInstanceOf(FileDecryptError);
  });

  it("refuses a stream that goes on after the last chunk at once, without buffering it", async () => {
    const ct = await encryptFileBytes(key, "content", new Uint8Array(100));
    let pulled = 0;
    // 64 MiB after the file (1024 pulls of 64 KiB); the decryption must stop at the first of them.
    const endless = new ReadableStream<Uint8Array>({
      pull(c) {
        pulled += 1;
        if (pulled > 1025) c.close();
        else c.enqueue(pulled === 1 ? ct : new Uint8Array(64 * 1024));
      },
    });
    await expect(readAll(endless.pipeThrough(decryptFileChunks(key, "content", ct.length)))).rejects.toBeInstanceOf(FileDecryptError);
    expect(pulled).toBeLessThan(10);
  });

  it("computes sizes and ciphertext ranges", async () => {
    expect([0, 1, FILE_CHUNK, FILE_CHUNK + 1].map(encryptedSize)).toEqual([16, 17, FILE_CHUNK + 16, FILE_CHUNK + 33]);
    for (const n of [0, 1, 23, FILE_CHUNK - 1, FILE_CHUNK, FILE_CHUNK + 1, 2 * FILE_CHUNK, 5 * FILE_CHUNK + 7]) expect(plaintextSize(encryptedSize(n))).toBe(n);
    for (const bad of [-1, 0, 15, FILE_CHUNK + 16 + 16, 1.5]) expect(plaintextSize(bad)).toBeNull();
    const plain = big();
    const ct = await encryptFileBytes(key, "content", plain);
    const r = ciphertextRange(FILE_CHUNK + 5, FILE_CHUNK + 10, ct.length)!;
    expect(r).toEqual({ start: FILE_CHUNK + 16, end: 2 * (FILE_CHUNK + 16) - 1, firstChunk: 1, lastChunk: 1, skip: 5 });
    const out = await readAll(pieces(ct.slice(r.start, r.end + 1), 9999).pipeThrough(decryptFileChunks(key, "content", ct.length, r.firstChunk, r.lastChunk)));
    expect(out.subarray(r.skip, r.skip + 6)).toEqual(plain.subarray(FILE_CHUNK + 5, FILE_CHUNK + 11));
    const tail = ciphertextRange(2 * FILE_CHUNK, 10 ** 9, ct.length)!;
    expect(tail.end).toBe(ct.length - 1);
    expect(ciphertextRange(plain.length, plain.length + 1, ct.length)).toBeNull();
  });
});

describe("entry records", () => {
  it("accepts the valid records of the vectors and refuses every invalid one", () => {
    expect(parseFileRecord(rv.valid, rv.entry)).toMatchObject({ kind: "file", name: "Quarterly report.pdf", mime: "application/pdf", size: 23, thumbnail: { mime: "image/webp", width: 320, height: 180 } });
    expect(parseFileRecord(rv.folder, rv.folder_entry)).toMatchObject({ kind: "folder", name: "Reports" });
    for (const c of rv.invalid) expect(parseFileRecord(c.record, rv.entry), c.name).toBeNull();
  });

  it("checks names like the node did for unencrypted channels", () => {
    expect(entryName("  Bericht.pdf ")).toBe("Bericht.pdf");
    expect(entryName("Café")).toBe("Café");
    for (const bad of ["", " ", "a/b", "a\\b", ".", "..", "x\u0000y", "invoice‮txt.exe", "a".repeat(256)]) expect(entryName(bad), bad).toBeNull();
    expect(validEntryName(" padded")).toBe(false);
  });

  it("round-trips a record through two members' session managers and binds it to its entry", async () => {
    const net = new Network();
    const alice = { mls: device(net, "alice", "01J9ZK3G5M8Q2W4E6R8T0Y2VA1") };
    const bob = { mls: device(net, "bob", "01J9ZK3G5M8Q2W4E6R8T0Y2VB1") };
    const q = qualify("t.local", "01J9ZK3G5M8Q2W4E6R8T0Y2V00");
    expect(await alice.mls.ensureJoined(q, { canCreate: true })).toBe("joined");
    expect(await bob.mls.ensureJoined(q, { canCreate: false })).toBe("joined");
    await alice.mls.catchUp(q);
    const entry = { id: "01J9ZK3G5M8Q2W4E6R8T0Y2VF1", kind: "file", size: encryptedSize(23) };
    const fileKey = b64urlEncode(key);
    const enc = await encryptFileRecord(alice.mls, q, { entry: entry.id, kind: "file", name: "Plan.pdf", mime: "application/pdf", size: 23, key: fileKey });
    const listed = { ...entry, ...enc, record_author: "alice@t.local", record_device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1", record_at: new Date().toISOString() };
    const got = await decryptFileRecord(bob.mls, q, listed);
    expect(got).toEqual({ ok: true, record: { entry: entry.id, kind: "file", name: "Plan.pdf", mime: "application/pdf", size: 23, key: fileKey } });
    // The node moves the record to another entry: refused.
    expect(await decryptFileRecord(bob.mls, q, { ...listed, id: "01J9ZK3G5M8Q2W4E6R8T0Y2VF2" })).toMatchObject({ ok: false });
    // No record served (history window).
    expect(await decryptFileRecord(bob.mls, q, { ...entry, record: null })).toEqual({ ok: false, reason: "withheld" });
    // The record proves the epoch's key in a history share check like a message would.
    const samples = recordSamples([listed, { ...entry, record: null }]);
    expect(samples).toHaveLength(1);
    const sample = pickSample(samples, enc.record_epoch, "carol@t.local")!;
    const [[, epochKey]] = alice.mls.exportEpochKeys(q, [enc.record_epoch]) as [[number, Uint8Array]];
    expect(await epochKeyOpens(epochKey, q, sample)).toBe(true);
    // A wrong author is a bad signature or an unknown device, never content.
    expect(await decryptFileRecord(bob.mls, q, { ...listed, id: "01J9ZK3G5M8Q2W4E6R8T0Y2VF3", record_author: "bob@t.local", record_device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2VB1" })).toMatchObject({ ok: false });
  });
});

