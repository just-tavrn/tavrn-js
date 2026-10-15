// SPDX-License-Identifier: MPL-2.0
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { decryptFile, encryptFile, initSync as wasm } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { AttachmentIntegrityError, contentAttachments, decryptAttachment, encryptAttachment, encryptAttachmentBytes, safeFileName, verifyPlainAttachment } from "../src/content";

beforeAll(() => ensureCrypto());

const ID = "01J9ZK3G5M8Q2W4E6R8T0Y2V00";

describe("plaintext attachments", () => {
  it("accepts the bytes the signed sha256 names and refuses others", async () => {
    const bytes = new TextEncoder().encode("Rechnung.pdf");
    const sha256 = b64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
    await expect(verifyPlainAttachment(bytes, sha256)).resolves.toBeUndefined();
    const swapped = new TextEncoder().encode("Rechnung.pdg");
    await expect(verifyPlainAttachment(swapped, sha256)).rejects.toBeInstanceOf(AttachmentIntegrityError);
  });
});

describe("encrypted attachments", () => {
  it("round-trips a file and refuses a modified ciphertext before decrypting", async () => {
    const file = new File([new TextEncoder().encode("geheimes Bild")], "../bild.png", { type: "image/png" });
    const { blob, meta } = await encryptAttachment(file);
    expect(meta).toMatchObject({ name: "_bild.png", mime: "image/png", size: 13 });
    const cipher = new Uint8Array(await blob.arrayBuffer());
    expect(new TextDecoder().decode(cipher)).not.toContain("geheimes");
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", cipher));
    expect(b64urlEncode(digest)).toBe(meta.sha256);
    expect(new TextDecoder().decode(await decryptAttachment(cipher, meta))).toBe("geheimes Bild");
    const tampered = cipher.slice();
    tampered[0]! ^= 1;
    await expect(decryptAttachment(tampered, meta)).rejects.toBeInstanceOf(AttachmentIntegrityError);
    const otherKey = { ...meta, key: b64urlEncode(new Uint8Array(32)) };
    await expect(decryptAttachment(cipher, otherKey)).rejects.toMatchObject({ name: "decryption_failed" });
  });

  it("encrypts exactly like the crypto core (the file vector) and reads what the core encrypted", async () => {
    const v = JSON.parse(readFileSync(new URL("../../protocol/testvectors/encryption.json", import.meta.url), "utf8")).file as Record<string, string>;
    const { ciphertext, sha256 } = await encryptAttachmentBytes(b64urlDecode(v.plaintext!), b64urlDecode(v.key!), b64urlDecode(v.nonce!));
    expect(b64urlEncode(ciphertext)).toBe(v.ciphertext);
    expect(b64urlEncode(sha256)).toBe(v.sha256);
    expect(b64urlEncode(await decryptAttachment(b64urlDecode(v.ciphertext!), { key: v.key!, nonce: v.nonce!, sha256: v.sha256! }))).toBe(v.plaintext);
    // Both ways against the WebAssembly implementation, with a random key.
    const plain = crypto.getRandomValues(new Uint8Array(60_000));
    const f = encryptFile(plain);
    try {
      expect(await decryptAttachment(f.ciphertext, { key: b64urlEncode(f.key), nonce: b64urlEncode(f.nonce), sha256: b64urlEncode(f.sha256) })).toEqual(plain);
    } finally {
      f.free();
    }
    const key = crypto.getRandomValues(new Uint8Array(32));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ours = await encryptAttachmentBytes(plain, key, nonce);
    expect(decryptFile(ours.ciphertext, key, nonce, ours.sha256)).toEqual(plain);
    await expect(encryptAttachmentBytes(plain, key.subarray(1), nonce)).rejects.toMatchObject({ name: "invalid_input" });
  });

  it("does not grow the WebAssembly memory for attachments", async () => {
    // initSync returns the instance's exports once the module is initialized.
    const memory = () => (wasm as unknown as () => { memory: WebAssembly.Memory })().memory.buffer.byteLength;
    const before = memory();
    const { blob, meta } = await encryptAttachment(new File([new Uint8Array(8 << 20)], "big.bin"));
    expect(await decryptAttachment(new Uint8Array(await blob.arrayBuffer()), meta)).toHaveLength(8 << 20);
    expect(memory()).toBe(before);
  });

  it("accepts only content attachments that match the envelope", () => {
    const key = b64urlEncode(new Uint8Array(32).fill(1));
    const nonce = b64urlEncode(new Uint8Array(12).fill(2));
    const sha = b64urlEncode(new Uint8Array(32).fill(3));
    const good = { id: ID, name: "a\u0000b.txt", mime: "Text/Plain", size: 5, key, nonce, sha256: sha };
    const envelope = [{ id: ID, name: "", mime: "application/octet-stream", size: 21, sha256: sha }];
    expect(contentAttachments({ attachments: [good] }, envelope)).toEqual([{ ...good, name: "ab.txt", mime: "text/plain" }]);
    expect(contentAttachments({ attachments: [{ ...good, id: "01J9ZK3G5M8Q2W4E6R8T0Y2V99" }] }, envelope)).toEqual([]);
    expect(contentAttachments({ attachments: [{ ...good, sha256: key }] }, envelope)).toEqual([]);
    expect(contentAttachments({ attachments: [{ ...good, key: "short" }] }, envelope)).toEqual([]);
    expect(contentAttachments({ attachments: [{ ...good, mime: "<script>" }] }, envelope)[0]!.mime).toBe("application/octet-stream");
    expect(contentAttachments({ attachments: "x" }, envelope)).toEqual([]);
    // Spoiler flag (design note 4.13): only a literal true counts.
    expect(contentAttachments({ attachments: [{ ...good, spoiler: true }] }, envelope)[0]!.spoiler).toBe(true);
    expect(contentAttachments({ attachments: [{ ...good, spoiler: "yes" }] }, envelope)[0]!.spoiler).toBeUndefined();
    expect(contentAttachments({}, undefined)).toEqual([]);
    expect(b64urlDecode(nonce)).toHaveLength(12);
  });

  it("cleans file names", () => {
    expect(safeFileName("..\\..\\etc/passwd")).toBe("_.._etc_passwd");
    expect(safeFileName("\u0007")).toBe("file");
    expect(safeFileName("x".repeat(300))).toHaveLength(255);
  });
});
