// SPDX-License-Identifier: MPL-2.0
import { beforeAll, describe, expect, it } from "vitest";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { AttachmentIntegrityError, contentAttachments, decryptAttachment, encryptAttachment, safeFileName } from "../src/content";

beforeAll(() => ensureCrypto());

const ID = "01J9ZK3G5M8Q2W4E6R8T0Y2V00";

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
