// SPDX-License-Identifier: MPL-2.0
// Write-only webhooks (ENCRYPTION.md §5b): the WebAssembly derivation matches the published vectors of the Rust
// crate, a box sealed by the vectors opens, and the payload checks of sealed webhook messages.
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { Client, inboxPublicKey, sealToInbox } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import { ensureCrypto } from "../src/wasm";
import { sealedContent, validWebhookName, webhookPayload } from "../src/sealed";

beforeAll(() => ensureCrypto());

const vectors = JSON.parse(readFileSync(new URL("../../protocol/testvectors/encryption.json", import.meta.url), "utf8"));
const v = vectors.webhook_inbox as Record<string, string | number>;

describe("inbox keys and sealed boxes (WebAssembly)", () => {
  it("derives the published inbox public key from the content key", () => {
    expect(b64urlEncode(inboxPublicKey(b64urlDecode(v.content_key as string)))).toBe(v.inbox_public_key);
  });

  it("opens the published sealed box with the epoch's content key and signs the published key like the vectors", () => {
    const att = vectors.device_attestation;
    const client = Client.create(att.user_address, att.device_id);
    try {
      client.importEpochKey(v.conversation as string, v.epoch as number, b64urlDecode(v.content_key as string));
      expect(client.openSealed(v.conversation as string, v.epoch as number, b64urlDecode(v.sealed as string))).toBe(v.payload);
      const key = client.inboxKey(v.conversation as string, v.epoch as number);
      expect(b64urlEncode(key.publicKey)).toBe(v.inbox_public_key);
      expect(key.signature).toHaveLength(64);
      key.free();
      // A fresh box from the binding opens as well; another epoch's key does not.
      const box = sealToInbox(b64urlDecode(v.inbox_public_key as string), new TextEncoder().encode("{}"));
      expect(client.openSealed(v.conversation as string, v.epoch as number, box)).toBe("{}");
      client.importEpochKey(v.conversation as string, 43, new Uint8Array(32).fill(1));
      expect(() => client.openSealed(v.conversation as string, 43, box)).toThrow(expect.objectContaining({ name: "decryption_failed" }));
      expect(() => client.openSealed(v.conversation as string, 44, box)).toThrow(expect.objectContaining({ name: "unknown_epoch" }));
    } finally {
      client.free();
    }
  });
});

describe("sealed webhook payloads", () => {
  it("recognizes only the sealed content shape", () => {
    expect(sealedContent({ type: "webhook.sealed", epoch: 3, sealed: "abc_-", sealed_by: "node" })).toEqual({ epoch: 3, sealed: "abc_-", sealedBy: "node" });
    expect(sealedContent({ type: "webhook.sealed", epoch: 3, sealed: "abc" })).toEqual({ epoch: 3, sealed: "abc", sealedBy: "sender" });
    for (const bad of ["AAAA", null, [], { type: "text" }, { type: "webhook.sealed", epoch: -1, sealed: "a" }, { type: "webhook.sealed", epoch: 1.5, sealed: "a" }, { type: "webhook.sealed", epoch: 1, sealed: "a b" }]) {
      expect(sealedContent(bad)).toBeNull();
    }
  });

  it("keeps text, valid embeds and a valid username, nothing else", () => {
    expect(webhookPayload(JSON.stringify({ content: { type: "text", body: "hi", gif: { url: "x" }, preview: {} }, username: " CI ", extra: 1 }))).toEqual({ content: { type: "text", body: "hi" }, username: "CI" });
    expect(webhookPayload(JSON.stringify({ content: { type: "text", body: "", embeds: [{ title: "t" }] } }))).toEqual({ content: { type: "text", body: "", embeds: [{ title: "t" }] } });
    expect(webhookPayload(JSON.stringify({ content: { type: "text", body: "x", embeds: [{ url: "javascript:alert(1)", title: "t" }] } }))).toEqual({ content: { type: "text", body: "x" } });
    for (const bad of ["not json", "[]", "{}", JSON.stringify({ content: { type: "action", body: "x" } }), JSON.stringify({ content: { type: "text", body: "   " } }), JSON.stringify({ content: { type: "text", body: "x".repeat(4001) } })]) {
      expect(webhookPayload(bad)).toBeNull();
    }
  });

  it("checks usernames like the node", () => {
    expect(validWebhookName("CI Bot")).toBe(true);
    expect(validWebhookName("ä".repeat(32))).toBe(true);
    for (const bad of ["", " ", "a@b", "#c", "a:b", "everyone", "Here", "x".repeat(33), "a\nb", "‮x", 7]) expect(validWebhookName(bad)).toBe(false);
  });
});
