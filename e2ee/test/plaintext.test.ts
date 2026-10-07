// SPDX-License-Identifier: MPL-2.0
import { describe, expect, it } from "vitest";
import { b64urlEncode } from "@tavrn/sdk";
import { envelopeFields, plainMarker, signatureNonce, signedAttachments } from "../src/plaintext";

describe("plaintext signature helpers", () => {
  it("reads the nonce from an 80-byte signature and refuses anything else", () => {
    const bytes = new Uint8Array(80).map((_, i) => i);
    const sig = b64urlEncode(bytes);
    expect(sig).toHaveLength(107);
    expect(signatureNonce(sig)).toBe(b64urlEncode(bytes.slice(0, 16)));
    expect(signatureNonce(sig.slice(1))).toBeNull();
    expect(signatureNonce(`${sig.slice(0, 106)}+`)).toBeNull();
    expect(signatureNonce(b64urlEncode(new Uint8Array(81)))).toBeNull();
    expect(signatureNonce("")).toBeNull();
  });

  it("maps verification results to markers", () => {
    expect(plainMarker(undefined)).toBeNull();
    expect(plainMarker("valid")).toBeNull();
    expect(plainMarker("unsigned")).toBe("unverified");
    expect(plainMarker("unverifiable")).toBe("unverified");
    expect(plainMarker("invalid")).toBe("hidden");
    expect(plainMarker("replay")).toBe("hidden");
  });

  it("takes the covered fields from an envelope in envelope order", () => {
    const m = {
      id: "m1",
      author: "alice@t.local",
      device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1",
      reply_to_id: "01J9ZK3G5M8Q2W4E6R8T0Y2V01",
      mentions: ["bob@t.local", "carol@t.local"],
      mentions_everyone: true,
      attachments: [
        { id: "B", size: 2, sha256: "y", name: "b.png", mime: "image/png" },
        { id: "A", size: 1, sha256: "x", name: "a.png", mime: "image/png" },
      ],
      content: { type: "text", body: "x" },
    };
    expect(envelopeFields("t.local/C", m)).toEqual({
      conversation: "t.local/C",
      author: "alice@t.local",
      device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2VA1",
      reply_to: "01J9ZK3G5M8Q2W4E6R8T0Y2V01",
      thread_id: null,
      mentions_everyone: true,
      mentions: ["bob@t.local", "carol@t.local"],
      attachments: [
        { id: "B", size: 2, sha256: "y" },
        { id: "A", size: 1, sha256: "x" },
      ],
    });
    // System messages have no device and are never signed.
    expect(envelopeFields("t.local/C", { ...m, device_id: null })).toBeNull();
    // The signer sorts attachments by id, as the node lists them.
    expect(signedAttachments(m.attachments).map((a) => a.id)).toEqual(["A", "B"]);
  });
});
