// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { b64urlDecode, b64urlEncode, credentialToJSON, parseCreationOptions, parseRequestOptions, prfFirst, stripPrfResults } from "../src/webauthn";

const enc = (s: string) => new TextEncoder().encode(s);
const PRF = "dGF2cm4gc2VjcmV0IHN0b3JhZ2UgcHJmIHYx";

describe("base64url", () => {
  it("round-trips without padding", () => {
    for (const s of ["", "f", "fo", "foo", "foob", "fooba", "foobar"]) {
      const b = b64urlEncode(enc(s));
      expect(b).not.toContain("=");
      expect(new TextDecoder().decode(b64urlDecode(b))).toBe(s);
    }
    expect(b64urlEncode(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    expect(new TextDecoder().decode(b64urlDecode(PRF))).toBe("tavrn secret storage prf v1");
  });

  it("rejects invalid input", () => {
    expect(() => b64urlDecode("a+b")).toThrow();
  });
});

describe("option conversion (fallback without parse…FromJSON)", () => {
  it("converts creation options including the PRF input", () => {
    const opts = parseCreationOptions({
      publicKey: {
        rp: { id: "localhost", name: "tavrn" },
        user: { id: b64urlEncode(enc("user-handle")), name: "alice", displayName: "Alice" },
        challenge: b64urlEncode(enc("challenge")),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [{ type: "public-key", id: b64urlEncode(enc("old")) }],
        extensions: { prf: { eval: { first: PRF } } },
      },
    });
    const pk = opts.publicKey!;
    expect(new TextDecoder().decode(pk.challenge as Uint8Array)).toBe("challenge");
    expect(new TextDecoder().decode(pk.user.id as Uint8Array)).toBe("user-handle");
    expect(new TextDecoder().decode(pk.excludeCredentials![0]!.id as Uint8Array)).toBe("old");
    const prf = (pk.extensions as { prf: { eval: { first: Uint8Array } } }).prf.eval.first;
    expect(new TextDecoder().decode(prf)).toBe("tavrn secret storage prf v1");
    expect(pk.rp.id).toBe("localhost");
  });

  it("converts request options and keeps mediation", () => {
    const opts = parseRequestOptions({
      publicKey: { challenge: b64urlEncode(enc("c")), rpId: "localhost", allowCredentials: [{ type: "public-key", id: b64urlEncode(enc("k1")) }], userVerification: "required", extensions: { prf: { eval: { first: PRF } } } },
      mediation: "optional",
    });
    expect(new TextDecoder().decode(opts.publicKey!.allowCredentials![0]!.id as Uint8Array)).toBe("k1");
    expect(opts.publicKey!.userVerification).toBe("required");
    expect(opts.mediation).toBe("optional");
  });

  it("rejects options without publicKey", () => {
    expect(() => parseCreationOptions({})).toThrow();
    expect(() => parseRequestOptions({ publicKey: {} })).toThrow();
  });
});

function fakeAssertion(prf?: ArrayBuffer) {
  const buf = (s: string) => enc(s).buffer as ArrayBuffer;
  return {
    id: "a2V5",
    rawId: buf("key"),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: { clientDataJSON: buf("cdj"), authenticatorData: buf("ad"), signature: buf("sig"), userHandle: buf("uh") },
    getClientExtensionResults: () => (prf ? { prf: { enabled: true, results: { first: prf } } } : {}),
  } as unknown as PublicKeyCredential;
}

describe("credential JSON", () => {
  it("serializes an assertion and strips the PRF result before it goes to the node", () => {
    const prf = new Uint8Array(32).fill(9).buffer;
    const cred = fakeAssertion(prf);
    expect(prfFirst(cred)).toEqual(new Uint8Array(32).fill(9));
    const json = credentialToJSON(cred);
    expect(json).toMatchObject({ id: "a2V5", rawId: "a2V5", type: "public-key", response: { clientDataJSON: b64urlEncode(enc("cdj")), signature: b64urlEncode(enc("sig")), userHandle: b64urlEncode(enc("uh")) } });
    const stripped = stripPrfResults(json);
    expect(JSON.stringify(stripped)).not.toContain("results");
    expect(stripped).toMatchObject({ clientExtensionResults: { prf: { enabled: true } } });
    // The input object is not mutated.
    expect((json.clientExtensionResults as { prf: { results?: unknown } }).prf.results).toBeDefined();
  });

  it("serializes an attestation response with transports", () => {
    const buf = (s: string) => enc(s).buffer as ArrayBuffer;
    const cred = {
      id: "a2V5",
      rawId: buf("key"),
      type: "public-key",
      authenticatorAttachment: null,
      response: { clientDataJSON: buf("cdj"), attestationObject: buf("att"), getTransports: () => ["internal"] },
      getClientExtensionResults: () => ({ prf: { enabled: true } }),
    } as unknown as PublicKeyCredential;
    const json = credentialToJSON(cred);
    expect(json.response).toEqual({ clientDataJSON: b64urlEncode(enc("cdj")), attestationObject: b64urlEncode(enc("att")), transports: ["internal"] });
    expect(prfFirst(cred)).toBeNull();
  });

  it("strips PRF results from a browser toJSON() as well", () => {
    expect(stripPrfResults({ id: "x", clientExtensionResults: { prf: { results: { first: "AAAA" } } } })).toEqual({ id: "x", clientExtensionResults: { prf: {} } });
    expect(stripPrfResults({ id: "x" })).toEqual({ id: "x" });
  });
});
