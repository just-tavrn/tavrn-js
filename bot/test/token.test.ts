// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { b64urlEncode } from "@tavrn/sdk";
import { appTokenClaims } from "../src/token";

const enc = (v: unknown) => b64urlEncode(new TextEncoder().encode(JSON.stringify(v)));
const jwt = (payload: unknown) => `${enc({ alg: "EdDSA", typ: "JWT" })}.${enc(payload)}.c2ln`;

describe("app token claims (APPLICATIONS.md §2.1)", () => {
  it("reads device, application, issuer and expiry", () => {
    const claims = appTokenClaims(jwt({ typ: "app", iss: "h.test", aud: "h.test", sub: "U", dev: "D", app: "A", exp: 1, owner: "o@h.test", scp: ["commands", 3] }));
    expect(claims).toEqual({ iss: "h.test", sub: "U", dev: "D", app: "A", exp: 1, owner: "o@h.test", scp: ["commands"] });
  });

  it("refuses session tokens, malformed tokens and missing claims", () => {
    expect(() => appTokenClaims(jwt({ typ: "session", iss: "h.test", sub: "U", dev: "D", app: "A", exp: 1 }))).toThrow(/not an app token/);
    expect(() => appTokenClaims("not-a-jwt")).toThrow(expect.objectContaining({ code: "token_invalid" }));
    expect(() => appTokenClaims("a.!!!.c")).toThrow(expect.objectContaining({ code: "token_invalid" }));
    expect(() => appTokenClaims(jwt({ typ: "app", iss: "h.test", sub: "U", app: "A", exp: 1 }))).toThrow(expect.objectContaining({ code: "token_invalid" }));
  });
});
