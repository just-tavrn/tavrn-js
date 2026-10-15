// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { HookVerifier, b64urlEncode, verifyHookRequest, type PublicKeyInfo } from "../src";

const subtle = globalThis.crypto.subtle;
const enc = (v: unknown) => b64urlEncode(new TextEncoder().encode(JSON.stringify(v)));
const NOW = 1_800_000_000;
const NODE = "node.example";
const APP = "01JAPPAPPAPPAPPAPPAPPAPPAP";
const URL = "https://bot.example/hook";

async function keyPair(kid: string) {
  const pair = (await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const info: PublicKeyInfo = { kid, alg: "EdDSA", crv: "Ed25519", x: b64urlEncode(raw) };
  const sign = async (claims: Record<string, unknown>) => {
    const input = `${enc({ alg: "EdDSA", typ: "JWT", kid })}.${enc(claims)}`;
    const sig = await subtle.sign({ name: "Ed25519" }, pair.privateKey, new TextEncoder().encode(input));
    return `${input}.${b64urlEncode(sig)}`;
  };
  return { info, sign };
}

async function sha(body: string) {
  return b64urlEncode(await subtle.digest("SHA-256", new TextEncoder().encode(body)));
}

let jtiCounter = 0;
async function claims(body: string, over: Record<string, unknown> = {}) {
  jtiCounter += 1;
  return { iss: NODE, sub: NODE, aud: `app:${APP}`, typ: "hook", iat: NOW - 5, exp: NOW + 295, jti: `jti-${jtiCounter}`, htu: URL, body_sha256: await sha(body), ...over };
}

/** A fake node whose `.well-known` serves `keys()`; counts the fetches. */
function fakeNode(keys: () => PublicKeyInfo[]) {
  const state = { fetches: 0 };
  const fetchImpl = (async (input: RequestInfo | URL) => {
    state.fetches += 1;
    expect(String(input)).toBe(`https://${NODE}/.well-known/tavrn`);
    return new Response(JSON.stringify({ domain: NODE, keys: keys() }), { headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { state, fetchImpl };
}

describe("HookVerifier", () => {
  const body = JSON.stringify({ id: "01JEVENT", type: "message.create", data: { content: { type: "text", body: "hi" } } });

  it("accepts a correctly signed request and returns the event", async () => {
    const k = await keyPair("k1");
    const node = fakeNode(() => [k.info]);
    let now = NOW;
    const v = new HookVerifier({ node: NODE, applicationId: APP, url: URL, fetch: node.fetchImpl, now: () => now });
    const token = await k.sign(await claims(body));
    const result = await v.verify({ headers: { "Tavrn-Signature": token, "Tavrn-Event-Type": "message.create" }, body });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.event.type).toBe("message.create");
    // A Headers object and a byte body work too; the keys come from the cache (≤ 1 hour).
    const second = await v.verify({ headers: new Headers({ "tavrn-signature": await k.sign(await claims(body)) }), body: new TextEncoder().encode(body) });
    expect(second.ok).toBe(true);
    expect(node.state.fetches).toBe(1);
    now += 3601;
    const later = await v.verify({ headers: { "tavrn-signature": await k.sign(await claims(body, { iat: now - 1, exp: now + 200 })) }, body });
    expect(later.ok).toBe(true);
    expect(node.state.fetches).toBe(2);
  });

  it("refuses tampered bodies, replays, wrong targets and audiences, and expired tokens", async () => {
    const k = await keyPair("k1");
    const node = fakeNode(() => [k.info]);
    const v = new HookVerifier({ node: NODE, applicationId: APP, url: URL, fetch: node.fetchImpl, now: () => NOW });
    const reason = async (token: string, b = body) => {
      const r = await v.verify({ headers: { "tavrn-signature": token }, body: b });
      return r.ok ? "ok" : r.reason;
    };
    // Tampered body: the hash no longer matches (checked before the body is parsed).
    expect(await reason(await k.sign(await claims(body)), body.replace("hi", "pwned"))).toBe("body");
    expect(await reason(await k.sign(await claims("not json")), "not json")).toBe("body_invalid");
    // Replayed jti.
    const once = await k.sign(await claims(body, { jti: "same" }));
    expect(await reason(once)).toBe("ok");
    expect(await reason(once)).toBe("replay");
    // Wrong htu, aud, typ, issuer.
    expect(await reason(await k.sign(await claims(body, { htu: "https://other.example/hook" })))).toBe("url");
    expect(await reason(await k.sign(await claims(body, { aud: "app:01JOTHERAPPOTHERAPPOTHERAP" })))).toBe("audience");
    expect(await reason(await k.sign(await claims(body, { typ: "s2s" })))).toBe("type");
    expect(await reason(await k.sign(await claims(body, { iss: "evil.example", sub: "evil.example" })))).toBe("issuer");
    // Expired, too long, from the future, iat too old.
    expect(await reason(await k.sign(await claims(body, { iat: NOW - 299, exp: NOW - 1 })))).toBe("expired");
    expect(await reason(await k.sign(await claims(body, { iat: NOW, exp: NOW + 3600 })))).toBe("time");
    expect(await reason(await k.sign(await claims(body, { iat: NOW + 600, exp: NOW + 700 })))).toBe("time");
    expect(await reason(await k.sign(await claims(body, { iat: NOW - 400, exp: NOW + 10 })))).toBe("time");
    // A signature of another key with a known kid, a missing header, garbage.
    const evil = await keyPair("k1");
    expect(await reason(await evil.sign(await claims(body)))).toBe("signature");
    expect((await v.verify({ headers: {}, body })).ok).toBe(false);
    expect(await reason("a.b")).toBe("format");
    const [h, , s] = (await k.sign(await claims(body))).split(".");
    expect(await reason(`${h}.${enc(await claims(body, { aud: `app:${APP}`, htu: URL, jti: "forged" }))}.${s}`)).toBe("signature");
  });

  it("refetches the keys once for an unknown kid (key rotation)", async () => {
    const old = await keyPair("k1");
    const rotated = await keyPair("k2");
    let published = [old.info];
    const node = fakeNode(() => published);
    let now = NOW;
    const v = new HookVerifier({ node: NODE, applicationId: APP, url: URL, fetch: node.fetchImpl, now: () => now });
    expect((await v.verify({ headers: { "tavrn-signature": await old.sign(await claims(body)) }, body })).ok).toBe(true);
    expect(node.state.fetches).toBe(1);
    // The node rotated: the token names k2, the cache knows k1 only → exactly one refetch.
    published = [old.info, rotated.info];
    const r = await v.verify({ headers: { "tavrn-signature": await rotated.sign(await claims(body)) }, body });
    expect(r.ok).toBe(true);
    expect(node.state.fetches).toBe(2);
    // An unknown kid that the node does not publish either: one refetch, then refused; no refetch storm.
    const stranger = await keyPair("k9");
    now += 60;
    const refused = await v.verify({ headers: { "tavrn-signature": await stranger.sign(await claims(body, { iat: now, exp: now + 100 })) }, body });
    expect(refused).toEqual({ ok: false, reason: "unknown_key" });
    expect(node.state.fetches).toBe(3);
    const again = await v.verify({ headers: { "tavrn-signature": await stranger.sign(await claims(body, { iat: now, exp: now + 100 })) }, body });
    expect(again).toEqual({ ok: false, reason: "unknown_key" });
    expect(node.state.fetches).toBe(3);
  });

  it("verifyHookRequest keeps one verifier per application (shared replay window)", async () => {
    const k = await keyPair("k1");
    const node = fakeNode(() => [k.info]);
    const opts = { node: NODE, applicationId: APP, url: "https://bot.example/shared", fetch: node.fetchImpl, now: () => NOW };
    const token = await k.sign(await claims(body, { htu: opts.url, jti: "shared-jti" }));
    expect((await verifyHookRequest({ headers: { "tavrn-signature": token }, body }, opts)).ok).toBe(true);
    expect(await verifyHookRequest({ headers: { "tavrn-signature": token }, body }, opts)).toEqual({ ok: false, reason: "replay" });
    expect(node.state.fetches).toBe(1);
  });

  it("reads the node's keys with a size cap and a timeout", async () => {
    const k = await keyPair("k1");
    const pulls: number[] = [];
    const huge = (async () => {
      const n = pulls.push(0) - 1;
      return new Response(
        new ReadableStream<Uint8Array>({
          pull(c) {
            pulls[n]! += 1;
            c.enqueue(new Uint8Array(16 * 1024).fill(0x20));
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;
    const v = new HookVerifier({ node: NODE, applicationId: APP, url: URL, fetch: huge, now: () => NOW });
    expect(await v.verify({ headers: { "tavrn-signature": await k.sign(await claims(body)) }, body })).toEqual({ ok: false, reason: "keys_unavailable" });
    // Every fetch (the first one and the refetch for the unknown key) stops at the cap.
    expect(pulls.length).toBeGreaterThan(0);
    for (const p of pulls) expect(p).toBeLessThanOrEqual(6);
    const hang = ((_url: string, init: RequestInit) => new Promise<Response>((_, reject) => init.signal?.addEventListener("abort", () => reject(init.signal!.reason), { once: true }))) as unknown as typeof fetch;
    const slow = new HookVerifier({ node: NODE, applicationId: APP, url: URL, fetch: hang, now: () => NOW, timeoutMs: 30 });
    expect(await slow.verify({ headers: { "tavrn-signature": await k.sign(await claims(body)) }, body })).toEqual({ ok: false, reason: "keys_unavailable" });
  });

  it("answers keys_unavailable when the node cannot be reached", async () => {
    const k = await keyPair("k1");
    const failing = (async () => new Response("nope", { status: 503 })) as typeof fetch;
    const v = new HookVerifier({ node: NODE, applicationId: APP, url: URL, fetch: failing, now: () => NOW });
    expect(await v.verify({ headers: { "tavrn-signature": await k.sign(await claims(body)) }, body })).toEqual({ ok: false, reason: "keys_unavailable" });
  });
});
