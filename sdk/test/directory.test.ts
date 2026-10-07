// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi, b64urlEncode, verifyDirectoryRooms, verifyListing, type DirectoryRoom, type PublicKeyInfo } from "../src";

const subtle = globalThis.crypto.subtle;
const enc = (v: unknown) => b64urlEncode(new TextEncoder().encode(JSON.stringify(v)));
const NOW = 1_800_000_000;
const ROOM = "01JABCDEFGHJKMNPQRSTVWXYZ0";

async function keyPair(kid: string): Promise<{ info: PublicKeyInfo; sign: (claims: Record<string, unknown>, header?: Record<string, unknown>) => Promise<string> }> {
  const pair = (await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  return {
    info: { kid, alg: "EdDSA", crv: "Ed25519", x: b64urlEncode(raw) },
    sign: async (claims, header = { alg: "EdDSA", typ: "JWT", kid }) => {
      const input = `${enc(header)}.${enc(claims)}`;
      const sig = await subtle.sign({ name: "Ed25519" }, pair.privateKey, new TextEncoder().encode(input));
      return `${input}.${b64urlEncode(sig)}`;
    },
  };
}

function claims(over: Record<string, unknown> = {}) {
  return { iss: "b.test", sub: ROOM, aud: "tavrn-directory", typ: "listing", iat: NOW - 60, exp: NOW - 60 + 48 * 3600, jti: "x", name: "Board games", description: "Signed", icon_sha256: null, member_count: 4, ...over };
}

describe("verifyListing", () => {
  it("accepts a listing the hosting node signed for exactly that room", async () => {
    const b = await keyPair("k1");
    const check = await verifyListing(await b.sign(claims()), { node: "b.test", roomId: ROOM }, [b.info], { now: NOW });
    expect(check.status).toBe("valid");
    if (check.status === "valid") expect(check.claims.name).toBe("Board games");
  });

  it("refuses forged, foreign and stale listings", async () => {
    const b = await keyPair("k1");
    const evil = await keyPair("k1");
    const expected = { node: "b.test", roomId: ROOM };
    const reason = async (token: string, keys = [b.info], exp = expected) => {
      const check = await verifyListing(token, exp, keys, { now: NOW });
      return check.status === "invalid" ? check.reason : check.status;
    };
    expect(await reason(await evil.sign(claims()))).toBe("signature");
    expect(await reason(await b.sign(claims({ iss: "c.test" })))).toBe("signer");
    expect(await reason(await b.sign(claims()), [b.info], { node: "c.test", roomId: ROOM })).toBe("signer");
    expect(await reason(await b.sign(claims({ sub: "01JOTHERROOM00000000000000" })))).toBe("room");
    expect(await reason(await b.sign(claims({ aud: "b.test" })))).toBe("audience");
    expect(await reason(await b.sign(claims({ typ: "s2s" })))).toBe("audience");
    expect(await reason(await b.sign(claims({ iat: NOW - 7200, exp: NOW - 1 })))).toBe("expired");
    expect(await reason(await b.sign(claims({ exp: NOW + 30 * 24 * 3600 })))).toBe("lifetime");
    expect(await reason(await b.sign(claims({ iat: NOW + 3600 })))).toBe("lifetime");
    expect(await reason(await b.sign(claims({ member_count: "many" })))).toBe("claims");
    expect(await reason(await b.sign(claims(), { alg: "none", typ: "JWT", kid: "k1" }))).toBe("header");
    expect(await reason(await b.sign(claims(), { alg: "EdDSA", typ: "JWT", kid: "k2" }))).toBe("unknown key");
    expect(await reason("a.b")).toBe("format");
    expect(await reason("x".repeat(5000))).toBe("format");
    // A tampered payload breaks the signature.
    const [h, , s] = (await b.sign(claims())).split(".");
    expect(await reason(`${h}.${enc(claims({ member_count: 9999 }))}.${s}`)).toBe("signature");
  });

  it("reports runtimes without Ed25519 instead of failing", async () => {
    const b = await keyPair("k1");
    const noEd25519 = { importKey: vi.fn().mockRejectedValue(new DOMException("no", "NotSupportedError")) } as unknown as SubtleCrypto;
    const check = await verifyListing(await b.sign(claims()), { node: "b.test", roomId: ROOM }, [b.info], { now: NOW, subtle: noEd25519 });
    expect(check.status).toBe("unsupported");
  });
});

describe("verifyDirectoryRooms", () => {
  it("drops entries that fail and prefers the signed values", async () => {
    const b = await keyPair("k1");
    const c = await keyPair("c1");
    const good: DirectoryRoom = { node: "b.test", room_id: ROOM, name: "Renamed by the relay", description: "", icon_url: null, member_count: 999, listing: await b.sign(claims()) };
    const forged: DirectoryRoom = { ...good, room_id: "01JFORGED00000000000000000", listing: await c.sign(claims({ sub: "01JFORGED00000000000000000" })) };
    const offline: DirectoryRoom = { ...good, node: "down.test" };
    const keysOf = vi.fn(async (node: string) => {
      if (node === "b.test") return [b.info];
      throw new Error("unreachable");
    });
    const rooms = await verifyDirectoryRooms([good, forged, offline], keysOf, { now: NOW });
    expect(rooms).toHaveLength(1);
    expect(rooms[0]).toMatchObject({ node: "b.test", name: "Board games", description: "Signed", member_count: 4, verification: "valid" });
    expect(keysOf).toHaveBeenCalledTimes(2);
  });
});

describe("directory API", () => {
  it("queries the node's directory routes", async () => {
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (url: string | URL | Request) => {
      calls.push(String(url));
      return new Response(JSON.stringify({ items: [], next: null }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    const api = new TavrnApi({ baseUrl: "https://a.test", fetchImpl: fetchImpl as unknown as typeof fetch });
    await api.directory.rooms({ q: "brett", local: true, min_members: 2 });
    await api.directory.nodes({ cursor: "b.test" });
    await api.directory.node("b.test");
    expect(calls).toEqual([
      "https://a.test/api/v1/directory/rooms?q=brett&local=true&min_members=2",
      "https://a.test/api/v1/directory/nodes?cursor=b.test",
      "https://a.test/api/v1/directory/nodes/b.test",
    ]);
  });
});

describe("directory reports (FEDERATION.md §9.2)", () => {
  it("sends reports to the home node and lists them for admins", async () => {
    const calls: { url: string; method: string; body?: unknown }[] = [];
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : undefined });
      const status = init?.method === "DELETE" ? 204 : init?.method === "POST" ? 201 : 200;
      return status === 204 ? new Response(null, { status }) : new Response(JSON.stringify(init?.method === "POST" ? { id: "r1" } : []), { status, headers: { "Content-Type": "application/json" } });
    });
    const api = new TavrnApi({ baseUrl: "https://a.test", fetchImpl: fetchImpl as unknown as typeof fetch, getToken: () => "t" });
    await api.directory.report({ domain: "b.test", room_id: "01J9ZK3G5M8Q2W4E6R8T0Y2V01", check: "spam", detail: "Advertising" });
    await api.admin.reports();
    await api.admin.reportsOf("b.test");
    await api.admin.dismissReports("b.test");
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "POST https://a.test/api/v1/directory/reports",
      "GET https://a.test/api/v1/admin/directory/reports",
      "GET https://a.test/api/v1/admin/directory/reports/b.test",
      "DELETE https://a.test/api/v1/admin/directory/reports/b.test",
    ]);
    expect(calls[0]!.body).toEqual({ domain: "b.test", room_id: "01J9ZK3G5M8Q2W4E6R8T0Y2V01", check: "spam", detail: "Advertising" });
  });
});
