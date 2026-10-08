// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi } from "../src";

function fetchMock(responses: Array<{ status: number; body?: unknown }>) {
  const calls: Array<{ url: string; method: string; body: unknown; auth: string | undefined }> = [];
  let i = 0;
  const impl = vi.fn(async (url: string, init: RequestInit) => {
    const headers = (init.headers ?? {}) as Record<string, string>;
    calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body as string) : undefined, auth: headers.Authorization });
    const r = responses[Math.min(i++, responses.length - 1)]!;
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status, headers: { "Content-Type": "application/json" } });
  });
  return { impl: impl as unknown as typeof fetch, calls };
}

const preauth = { status: "second_factor_required", preauth_token: "pre", methods: ["totp", "recovery_code"], expires_in: 600 };

describe("TavrnApi: second factor", () => {
  it("login and register return the pre-auth response", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: preauth }, { status: 201, body: { ...preauth, status: "enrollment_required" } }]);
    const api = new TavrnApi({ fetchImpl: impl });
    const login = await api.auth.login({ username: "alice", password: "pw" });
    expect(login.status).toBe("second_factor_required");
    const reg = await api.auth.register({ username: "alice", password: "pw" });
    expect(reg.status).toBe("enrollment_required");
    expect(calls.map((c) => c.url)).toEqual(["http://localhost/api/v1/auth/login", "http://localhost/api/v1/auth/register"]);
  });

  it("verifies with TOTP code or recovery code", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: { status: "ok", access_token: "a" } }]);
    const api = new TavrnApi({ fetchImpl: impl });
    await api.auth.verifySecondFactor({ preauth_token: "pre", totp_code: "123456" });
    await api.auth.verifySecondFactor({ preauth_token: "pre", recovery_code: "abcd-efgh-ijkl" });
    expect(calls[0]).toMatchObject({ method: "POST", url: "http://localhost/api/v1/auth/second-factor/verify", body: { preauth_token: "pre", totp_code: "123456" } });
    expect(calls[1]!.body).toEqual({ preauth_token: "pre", recovery_code: "abcd-efgh-ijkl" });
  });

  it("withToken uses the pre-auth token for enrollment without touching the session", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: { secret: "S", otpauth_url: "otpauth://x", issuer: "n" } }, { status: 200, body: { recovery_codes: ["a"], session: null } }, { status: 200, body: [] }]);
    const api = new TavrnApi({ fetchImpl: impl, getToken: () => "session", refreshToken: vi.fn() });
    const pre = api.withToken("pre");
    await pre.auth.totpEnroll();
    await pre.auth.totpConfirm("123456");
    await api.auth.webauthnCredentials();
    expect(calls.map((c) => [c.method, c.url, c.auth])).toEqual([
      ["POST", "http://localhost/api/v1/auth/totp/enroll", "Bearer pre"],
      ["POST", "http://localhost/api/v1/auth/totp/confirm", "Bearer pre"],
      ["GET", "http://localhost/api/v1/auth/webauthn/credentials", "Bearer session"],
    ]);
    expect(calls[1]!.body).toEqual({ code: "123456" });
  });

  it("does not try a refresh with a pre-auth token", async () => {
    const refresh = vi.fn(async () => "fresh");
    const { impl, calls } = fetchMock([{ status: 401, body: { code: "auth.preauth_invalid", status: 401, title: "", detail: "", type: "" } }]);
    const api = new TavrnApi({ fetchImpl: impl, getToken: () => "session", refreshToken: refresh }).withToken("pre");
    const err = await api.auth.totpEnroll().catch((e: { code: string }) => e);
    expect(err.code).toBe("auth.preauth_invalid");
    expect(refresh).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
  });

  it("covers factor management routes", async () => {
    const { impl, calls } = fetchMock([{ status: 204 }]);
    const api = new TavrnApi({ fetchImpl: impl });
    await api.auth.totpRemove({ password: "pw" });
    await api.auth.factors();
    await api.auth.regenerateRecoveryCodes("pw");
    await api.auth.webauthnRegisterStart();
    await api.auth.webauthnRegisterFinish({ challenge_id: "c", name: "Key", response: {} });
    await api.auth.deleteWebauthnCredential("cred_-1");
    await api.auth.webauthnLoginStart({});
    await api.auth.webauthnLoginFinish({ challenge_id: "c", response: {}, device_name: "Browser" });
    await api.admin.resetSecondFactor("u1");
    expect(calls.map((c) => `${c.method} ${c.url.replace("http://localhost/api/v1", "")}`)).toEqual([
      "DELETE /auth/totp",
      "GET /auth/factors",
      "POST /auth/recovery-codes/regenerate",
      "POST /auth/webauthn/register/start",
      "POST /auth/webauthn/register/finish",
      "DELETE /auth/webauthn/credentials/cred_-1",
      "POST /auth/webauthn/login/start",
      "POST /auth/webauthn/login/finish",
      "POST /admin/users/u1/second-factor/reset",
    ]);
    expect(calls[0]!.body).toEqual({ password: "pw" });
    expect(calls[2]!.body).toEqual({ password: "pw" });
  });
});

describe("TavrnApi: keys and secret storage", () => {
  it("covers identity, device key, key package and secret storage routes", async () => {
    const { impl, calls } = fetchMock([{ status: 204 }]);
    const api = new TavrnApi({ fetchImpl: impl });
    await api.keys.putIdentity({ identity_public_key: "pk" });
    await api.keys.get("alice");
    await api.keys.resetIdentity({ identity_public_key: "pk2", password: "pw" });
    await api.keys.putDeviceKey("D1", { device_public_key: "dk", identity_signature: "sig" });
    await api.keys.uploadKeyPackages("D1", { key_packages: ["kp"] });
    await api.keys.countKeyPackages("D1");
    await api.secretStorage.list();
    await api.secretStorage.putRecovery({ wrapped: "w", params: {} });
    await api.secretStorage.putPasskey("cred_-1", { wrapped: "w", params: { v: 1 } });
    await api.secretStorage.deletePasskey("cred_-1");
    expect(calls.map((c) => `${c.method} ${c.url.replace("http://localhost/api/v1", "")}`)).toEqual([
      "PUT /users/me/identity",
      "GET /users/alice/keys",
      "POST /users/me/identity/reset",
      "PUT /users/me/devices/D1/key",
      "POST /users/me/devices/D1/key-packages",
      "GET /users/me/devices/D1/key-packages",
      "GET /users/me/secret-storage",
      "PUT /users/me/secret-storage/recovery",
      "PUT /users/me/secret-storage/passkey/cred_-1",
      "DELETE /users/me/secret-storage/passkey/cred_-1",
    ]);
    expect(calls[2]!.body).toEqual({ identity_public_key: "pk2", password: "pw" });
    expect(calls[8]!.body).toEqual({ wrapped: "w", params: { v: 1 } });
  });

  it("encodes path segments", async () => {
    const { impl, calls } = fetchMock([{ status: 200, body: {} }]);
    const api = new TavrnApi({ fetchImpl: impl });
    await api.keys.get("a/b");
    await api.auth.deleteWebauthnCredential("x/y");
    expect(calls[0]!.url).toBe("http://localhost/api/v1/users/a%2Fb/keys");
    expect(calls[1]!.url).toBe("http://localhost/api/v1/auth/webauthn/credentials/x%2Fy");
  });
});

describe("TavrnApi: app sessions of the connect flow (FEDERATION.md §8 step 3)", () => {
  it("creates a session, polls it and exchanges the code", async () => {
    const { impl, calls } = fetchMock([
      { status: 200, body: { session_id: "S".repeat(43), expires_in: 600 } },
      { status: 200, body: { status: "pending", device_name: "Desktop app", expires_in: 598 } },
      { status: 200, body: { status: "ready", code: "c0de", node: "home.example", expires_in: 119 } },
      { status: 200, body: { status: "ok", access_token: "a" } },
    ]);
    const api = new TavrnApi({ fetchImpl: impl });
    const created = await api.auth.createConnectSession({ code_challenge: "x".repeat(43), device_name: "Desktop app" });
    expect(created.session_id).toHaveLength(43);
    expect((await api.auth.pollConnectSession(created.session_id)).status).toBe("pending");
    const ready = await api.auth.pollConnectSession(created.session_id);
    expect(ready).toMatchObject({ status: "ready", code: "c0de", node: "home.example" });
    await api.auth.connectToken({ code: ready.code!, code_verifier: "v".repeat(43) });
    expect(calls.map((c) => [c.method, c.url])).toEqual([
      ["POST", "http://localhost/api/v1/auth/connect/session"],
      ["GET", `http://localhost/api/v1/auth/connect/session/${"S".repeat(43)}`],
      ["GET", `http://localhost/api/v1/auth/connect/session/${"S".repeat(43)}`],
      ["POST", "http://localhost/api/v1/auth/connect/token"],
    ]);
    expect(calls[0]!.body).toEqual({ code_challenge: "x".repeat(43), device_name: "Desktop app" });
  });

  it("the page confirms with the session id; an expired session is an error with its code", async () => {
    const { impl, calls } = fetchMock([
      { status: 200, body: { code: "c", expires_in: 120 } },
      { status: 410, body: { type: "about:blank", title: "Gone", status: 410, code: "connect.session_expired" } },
    ]);
    const api = new TavrnApi({ fetchImpl: impl, getToken: () => "session" });
    await api.auth.connectCode({ session_id: "S".repeat(43) });
    expect(calls[0]).toMatchObject({ url: "http://localhost/api/v1/auth/connect/code", body: { session_id: "S".repeat(43) }, auth: "Bearer session" });
    await expect(api.auth.pollConnectSession("a/b")).rejects.toMatchObject({ status: 410, code: "connect.session_expired" });
    expect(calls[1]!.url).toBe("http://localhost/api/v1/auth/connect/session/a%2Fb");
  });
});
