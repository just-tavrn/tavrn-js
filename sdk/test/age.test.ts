// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApi, ageOn, channelLocked, checkDateOfBirth, isAdult, isAgeError } from "../src";

function fetchMock(body: unknown, status = 200) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  });
  return { impl: impl as unknown as typeof fetch, calls };
}

describe("age.v1", () => {
  it("counts whole years from the birthday on, 29 February on 1 March", () => {
    expect(ageOn("2008-10-09", new Date("2026-10-08T12:00:00Z"))).toBe(17);
    expect(ageOn("2008-10-09", new Date("2026-10-09T00:00:00Z"))).toBe(18);
    expect(ageOn("2008-02-29", new Date("2026-02-28T23:00:00Z"))).toBe(17);
    expect(ageOn("2008-02-29", new Date("2026-03-01T00:00:00Z"))).toBe(18);
    expect(ageOn("2008-02-30", new Date("2026-03-01T00:00:00Z"))).toBeNull();
    expect(ageOn("8.2.2008", new Date())).toBeNull();
  });

  it("checks a date of birth like the node does", () => {
    const today = new Date("2026-10-09T10:00:00Z");
    expect(checkDateOfBirth("1990-05-17", 16, today)).toBeNull();
    expect(checkDateOfBirth("2010-10-09", 16, today)).toBeNull();
    expect(checkDateOfBirth("2010-10-10", 16, today)).toBe("below_minimum");
    expect(checkDateOfBirth("2026-10-10", 16, today)).toBe("invalid");
    expect(checkDateOfBirth("1899-12-31", 16, today)).toBe("invalid");
    expect(checkDateOfBirth("1990-13-01", 16, today)).toBe("invalid");
    expect(checkDateOfBirth("", 16, today)).toBe("invalid");
  });

  it("locks gated channels for everybody but adults", () => {
    const gated = { age_gate: "none", age_gate_effective: "adults_only" };
    expect(isAdult({ tier: "adult", method: "self" })).toBe(true);
    expect(isAdult({ tier: "minor", method: "self" })).toBe(false);
    expect(isAdult({ tier: "unknown", method: "none" })).toBe(false);
    expect(isAdult(undefined)).toBe(false);
    expect(channelLocked(gated, { tier: "minor", method: "self" })).toBe(true);
    expect(channelLocked(gated, null)).toBe(true);
    expect(channelLocked(gated, { tier: "adult", method: "self" })).toBe(false);
    expect(channelLocked({ age_gate_effective: "none" }, null)).toBe(false);
    expect(channelLocked({}, null)).toBe(false);
  });

  it("recognizes the age errors", () => {
    expect(isAgeError({ code: "age.restricted" })).toBe(true);
    expect(isAgeError({ code: "age.status_required" })).toBe(true);
    expect(isAgeError({ code: "room.banned" })).toBe(false);
    expect(isAgeError(null)).toBe(false);
  });

  it("sets the own date of birth and the operator's correction", async () => {
    const { impl, calls } = fetchMock({ id: "u1", age_status: { tier: "adult", method: "self" } });
    const api = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: impl });
    const me = await api.users.setDateOfBirth("1990-05-17");
    expect(me.age_status?.tier).toBe("adult");
    expect(calls[0]!.url).toBe("https://n.example/api/v1/users/me/date-of-birth");
    expect(calls[0]!.init.method).toBe("PUT");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ date_of_birth: "1990-05-17" });
    const admin = fetchMock(undefined, 204);
    const api2 = new TavrnApi({ baseUrl: "https://n.example", getToken: () => "tok", fetchImpl: admin.impl });
    await api2.admin.setDateOfBirth("u 1", null);
    expect(admin.calls[0]!.url).toBe("https://n.example/api/v1/admin/users/u%201/date-of-birth");
    expect(JSON.parse(String(admin.calls[0]!.init.body))).toEqual({ date_of_birth: null });
  });
});
