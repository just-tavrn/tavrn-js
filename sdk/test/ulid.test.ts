// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { newUlid, ulidTime } from "../src";

describe("client ULIDs (PROTOCOL.md §7e: thread ids chosen by the client)", () => {
  it("encodes the time and 80 random bits as 26 uppercase Crockford characters", () => {
    expect(newUlid(0, (b) => b.fill(0))).toBe("00000000000000000000000000");
    expect(newUlid(2 ** 48 - 1, (b) => b.fill(255))).toBe("7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
    // The reference value of the ULID specification's time part.
    expect(newUlid(1469918176385, (b) => b.fill(0)).slice(0, 10)).toBe("01ARYZ6S41");
    const now = Date.now();
    const id = newUlid(now);
    expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(ulidTime(id)).toBe(now);
    expect(new Set(Array.from({ length: 50 }, () => newUlid(now))).size).toBe(50);
  });

  it("refuses times out of range and reads only canonical ULIDs", () => {
    expect(() => newUlid(-1)).toThrow(RangeError);
    expect(() => newUlid(2 ** 48)).toThrow(RangeError);
    expect(() => newUlid(1.5)).toThrow(RangeError);
    expect(ulidTime("01ARYZ6S41TSV4RRFFQ69G5FAV")).toBe(1469918176385);
    for (const bad of ["01arYZ6S41TSV4RRFFQ69G5FAV", "01ARYZ6S41TSV4RRFFQ69G5FA", "81ARYZ6S41TSV4RRFFQ69G5FAV", "01ARYZ6S41TSV4RRFFQ69G5FAU"]) expect(ulidTime(bad)).toBeNull();
  });
});
