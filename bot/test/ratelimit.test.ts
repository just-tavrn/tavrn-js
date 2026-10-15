// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { retryAfterMs, retryingFetch } from "../src";

describe("Retry-After (APPLICATIONS.md §2.7)", () => {
  it("reads delta seconds and HTTP dates", () => {
    const now = Date.parse("2026-10-15T10:00:00Z");
    expect(retryAfterMs("3", now)).toBe(3000);
    expect(retryAfterMs("Thu, 15 Oct 2026 10:00:05 GMT", now)).toBe(5000);
    expect(retryAfterMs("Thu, 15 Oct 2026 09:00:00 GMT", now)).toBe(0);
    expect(retryAfterMs("soon", now)).toBeNull();
    expect(retryAfterMs(null, now)).toBeNull();
  });

  it("waits and repeats a refused request, up to its limits", async () => {
    const waits: number[] = [];
    const answers = [429, 429, 200];
    const calls: string[] = [];
    const fake = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${String(input)} ${String(init?.body ?? "")}`);
      const status = answers.shift() ?? 200;
      return new Response(status === 200 ? "{}" : null, { status, headers: status === 429 ? { "Retry-After": "2" } : {} });
    }) as typeof fetch;
    const f = retryingFetch(fake, { sleep: async (ms) => void waits.push(ms) });
    expect((await f("http://h.test/x", { method: "POST", body: "{\"a\":1}" })).status).toBe(200);
    expect(waits).toEqual([2000, 2000]);
    expect(calls).toEqual(Array(3).fill('POST http://h.test/x {"a":1}'));

    // Too long a wait, or no retries left: the 429 is handed over.
    const always = (async () => new Response(null, { status: 429, headers: { "Retry-After": "120" } })) as typeof fetch;
    const waited: number[] = [];
    expect((await retryingFetch(always, { sleep: async (ms) => void waited.push(ms) })("http://h.test/x")).status).toBe(429);
    expect(waited).toEqual([]);
    const short = (async () => new Response(null, { status: 429 })) as typeof fetch;
    expect((await retryingFetch(short, { retries: 2, sleep: async (ms) => void waited.push(ms) })("http://h.test/x")).status).toBe(429);
    expect(waited).toEqual([1000, 1000]);
  });

  it("does not repeat a streamed body", async () => {
    let n = 0;
    const fake = (async () => {
      n += 1;
      return new Response(null, { status: 429, headers: { "Retry-After": "0" } });
    }) as typeof fetch;
    const body = new ReadableStream({ start: (c) => c.close() });
    expect((await retryingFetch(fake, { sleep: async () => undefined })("http://h.test/x", { method: "POST", body, duplex: "half" } as RequestInit)).status).toBe(429);
    expect(n).toBe(1);
  });
});
