// SPDX-License-Identifier: Apache-2.0
// Every id in a request path is percent-encoded: an id with `/`, `?` or `#` can neither reach another route nor alter
// the query.
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { TavrnApi } from "../src";

const SRC = fileURLToPath(new URL("../src", import.meta.url));

describe("request paths", () => {
  it("percent-encodes the room id of the room reports of an application", async () => {
    const urls: string[] = [];
    const fetchImpl = vi.fn(async (url: string) => {
      urls.push(url);
      return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as unknown as typeof fetch;
    const api = new TavrnApi({ baseUrl: "https://n.example/", fetchImpl });
    await api.reports.roomForApp("R1?status=all#x", { limit: 5 });
    expect(urls[0]).toBe("https://n.example/api/v1/rooms/R1%3Fstatus%3Dall%23x/reports?limit=5");
  });

  it("interpolates nothing into a path template without encodeURIComponent", () => {
    const unencoded: string[] = [];
    for (const file of readdirSync(SRC).filter((f) => f.endsWith(".ts"))) {
      const source = readFileSync(join(SRC, file), "utf8");
      for (const template of source.match(/`\/[^`]*`/g) ?? []) {
        for (const part of template.match(/\$\{[^}]*\}/g) ?? []) {
          // A constant query suffix is no parameter.
          if (part.startsWith("${encodeURIComponent(") || part === '${opts.keepExternal ? "?keep_external=true" : ""}') continue;
          unencoded.push(`${file}: ${part}`);
        }
      }
    }
    expect(unencoded).toEqual([]);
  });
});
