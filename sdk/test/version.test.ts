// SPDX-License-Identifier: Apache-2.0
// SDK_VERSION is what the package reports about itself; it must follow the version in package.json.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { SDK_VERSION } from "../src";

describe("SDK_VERSION", () => {
  it("is the version of package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
    expect(SDK_VERSION).toBe(pkg.version);
  });
});
