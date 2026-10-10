// SPDX-License-Identifier: Apache-2.0
// BOT_VERSION goes into the client header (`tavrn-bot/<version>`); it must follow the version in package.json.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BOT_VERSION } from "../src";

describe("BOT_VERSION", () => {
  it("is the version of package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
    expect(BOT_VERSION).toBe(pkg.version);
  });
});
