// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { threadTitle } from "../src";

describe("threadTitle (PROTOCOL.md §7e)", () => {
  it("makes one line of at most 100 characters and never an empty title", () => {
    expect(threadTitle("  Deploy\n\tfailed  again ")).toBe("Deploy failed again");
    const long = threadTitle("ä".repeat(150));
    expect(Array.from(long)).toHaveLength(100);
    expect(long.endsWith("…")).toBe(true);
    expect(threadTitle("   ")).toBe("Thread");
    expect(threadTitle("😀".repeat(100))).toBe("😀".repeat(100));
  });
});
