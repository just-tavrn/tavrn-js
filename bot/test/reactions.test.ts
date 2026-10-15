// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { MessageTracker, validReaction } from "../src";

describe("validReaction (PROTOCOL.md §7b, the node's rules)", () => {
  it("accepts Unicode emojis, :name: and custom emoji tokens", () => {
    for (const e of ["👍", "🎉", "👨‍👩‍👧", "✅", ":party_parrot:", "<:party:01J9ZK3G5M8Q2W4E6R8T0Y2E01>", "<:party:01J9ZK3G5M8Q2W4E6R8T0Y2E01@other.example>", "<:a1:01J9ZK3G5M8Q2W4E6R8T0Y2E01@dev.test:8443>"]) {
      expect(validReaction(e), e).toBe(true);
    }
  });
  it("refuses whitespace, control characters, long strings and malformed tokens", () => {
    for (const e of ["", " ", "two words", "a\nb", "x".repeat(17), "<:party:lowercaseid0000000000000>", "<:P:01J9ZK3G5M8Q2W4E6R8T0Y2E01>", "<:party:01J9ZK3G5M8Q2W4E6R8T0Y2E01@Bad_Host>", "<b>", "a>b"]) {
      expect(validReaction(e), JSON.stringify(e)).toBe(false);
    }
  });
});

describe("MessageTracker", () => {
  const q = "h.test/C";
  const m = (reactions: { emoji: string; count: number }[], extra: Record<string, unknown> = {}) => ({ id: "M", reactions, edited_at: null as string | null, ...extra });

  it("reports added and removed reactions against the remembered counts", () => {
    const t = new MessageTracker();
    t.remember(q, m([{ emoji: "👍", count: 1 }]));
    expect(t.update(q, m([{ emoji: "👍", count: 2 }])).reactions).toEqual([{ emoji: "👍", count: 2, added: true, user: null }]);
    expect(t.update(q, m([{ emoji: "👍", count: 2 }, { emoji: "🎉", count: 1 }])).reactions).toEqual([{ emoji: "🎉", count: 1, added: true, user: null }]);
    expect(t.update(q, m([{ emoji: "🎉", count: 1 }])).reactions).toEqual([{ emoji: "👍", count: 0, added: false, user: null }]);
    expect(t.update(q, m([{ emoji: "🎉", count: 1 }])).reactions).toEqual([]);
    expect(t.counts(q, "M")).toEqual(new Map([["🎉", 1]]));
  });

  it("reports nothing for unknown messages unless the node names the reaction, and notices edits", () => {
    const t = new MessageTracker();
    expect(t.update(q, m([{ emoji: "👍", count: 3 }]))).toEqual({ reactions: [], edited: false });
    expect(t.update(q, m([{ emoji: "👍", count: 4 }], { reaction: { emoji: "👍", user: "Alice@H.test", added: true } })).reactions).toEqual([{ emoji: "👍", count: 4, added: true, user: "alice@h.test" }]);
    expect(t.update(q, { ...m([{ emoji: "✅", count: 1 }]), id: "N", reaction: { emoji: "✅", user: "bob@h.test", added: true } }).reactions).toEqual([{ emoji: "✅", count: 1, added: true, user: "bob@h.test" }]);
    // A malformed field is ignored (the counts decide).
    expect(t.update(q, m([{ emoji: "👍", count: 5 }], { reaction: { emoji: 1 } })).reactions).toEqual([{ emoji: "👍", count: 5, added: true, user: null }]);
    expect(t.update(q, m([{ emoji: "👍", count: 5 }], { edited_at: "2026-10-15T10:00:00Z" })).edited).toBe(true);
    expect(t.update(q, m([{ emoji: "👍", count: 5 }], { edited_at: "2026-10-15T10:00:00Z" })).edited).toBe(false);
  });

  it("forgets the oldest messages beyond its size and forgotten ones", () => {
    const t = new MessageTracker(2);
    t.remember(q, { id: "A", reactions: [] });
    t.remember(q, { id: "B", reactions: [] });
    t.remember(q, { id: "C", reactions: [] });
    expect(t.counts(q, "A")).toBeNull();
    expect(t.counts(q, "C")).toEqual(new Map());
    t.forget(q, "C");
    expect(t.counts(q, "C")).toBeNull();
  });
});
