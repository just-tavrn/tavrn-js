// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { checkContent } from "../src";
import { countSupport, proposalEmbed, type Proposal } from "../examples/proposals/tally";

describe("the proposals example bot", () => {
  const p: Proposal = { messageId: "M", conversation: "h.test/C", threadId: "T", idea: "Movie night", by: "alice@h.test", supporters: 1, accepted: false };

  it("accepts a proposal once the 👍 count reaches the threshold, once", () => {
    expect(countSupport(p, "🎉", 5, 3)).toEqual({ proposal: p, reached: false });
    expect(countSupport(p, "👍", 2, 3).reached).toBe(false);
    const { proposal, reached } = countSupport(p, "👍", 3, 3);
    expect(reached).toBe(true);
    expect(proposal).toMatchObject({ supporters: 3, accepted: true });
    expect(countSupport(proposal, "👍", 4, 3).reached).toBe(false);
  });

  it("builds embeds the node accepts", () => {
    checkContent({ type: "text", body: "", embeds: [proposalEmbed(p, 3)] });
    checkContent({ type: "text", body: "", embeds: [proposalEmbed({ ...p, idea: "x".repeat(1000), accepted: true }, 3)] });
  });
});
