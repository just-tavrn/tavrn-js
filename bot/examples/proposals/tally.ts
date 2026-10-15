// SPDX-License-Identifier: Apache-2.0
/** The proposal logic of the example bot, without I/O (tested in test/examples.test.ts). */
import type { MessageEmbed } from "../../src";

export const SUPPORT = "👍";

export interface Proposal {
  messageId: string;
  conversation: string;
  threadId: string;
  idea: string;
  by: string;
  supporters: number;
  accepted: boolean;
}

/** The embed of a proposal: open (blue) or accepted (green). */
export function proposalEmbed(p: Pick<Proposal, "idea" | "by" | "supporters" | "accepted">, threshold: number): MessageEmbed {
  return {
    title: p.accepted ? "Accepted proposal" : "Proposal",
    description: p.idea,
    color: p.accepted ? 0x2ecc71 : 0x3498db,
    fields: [
      { name: "Proposed by", value: p.by, inline: true },
      { name: "Support", value: `${p.supporters} / ${threshold} ${SUPPORT}`, inline: true },
    ],
    footer: p.accepted ? "Discuss the details in the thread" : `React with ${SUPPORT} to support it`,
  };
}

/** A 👍 count changed: the new state and whether the proposal just reached the threshold. */
export function countSupport(p: Proposal, emoji: string, count: number, threshold: number): { proposal: Proposal; reached: boolean } {
  if (emoji !== SUPPORT || p.accepted) return { proposal: p, reached: false };
  const supporters = Math.max(0, count);
  const reached = supporters >= threshold;
  return { proposal: { ...p, supporters, accepted: reached }, reached };
}
