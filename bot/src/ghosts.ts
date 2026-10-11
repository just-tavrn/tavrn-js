// SPDX-License-Identifier: Apache-2.0
/**
 * Unknown devices for a client nobody watches (`ENCRYPTION.md` §4.6): the session manager refuses to encrypt while
 * the roster holds a ghost leaf nobody acknowledged. A person acknowledges in the warning; a bot follows its
 * `ghostPolicy` instead:
 *
 * - `strict` (default): leaves of devices that were attested and are now retired (deleted, their removal waiting
 *   for the owner's cleanup) are accepted; anything else refuses the message with `BotError("ghost")`: a leaf whose
 *   key was never attested, a member whose identity key changed without a verifying continuity chain, a duplicate,
 *   a non-member. Rotations with a valid chain are no violation at all.
 * - `accept`: every violation is acknowledged and logged (one warning per leaf); use it only where availability
 *   matters more than the guarantee that nobody else reads along.
 */
import { MlsError, splitIdentity, type GhostViolation, type MlsManager } from "@tavrn/e2ee";
import { b64urlEncode } from "@tavrn/sdk";
import { BotError } from "./errors";
import type { BotLogger } from "./logger";

export type GhostPolicy = "strict" | "accept";

type GhostMls = Pick<MlsManager, "unacknowledgedGhosts" | "acknowledgeGhosts" | "retiredDevice">;

function isGhostRefusal(e: unknown): boolean {
  return e instanceof MlsError && e.code === "ghost";
}

/** Whether a violation is the leaf of a device that was attested and is retired now (awaiting cleanup). */
export function retiredLeaf(mls: Pick<MlsManager, "retiredDevice">, g: GhostViolation): boolean {
  if (g.reason !== "unattested" && g.reason !== "removed") return false;
  const { address, deviceId } = splitIdentity(g.identity);
  const retired = mls.retiredDevice(address, deviceId);
  return !!retired && b64urlEncode(retired.key) === g.key;
}

/**
 * Runs `seal` (an encryption of the session manager) under the bot's ghost policy: on a refusal the leaves the policy
 * accepts are acknowledged and `seal` runs again (a few times, commits may bring more); the others refuse with
 * `BotError("ghost")` naming the conversation and the leaves.
 */
export async function sealUnderPolicy<T>(mls: GhostMls, q: string, policy: GhostPolicy, logger: BotLogger, seal: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await seal();
    } catch (e) {
      if (!isGhostRefusal(e) || attempt >= 3) throw ghostError(e, q, mls.unacknowledgedGhosts(q));
      const open = mls.unacknowledgedGhosts(q);
      const refused = policy === "accept" ? [] : open.filter((g) => !retiredLeaf(mls, g));
      if (refused.length || !open.length) throw ghostError(e, q, refused.length ? refused : open);
      for (const g of open) {
        if (policy === "accept" && !retiredLeaf(mls, g)) logger.warn("sending despite an unknown device (ghostPolicy accept)", { conversation: q, leaf: g.identity, reason: g.reason });
      }
      await mls.acknowledgeGhosts(q, open);
    }
  }
}

function ghostError(e: unknown, q: string, leaves: GhostViolation[]): unknown {
  if (!isGhostRefusal(e)) return e;
  const list = leaves.map((g) => `${g.identity} (${g.reason})`).join(", ") || "unknown";
  return new BotError("ghost", `Not sent to ${q}: the encryption group has devices this bot does not trust: ${list}. See ghostPolicy.`, { cause: e });
}
