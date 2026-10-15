// SPDX-License-Identifier: Apache-2.0
/**
 * Example bot: `/propose <idea>` posts the idea as an embed, opens a thread for the discussion and counts 👍 reactions;
 * at the threshold it marks the proposal accepted (edits the embed) and says so in the thread. Its presence shows what
 * it does. Works in encrypted channels (embed, thread title and edits are encrypted; reactions are metadata).
 *
 *   TAVRN_BOT_NODE=http://127.0.0.1:8080 TAVRN_BOT_TOKEN=<app token> \
 *   TAVRN_BOT_KEY_FILE=./tavrn-key-proposals.txt TAVRN_BOT_STATE_DIR=./.tavrn-state-proposals \
 *   pnpm --filter @tavrn/bot example:proposals
 *
 * Scopes: messages:read, messages:write, commands, presence. See README.md next to this file.
 */
import { createBot, threadTitle } from "../../src";
import { SUPPORT, countSupport, proposalEmbed, type Proposal } from "./tally";

function env(name: string, fallback?: string): string {
  const v = process.env[name]?.trim() || fallback;
  if (!v) {
    console.error(`${name} is not set (see bot/examples/proposals/README.md)`);
    process.exit(2);
  }
  return v;
}

const threshold = Math.max(1, Number(process.env.TAVRN_BOT_THRESHOLD ?? 3) || 3);
const bot = createBot({
  node: env("TAVRN_BOT_NODE"),
  token: env("TAVRN_BOT_TOKEN"),
  key: process.env.TAVRN_BOT_KEY ?? null,
  keyFile: process.env.TAVRN_BOT_KEY_FILE ?? null,
  stateDir: env("TAVRN_BOT_STATE_DIR", ".tavrn-state"),
});

/** Open proposals by message id (in memory: a restart forgets them). */
const proposals = new Map<string, Proposal>();

bot.command("propose", async (i) => {
  const idea = String(i.args.idea ?? "").trim();
  if (!idea) {
    await i.error("Tell me the idea: /propose idea:<text>");
    return;
  }
  await i.defer({ ephemeral: true });
  const by = i.user;
  const message = await bot.send(i.conversation, { type: "text", body: "", embeds: [proposalEmbed({ idea, by, supporters: 0, accepted: false }, threshold)] }, { threadId: i.threadId });
  await bot.react(i.conversation, message.id, SUPPORT);
  const thread = await bot.createThread(i.conversation, { title: threadTitle(idea), rootMessageId: message.id });
  // The bot's own 👍 counts towards the tally; people need `threshold` including it.
  proposals.set(message.id, { messageId: message.id, conversation: i.conversation, threadId: thread.id, idea, by, supporters: 1, accepted: false });
  await i.followUp(`Posted. Discuss it in the thread "${thread.title ?? idea}".`);
});

bot.onReaction(async (r) => {
  const p = proposals.get(r.messageId);
  if (!p) return;
  const { proposal, reached } = countSupport(p, r.emoji, r.count, threshold);
  proposals.set(p.messageId, proposal);
  if (!reached) return;
  await bot.edit(p.conversation, p.messageId, { type: "text", body: "", embeds: [proposalEmbed(proposal, threshold)] });
  await bot.send(p.conversation, `Accepted with ${proposal.supporters} ${SUPPORT}. Next step: a volunteer writes it up here.`, { threadId: p.threadId });
});

bot.on("error", (e) => bot.logger.error("bot error", { error: e }));

const shutdown = async () => {
  await bot.stop();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());

await bot.start();
await bot.setCommands([
  {
    name: "propose",
    description: "Propose an idea; it is accepted when enough people react with 👍",
    args: [{ name: "idea", description: "The idea", type: "string", required: true, max_length: 1000 }],
  },
] as never);
// Presence needs the scope `presence`; without it the bot runs anyway.
await bot.setPresence({ customStatus: { text: `Counting ${SUPPORT} (${threshold} needed)` } }).catch((e: unknown) => bot.logger.warn("presence not set", { error: e }));
await bot.setActivity({ type: "watching", name: "the proposals" }).catch(() => undefined);
console.log(`ready ${bot.info.address}`);
