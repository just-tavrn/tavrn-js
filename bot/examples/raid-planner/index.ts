// SPDX-License-Identifier: Apache-2.0
/**
 * Example bot: a raid planner with message components (APPLICATIONS.md §5.10). `/raid` posts a card with Sign up /
 * Decline buttons, a class select and a button that opens a form for a note to the raid lead; the card counts the
 * sign-ups and is updated in place. Works in encrypted channels too.
 *
 *   TAVRN_BOT_NODE=http://127.0.0.1:8080 TAVRN_BOT_TOKEN=<app token> \
 *   TAVRN_BOT_KEY_FILE=./tavrn-key-raid.txt TAVRN_BOT_STATE_DIR=./.tavrn-state pnpm --filter @tavrn/bot exec vite-node examples/raid-planner/index.ts
 *
 * The application needs the command `raid` (`bot.setCommands` below announces it).
 */
import { button, createBot, modal, row, select, textInput, withComponents, type Bot } from "../../src";

/** user → class ("?" until chosen). One raid per bot process keeps the example short. */
export type Signups = Map<string, string>;

/** The raid card with the current count. */
export function card(signups: Signups): Record<string, unknown> {
  return withComponents(
    `Raid on Friday 20:00 · ${signups.size} signed up`,
    row(
      button({ label: "Sign up", customId: "raid:signup", style: "success", emoji: "✅" }),
      button({ label: "Decline", customId: "raid:decline", style: "danger" }),
      button({ label: "Note for the lead", customId: "raid:note" }),
    ),
    row(
      select("raid:class", [{ label: "Tank", value: "tank", emoji: "🛡️" }, { label: "Healer", value: "healer" }, { label: "Damage", value: "dps" }], {
        placeholder: "Your class",
      }),
    ),
  );
}

/** Registers the command, component and modal handlers. */
export function register(bot: Bot, signups: Signups = new Map()): Bot {
  return bot
    .command("raid", (i) => i.reply(card(signups)))
    .component("raid:signup", (i) => {
      signups.set(i.user, signups.get(i.user) ?? "?");
      return i.update(card(signups));
    })
    .component("raid:decline", (i) => {
      signups.delete(i.user);
      return i.update(card(signups));
    })
    .component("raid:class", (i) => {
      const choice = i.values?.[0] ?? "?";
      signups.set(i.user, choice);
      return i.ephemeral(`You go as ${choice}.`);
    })
    .component("raid:note", (i) => i.modal(modal("raid:note-form", "A note for the raid lead", textInput("note", "Note", { style: "paragraph", maxLength: 500 }))))
    .modal("raid:note-form", (i) => i.ephemeral(`Noted: ${i.fields.note ?? ""}`));
}

if (process.env.TAVRN_BOT_TOKEN) {
  const bot = register(
    createBot({
      node: process.env.TAVRN_BOT_NODE ?? "http://127.0.0.1:8080",
      token: process.env.TAVRN_BOT_TOKEN,
      key: process.env.TAVRN_BOT_KEY ?? null,
      keyFile: process.env.TAVRN_BOT_KEY_FILE ?? null,
      stateDir: process.env.TAVRN_BOT_STATE_DIR ?? ".tavrn-state",
    }),
  );
  bot.on("error", (e) => bot.logger.error("bot error", { error: e }));
  await bot.start();
  await bot.setCommands([{ name: "raid", description: "Plan a raid with sign-up buttons", args: [] }]);
}
