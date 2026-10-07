// SPDX-License-Identifier: Apache-2.0
/**
 * Example bot: echoes every message that mentions it and answers `/weather <city>` with a canned forecast (no
 * network). Works in encrypted channels: the runtime makes the bot a member of their encryption groups.
 *
 *   TAVRN_BOT_NODE=http://127.0.0.1:8080 TAVRN_BOT_TOKEN=<app token> \
 *   TAVRN_BOT_KEY_FILE=./tavrn-key-echo.txt TAVRN_BOT_STATE_DIR=./.tavrn-state just bot-example
 *
 * See README.md next to this file.
 */
import { createBot } from "../../src";

function env(name: string, fallback?: string): string {
  const v = process.env[name]?.trim() || fallback;
  if (!v) {
    console.error(`${name} is not set (see bot/examples/echo-weather/README.md)`);
    process.exit(2);
  }
  return v;
}

/** The canned forecast: deterministic per city, so tests and demos can rely on it. */
export function forecast(city: string): string {
  const conditions = ["sunny", "cloudy", "rainy", "windy", "foggy"];
  const sum = [...city.toLowerCase()].reduce((n, c) => n + c.charCodeAt(0), 0);
  return `Weather in ${city}: ${12 + (sum % 15)} °C, ${conditions[sum % conditions.length]} (canned forecast)`;
}

const bot = createBot({
  node: env("TAVRN_BOT_NODE"),
  token: env("TAVRN_BOT_TOKEN"),
  key: process.env.TAVRN_BOT_KEY ?? null,
  keyFile: process.env.TAVRN_BOT_KEY_FILE ?? null,
  stateDir: env("TAVRN_BOT_STATE_DIR", ".tavrn-state"),
  joinPolicy: process.env.TAVRN_BOT_JOIN === "lazy" ? "lazy" : "eager",
});

// Echo: every message that mentions the bot, encrypted or not, is answered in the same conversation.
bot.on("message", async (m) => {
  if (!m.mentionsMe || m.authorKind !== "user") return;
  const text = m.text.replace(new RegExp(`@${bot.info.username}\\b`, "gi"), "").trim();
  await m.reply(`Echo: ${text || "…"}`);
});

// /weather <city>: a reply in the channel; `private` answers only the invoker.
bot.command("weather", async (i) => {
  const city = String(i.args.city ?? "").trim() || "nowhere";
  if (i.args.private === true) await i.ephemeral(forecast(city));
  else await i.reply(forecast(city));
});

bot.on("tokenExpiring", (e) => {
  bot.logger.warn("the app token expires soon: rotate it (bot.rotateToken()) or ask the owner for a new one", { days: e.days, expires_at: e.expiresAt });
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
    name: "weather",
    description: "Canned weather forecast for a city",
    args: [
      { name: "city", description: "City name", type: "string", required: true, max_length: 100 },
      { name: "private", description: "Answer only me", type: "boolean", required: false },
    ],
    dm_allowed: true,
  },
] as never);
// One line on stdout for scripts that wait for the bot (the runtime logs JSON lines to stderr).
console.log(`ready ${bot.info.address}`);
