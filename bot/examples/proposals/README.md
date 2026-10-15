# Example bot: proposals with a 👍 tally

A small community bot built with `@tavrn/bot`:

- **`/propose <idea>`** posts the idea as an **embed**, adds the first 👍 and opens a **thread** from the message for
  the discussion;
- it follows the **reactions** (`bot.onReaction`): when the proposal has `TAVRN_BOT_THRESHOLD` 👍 (default 3, the
  bot's own included), it **edits** the embed to "Accepted proposal" and says so in the thread;
- its **presence** shows what it does (custom status and a "watching" activity).

Everything works in encrypted channels: the embed, the thread title and the edit are encrypted for the channel,
reactions are metadata the node sees anyway. Proposals are kept in memory only.

## Run it against a development node

Create an application with the scopes `messages:read`, `messages:write`, `commands` and `presence` (settings →
*Applications*), a token, and add the bot to a room (see `../echo-weather/README.md` for the steps). Then, from the
repository root:

```sh
TAVRN_BOT_NODE=http://127.0.0.1:8080 \
TAVRN_BOT_TOKEN=<the secret> \
TAVRN_BOT_KEY_FILE=./tavrn-key-proposals.txt \
TAVRN_BOT_STATE_DIR=./.tavrn-state-proposals \
TAVRN_BOT_THRESHOLD=2 \
pnpm --filter @tavrn/bot example:proposals
```

The paths are relative to `bot/`. Type `/propose idea:Movie night on Friday` in the room and react with 👍.
