# Example bot: echo and `/weather`

A small bot built with `@tavrn/bot`:

- it **echoes** every message that mentions it (`@echo hello` → `Echo: hello`), in encrypted channels too;
- it answers **`/weather <city>`** with a canned forecast (no network access); with `private: true` only the invoker
  sees the answer.

## Run it against a development node

1. Start a development node ([tavrn-node](https://github.com/just-tavrn/tavrn-node), `--dev`) and the web client
   ([tavrn-web](https://github.com/just-tavrn/tavrn-web)), sign up.
2. Settings → *Applications* → create an application (e.g. "Echo"), then a token; copy the secret.
3. Open the application's add link and add the bot to a room (its default channel is encrypted).
4. Start the bot from the repository root:

```
TAVRN_BOT_NODE=http://127.0.0.1:8080 \
TAVRN_BOT_TOKEN=<the secret> \
TAVRN_BOT_KEY_FILE=./tavrn-key-echo.txt \
TAVRN_BOT_STATE_DIR=./.tavrn-state-echo \
just bot-example
```

(`pnpm --filter @tavrn/bot example` does the same; both run in `bot/`, so relative paths are relative to `bot/`.) The
first start creates the key file and prints `ready <address>`. Mention the bot in the room or type `/weather Berlin`.

| Variable | Meaning |
|---|---|
| `TAVRN_BOT_NODE` | URL or domain of the bot's home node |
| `TAVRN_BOT_TOKEN` | the app token |
| `TAVRN_BOT_KEY_FILE` | the bot key file (created on the first start; keep it safe) |
| `TAVRN_BOT_KEY` | alternatively the key itself (`key:` value of the key file) |
| `TAVRN_BOT_STATE_DIR` | encrypted local state (default `.tavrn-state`) |
| `TAVRN_BOT_JOIN` | `lazy` to join encrypted channels only on first need |

Stop it with Ctrl-C: the runtime uploads pending history backups before it exits. See `../../README.md` for the key
file, token rotation and federation.
