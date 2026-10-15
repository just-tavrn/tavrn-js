# Example: a raid planner with buttons, a select menu and a form

`/raid` posts a card with **Sign up** and **Decline** buttons, a class select menu and a button that opens a form for a
note to the raid lead (APPLICATIONS.md §5.10). Clicking updates the card in place (`update`), choosing a class answers
only the clicking member (`ephemeral`), and the form arrives as a `modal.submit` interaction.

```sh
TAVRN_BOT_NODE=http://127.0.0.1:8080 TAVRN_BOT_TOKEN=<app token> \
TAVRN_BOT_KEY_FILE=./tavrn-key-raid.txt TAVRN_BOT_STATE_DIR=./.tavrn-state \
pnpm --filter @tavrn/bot exec vite-node examples/raid-planner/index.ts
```

The application needs the scopes `commands` and `messages:write`; members need *Use buttons and menus of apps*
(`use_components`, everyone by default).
