# @tavrn/bot – bots for tavrn

`@tavrn/bot` is the bot runtime for Node.js (20 or newer). It turns an app token into a running bot that:

- keeps the bot's **identity** in a key file and its encryption state in a state directory,
- is a full **end-to-end encryption** member: it reads and writes encrypted channels like any device,
- delivers **messages** (decrypted) to your code and sends replies (encrypted where needed),
- answers **commands** (`/weather berlin`) with replies, "thinking…" plus follow-ups, or replies only the invoker sees,
- reacts, edits, pins, attaches files, starts threads, runs polls, moderates, opens DMs and shows its presence through
  typed helpers (["What a bot can do"](#what-a-bot-can-do), the full table in [`docs/COVERAGE.md`](docs/COVERAGE.md)),
- follows its **installations** to other nodes (federation) on its own and waits out rate limits.

The protocol behind it is [`APPLICATIONS.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/APPLICATIONS.md) (§2 tokens, §3 bot devices and encryption, §4 installation, §5
commands, §6.3 hook requests). The package builds on `@tavrn/sdk` (API client, WebSocket) and `@tavrn/e2ee` (MLS
session manager, key storage). License: Apache-2.0 (your bot may use any license; the MPL-2.0 files of
`@tavrn/crypto` and `@tavrn/e2ee` stay MPL-2.0).

## Quick start

1. **Create an application.** In the web client: settings → *Applications* → *New application*. Choose a name, a
   username for the bot (its address becomes `<username>@<your node>`), whether anybody may add it (*public*) and the
   permissions it asks for. The bot account is created with it.
2. **Create a token.** In the application, *Tokens* → *New token*. The secret is shown **once**: keep it like a
   password (an environment variable or a secret store, never in the code). Every token is a separate *device* of the
   bot (at most 5, e.g. one per shard or for staging); its scopes cap what it may do at all.
3. **Add the bot to a room.** Open the application's **add link** (`https://<node>/add/<application id>`, shown in the
   application) and pick a room where you hold *Manage room*. The consent screen shows the permissions; the bot joins
   with a role of exactly the confirmed ones. Users of other nodes can open the link in their own client
   (`/add/<domain>/<id>`).
4. **Run the bot.**

```ts
import { createBot } from "@tavrn/bot";

const bot = createBot({
  node: "https://node.example",                 // home node of the bot (URL or domain)
  token: process.env.TAVRN_BOT_TOKEN!,           // the app token
  keyFile: process.env.TAVRN_BOT_KEY_FILE,       // default ./tavrn-key-<username>.txt
  stateDir: process.env.TAVRN_BOT_STATE_DIR,     // default ./.tavrn-state
});

bot.on("message", async (m) => {
  if (m.mentionsMe) await m.reply(`You said: ${m.text}`);
});

bot.command("weather", async (i) => {
  await i.reply(`Weather in ${String(i.args.city)}: sunny`);
});

await bot.start();
await bot.setCommands([{ name: "weather", description: "Forecast", args: [{ name: "city", description: "City", type: "string", required: true }] }]);
process.on("SIGTERM", () => void bot.stop().then(() => process.exit(0)));
```

The example in [`examples/echo-weather/`](examples/echo-weather/README.md) does exactly this and runs against a
development node with `just bot-example`. [`examples/proposals/`](examples/proposals/README.md) is a community bot:
`/propose` posts an embed, opens a thread, counts 👍 reactions, edits the proposal when it is accepted and shows its
presence (`pnpm --filter @tavrn/bot example:proposals`).

Node.js 22 and newer have a global `WebSocket`. On Node.js 20 start with `--experimental-websocket` or pass
`WebSocketImpl` (e.g. `import WebSocket from "ws"`).

## Configuration

| Option | Environment (example bot) | Meaning |
|---|---|---|
| `node` | `TAVRN_BOT_NODE` | Home node: a URL (`https://node.example`, also an internal address such as `http://tavrn:8080`) or the domain. The node must be the one that issued the token. |
| `token` | `TAVRN_BOT_TOKEN` | The app token (`typ = app`). |
| `key` | `TAVRN_BOT_KEY` | The key file's text or its `key:` value; takes precedence over `keyFile`. |
| `keyFile` | `TAVRN_BOT_KEY_FILE` | Path of the key file, default `./tavrn-key-<username>.txt`. Created on the first start. |
| `stateDir` | `TAVRN_BOT_STATE_DIR` | Encrypted local state, default `./.tavrn-state`. One process and one token per directory. |
| `joinPolicy` | `TAVRN_BOT_JOIN` (`lazy`) | `eager` (default) or `lazy` joining of encryption groups, see below. |
| `logger` | | `{ debug, info, warn, error }(message, fields)`; default JSON lines on stderr (`TAVRN_BOT_DEBUG=1` adds debug). |
| `autoDeferMs` | | Commands are deferred automatically when the handler has not answered after this long (default 2000 ms; the node waits 3 s). |
| `ghostPolicy` | | `strict` (default) or `accept`: what the bot does about unknown devices in an encryption group, see "Unknown devices" below. |
| `historyBackup` | | `false` (default): no history backup on the node. `true`: back up the epoch keys (encrypted) and restore them into a fresh state directory. See "History backups" below. |
| `rateLimit` | | `429` answers (APPLICATIONS.md §2.7): by default the runtime waits the announced `Retry-After` and repeats the request (`{ retries: 3, maxWaitMs: 30000 }`); `false` hands every `429` to your code. |

These variables belong to the bot process, not to the node.

## Events and sending

| Event | Payload |
|---|---|
| `ready` | `BotInfo` (address, application, device, home domain) |
| `message` | `BotMessage`: `text`, `content`, `author`, `authorId`, `authorKind`, `mentionsMe`, `encrypted`, `conversation`, `roomId`, `threadId`, `attachments`, `editedAt`, `signature` (plaintext: the author device's signature check), `reply()`, `replyInThread()`, `react()`, `download()` |
| `undecryptable` | an encrypted message the bot could not read (sent before it joined, unknown device, …) |
| `install` / `uninstall` | the bot was added to or removed from a room (`node`, `roomId`) |
| `tokenExpiring` | the token expires in 7 or 1 days |
| `tokenRotated` | `rotateToken()` produced a new secret |
| `pollVote` | a member voted, changed or retracted a vote (`conversation`, `messageId`, `user`, `record`, `retracted`; also `bot.onPollVote(fn)`) |
| `reaction` | a reaction was added or removed: `node`, `conversation`, `messageId`, `emoji`, `count` (after the change), `added`, `user` (null while the node does not name it), `encrypted`; also `bot.onReaction(fn)` |
| `messageEdit` | somebody edited a message: the new version as a `BotMessage`, decrypted |
| `messageDelete` | a message was deleted (`conversation`, `messageId`) |
| `memberJoin` / `memberLeave` | somebody joined or left a room (`roomId`, `userId`, `user`; scope `members:read`) |
| `thread` | a thread was created, updated (title, archive, lock, counters) or deleted (`action`, `threadId`, `conversation`, `thread`) |
| `dmRequest` | somebody who is not the owner opened a DM with the bot (`conversation`, `from`); answer with `acceptDm` / `declineDm` |
| `event` | every WebSocket event of every node, unchanged |
| `error` | connection ended (`token_refused`, `replaced`), a listener failed |

`bot.send(conversation, content, { replyTo, mentions })` sends text or a content object (`{ type: "text", body,
embeds }`) to a conversation: `conversation` is the qualified id `<node>/<id>` of a received message
(`m.conversation`) or the bare id of a conversation on the home node. In encrypted conversations the content is
encrypted for the conversation's group (the bot joins first if needed) together with its signed context (the thread
and the reply the envelope carries, ENCRYPTION.md §5.2), so the node cannot move it into another thread or point it at
another message; in unencrypted ones it is sent in plaintext, signed by the bot device. The bot's own messages are not
delivered back to it. Text content is checked before anything is sent or encrypted: a body of at most 4000 characters
and valid embeds (`EmbedsInvalidError`, code `message.embeds_invalid`). `{ files }` attaches files (below).

**Threads** (PROTOCOL.md §7e): `m.threadId` names the thread a message belongs to (null in the channel itself);
`m.reply()` answers in the same thread, `bot.send(conversation, content, { threadId })` writes into a thread, and
`m.replyInThread(content, { title? })` answers in the message's thread, in the thread it already started, or in a new
thread started from it (the title, encrypted in encrypted channels, defaults to the start of the message). Threads
need no extra scope: reading falls under `messages:read`, writing under `messages:write`.

**Polls** (PROTOCOL.md §7g): a poll is a message, its votes are records next to it (one per member).

```ts
const poll = await bot.createPoll(m.conversation, {
  kind: "choice", question: "Release today?", options: ["Yes", "No", "Tomorrow"], maxChoices: 1,
}, { closesAt: new Date(Date.now() + 3600_000) });
bot.onPollVote(async (e) => {
  const { tally } = await bot.votes(e.conversation, e.messageId); // checked records, one vote per member
  if (tally.voters >= 3) await bot.send(e.conversation, `Leading: ${tally.best.join(", ")}`);
});
await bot.vote(m.conversation, poll.id, { choices: ["o1"] }); // date polls: { answers: { s1: "yes" } }
```

`createPoll` takes a `PollInput` (or a ready `{ type: "poll", … }` object) and needs the permission `create_polls`;
encrypted polls and votes are sealed for the conversation's group like messages, plaintext ones are signed by the
bot device. `votes()` verifies every record against the voter's device and the poll's hash and leaves out stale and
late votes; `retractVote()` takes the bot's vote back. Voting needs `messages:write`, reading votes `messages:read`.

## What a bot can do

Every helper takes the conversation as `bot.send` does (a qualified id `<node>/<id>`, a bare id of the home node, or a
received message/interaction); room helpers take a room the same way (`m`, `"<node>/<room id>"` or a bare id). Each
names the scope it needs; the room permissions decide where. Inputs are checked with the protocol's limits first
(`RangeError`/`TypeError`), refusals of the node arrive as `TavrnApiError` with its `code`. The complete list, with
what the node keeps closed to bots, is [`docs/COVERAGE.md`](docs/COVERAGE.md).

**Reactions** (`messages:write` to react, `messages:read` for the events). Reactions are plaintext metadata, also in
encrypted channels. The node announces changes with the new counts but not (yet, tavrn-protocol#43) who reacted, so
`user` is null and changes are computed for messages the bot has seen since it started:

```ts
bot.onReaction(async (r) => {
  if (r.emoji === "👍" && r.added && r.count >= 3) await bot.send(r.conversation, "Three 👍: accepted!", { replyTo: r.messageId });
});
await m.react("👀");                      // or bot.react(conversation, messageId, "<:party:01J…>")
await bot.unreact(m.conversation, m.id, "👀");
```

**Embeds** (APPLICATIONS.md §6.4): `{ type: "text", body: "", embeds: [{ title, description, url, color, fields,
footer, timestamp }] }`, at most 10 per message, no remote images; encrypted like the rest of the content.

**Files** (`messages:write`, `attach_files`): `send(conversation, "Report", { files: [{ name: "report.pdf", data,
mime }] })` uploads up to 10 files. In encrypted conversations each file is encrypted with its own key and only
ciphertext reaches the node (its upload category is declared from the name and type, PROTOCOL.md §7a).
`m.attachments` lists received files, `await m.download(id?)` returns `{ name, mime, size, data }`, decrypted and
checked against its hash. Files channels are not open to bots (tavrn-protocol#44).

**History, edits, deletions, pins** (`messages:read` / `messages:write`): `bot.messages(conversation, { limit, before,
after, around, threadId })` returns readable messages decrypted; `bot.edit(conversation, id, "new text")` edits the
bot's own message (encrypted again with the same signed context, or signed again); `bot.deleteMessage(...)` deletes
its own, or anybody's with `moderation` (`manage_messages`); `pin`, `unpin`, `pins`; `typing(conversation)` shows
"… is typing"; `markRead`.

**Threads** (`messages:*`; others' threads need `moderation`): besides `m.replyInThread()`,

```ts
const t = await bot.createThread(m.conversation, { title: "Release 0.4", rootMessageId: m.id }); // or a forum post: { title, content, tags }
await bot.send(t.conversation, "Checklist: …", { threadId: t.id });
const { items } = await bot.threads(m.conversation, { archived: "false" });   // titles decrypted
await bot.archiveThread(t.conversation, t.id);
await bot.updateThread(t.conversation, t.id, { title: "Release 0.4.0", locked: true });
```

Titles in encrypted channels are encrypted and bound to their thread; the runtime picks the thread id where the node
keeps client ids (`threads.client_ids`). Events: `thread`.

**Polls**: see above; `bot.closePoll(conversation, id, at?)` closes one early (author or `manage_messages`).

**Rooms and members**: `bot.rooms(node?)`, `bot.room(room)` (always allowed), `bot.members(room, { limit, after })`
(`members:read`), `bot.profile(address)`, `bot.search(room, { q })` (plaintext channels only: the node indexes no
encrypted content), events `memberJoin` / `memberLeave`.

**Moderation** (`moderation`; the room permissions still decide): `bot.timeout(room, userId, minutes, { reason })` (0
lifts it, at most 28 days), `bot.kick(room, userId)`, `bot.ban(room, "user@node" | "domain")`, `bot.unban`,
`bot.bans`, `bot.auditLog`. `userId` is the member's id on the room's node: `m.authorId`, `interaction.userId`.
Reports stay closed to bots (tavrn-protocol#45).

```ts
bot.on("message", async (m) => {
  if (/https?:\/\/scam\.example\//i.test(m.text)) {
    await bot.deleteMessage(m.conversation, m.id);
    await bot.timeout(m, m.authorId, 60, { reason: "spam link" });
  }
});
```

**Presence** (`presence`): `bot.setPresence({ status: "dnd", customStatus: { text: "Deploying", emoji: "🚀" } })`,
`bot.setActivity({ type: "watching", name: "3 servers" })`, `bot.clearActivity()`; applied on every node the bot is
connected to (presence is kept per node).

**DMs** (`dms` to open, `messages:*` to read and write): `await bot.dm("alice@node.example", "Your report is
ready")` opens (or reuses) the 1:1 DM on the home node, creates its encryption group and adds the user's devices. The
owner always gets a normal conversation, everybody else a message request under their own `dm_policy`. Requests to the
bot arrive as `dmRequest`: `acceptDm(e.conversation)` / `declineDm(e.conversation, { block })`.

**Voice channel status** (`rooms:manage`, which unlocks `voice_status`): `bot.setVoiceStatus(room, channelId, "Raid
night")`. Bots do not join voice (the runtime has no media stack).

**Everything else** the route table opens (room management, webhooks, voice moderation, invites, emojis):
`bot.api(node?)` is the `@tavrn/sdk` client with the bot's credentials on that node, e.g.
`await bot.api().webhooks.list(roomId)`. Content you write through it in encrypted channels is yours to encrypt.

**Rate limits and connections.** Requests that answer `429` are repeated after `Retry-After` (option `rateLimit`);
the WebSocket reconnects with backoff, a `resync` reloads rooms and channels, a token refused at runtime ends the bot
with `token_refused`, a replaced connection with `replaced`.

## Commands

`bot.command(name, handler)` registers a handler; `bot.setCommands([...])` announces the definitions (the same as
the owner's editor, §5.1). The handler gets an `Interaction` with `args`, `user`, `conversation`, `locale`,
`permissions` and these answers (only the first one counts, §5.7):

- `reply(content, { ephemeral?, mentions? })`: a message in the conversation (marked "used /weather"), or with
  `ephemeral` a reply only the invoker sees;
- `ephemeral(content)`: shorthand;
- `defer({ ephemeral? })`: the invoker sees "… is thinking"; then `followUp(content)` (at most 10, within 15
  minutes). `reply` after `defer` sends a follow-up;
- `error(message)`: a short notice for the invoker. The node sees it, so keep it generic.

**Threads** (PROTOCOL.md §7e): `threadId` names the thread a command was invoked in (null outside threads), and the
node puts the reply and the follow-ups there. `replyInThread(content, { title?, ephemeral?, mentions? })` answers in
that thread, or, invoked in the channel itself, starts a thread of the channel (the title, encrypted in encrypted
channels, defaults to the start of the text) and answers there; later follow-ups go there too. `reply`, `followUp`
and `replyInThread` take `{ threadId }` to answer in another thread of the conversation.

A handler that throws or never answers is answered with a generic error notice. In encrypted channels the arguments
arrive encrypted: the runtime decrypts them, checks the signature of the invoker's device and refuses arguments made
for another command, older than five minutes or replayed (§5.8); replies and follow-ups are encrypted for the channel
and sign the interaction they answer (`ctx.interaction`, ENCRYPTION.md §5.2), so the node cannot present them as the
answer to another invocation. Thread titles the runtime creates for `replyInThread` carry no signed context (the node
chooses the thread id); clients accept them as titles of older clients.
"Ephemeral" is a delivery property there, not a cryptographic one: any member of the epoch could decrypt an
ephemeral reply if the node handed it over.

## Buttons, select menus and forms

Messages of the bot can carry components (APPLICATIONS.md §5.10): up to five rows of up to five buttons or one select
menu. The client draws them from its own palette; the bot chooses only the texts, the style (`primary`, `secondary`,
`success`, `danger`, `link`) and an emoji. `bot.component(customId | RegExp, handler)` handles clicks and choices,
`bot.modal(customId | RegExp, handler)` the forms the bot opened. The handler gets the command `Interaction` with
`messageId`, `customId`, `values` (a select's choices) or `fields` (a form's input), and two more answers:
`update(content)` edits the message that carries the component, `modal(form)` opens a form on the invoker's device.
A raid planner:

```ts
import { button, createBot, modal, row, select, textInput, withComponents } from "@tavrn/bot";

const signups = new Map<string, string>(); // user → class

const card = () =>
  withComponents(
    `Raid on Friday 20:00 · ${signups.size} signed up`,
    row(
      button({ label: "Sign up", customId: "raid:signup", style: "success", emoji: "✅" }),
      button({ label: "Decline", customId: "raid:decline", style: "danger" }),
      button({ label: "Note for the lead", customId: "raid:note" }),
    ),
    row(select("raid:class", [{ label: "Tank", value: "tank", emoji: "🛡️" }, { label: "Healer", value: "healer" }, { label: "Damage", value: "dps" }], { placeholder: "Your class" })),
  );

bot.command("raid", (i) => i.reply(card()));
bot.component("raid:signup", (i) => (signups.set(i.user, signups.get(i.user) ?? "?"), i.update(card())));
bot.component("raid:decline", (i) => (signups.delete(i.user), i.update(card())));
bot.component("raid:class", (i) => (signups.set(i.user, i.values?.[0] ?? "?"), i.ephemeral(`You go as ${i.values?.[0]}.`)));
bot.component("raid:note", (i) => i.modal(modal("raid:note-form", "A note for the raid lead", textInput("note", "Note", { style: "paragraph", maxLength: 500 }))));
bot.modal("raid:note-form", (i) => i.ephemeral(`Noted: ${i.fields.note}`));
```

The builders check what they build with the node's rules and throw a `TypeError` naming the offending field. Only
the bot that wrote a message receives its interactions; `custom_id` comes back from the user's client, so treat it as
untrusted input. In encrypted channels the values arrive encrypted: the runtime decrypts them, checks the invoker's
device signature and refuses values made for another message, component or form, older than five minutes or
replayed; whether a choice is one of the select's options is the handler's check there (`validateComponentValues`
of `@tavrn/sdk` does it with the components the bot sent), because the node cannot see them. `update` encrypts the new
content with the message's thread as its signed context (pass `{ replyTo }` when the message was a reply).

## How end-to-end encryption works for bots

A bot is an ordinary participant of tavrn's encryption ([`ENCRYPTION.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/ENCRYPTION.md)):

- **Identity.** On the first start the runtime creates the bot's master secret, writes the **key file** (mode 0600,
  an existing file is never replaced) and publishes the identity key derived from it. Every later start needs the same
  key: without it the runtime stops with `key_missing` ("restore the key file or ask the owner to reset the bot
  identity"), with another one with `key_mismatch`.
- **Devices.** Every token is a device of the bot. The runtime attests the token's device (and the device's share key,
  ENCRYPTION.md §3.1) with the identity key and keeps KeyPackages uploaded, so people can add the bot to private
  channels and DMs.
- **Groups.** The bot joins the encryption group of every encrypted channel it can view (external commit) and accepts
  Welcomes for private channels and DMs. With `joinPolicy: "eager"` it joins right after an installation; with
  `"lazy"` only when it needs a channel (a message, a command, `send`), which avoids an epoch per channel in large
  rooms. A bot can never read what was sent before it joined.
- **Local state.** The MLS state lives in `stateDir/state.json`, encrypted with a key derived from the master secret:
  the directory alone is useless to a thief, the key file is the secret. Keep the directory on a persistent volume:
  without a history backup (the default) it is the only place the epoch keys of past messages live.
- **"No bots".** Channels, categories and rooms can forbid bots. The node hides such channels from bots and refuses
  their joins; clients treat a bot that is still in such a channel's group as an unknown device (ghost warning) and
  moderators' clients remove it.
- **Encrypted channels in new rooms.** Rooms created since the setting `bots_in_encrypted_channels` exists keep bots out
  of every encrypted channel unless the channel's settings say "Bots allowed" (rooms that existed before keep
  `allowed`). An installed bot therefore reaches only plaintext channels and the encrypted channels a room manager
  opened for it; the runtime joins such a channel as soon as it is opened (`channel.update`) and loses it when it is
  closed again. Every member sees in the room's welcome channel when a bot joins or leaves an encrypted channel.

### Unknown devices

Before anything is encrypted the runtime checks the conversation's group for devices that are not what their user's
identity key confirms (`ENCRYPTION.md` §4.6). People see a warning and decide; nobody watches a bot, so `ghostPolicy`
decides for it:

- `strict` (default): the leaf of a device that was confirmed and is now retired (deleted, waiting for its owner's
  cleanup) is accepted. Anything else refuses the message with `BotError("ghost")`, which names the conversation and
  the devices: a key that was never confirmed, a member whose identity key changed without a continuity chain from the
  old key (an identity reset; a rotation with a valid chain is fine), a device of a non-member. The bot sends again
  once the group is clean (the members' clients remove such devices) or the change was confirmed.
- `accept`: the message goes out anyway and every accepted device is logged as a warning. Use it only where reaching
  the conversation matters more than the guarantee that nobody else reads along.

### History backups

By default (`historyBackup: false`) the runtime keeps **no** history backup on the node: nothing is uploaded and nothing
is restored. If the state directory is lost, start the bot with a new token (a new device: the old device's key lived
only in the lost directory) and the same key file; it joins its channels again and reads only messages sent from then
on.

With `historyBackup: true` the runtime backs up the epoch keys of every conversation to the bot's home node, encrypted
with a key derived from the bot's master secret, uploads pending backups on `stop()` and restores all backups into a
fresh state directory, so the bot can read what it was entitled to before. The trade-off:

- **For it:** bots that must answer about older messages (search, summaries, moderation bots) survive a lost or
  replaced state directory, e.g. a container without a persistent volume.
- **Against it:** whoever obtains the key file (and an app token to fetch the backups) can then read the whole history
  the bot ever saw, not only what is sent after the leak; without backups a leaked key file only matters together with
  the state directory or for messages after a rejoin. Most bots react to new messages only and should keep the default.

The example bot (`examples/echo-weather`) keeps the default.

### The key file

`tavrn-key-<username>.txt` holds the master secret (`key:` line and 24 words). Whoever has it can read everything the
bot can read and impersonate the bot's devices. Keep it out of the repository, back it up like a private key,
mount it read-only into containers. There is **no recovery key** for bots: if the file is lost, the owner resets the
identity (application → *Reset identity*); the bot then creates a new key file on its next start, contacts see
"security key changed", and messages from before cannot be read any more. If the file leaked, reset the identity
**and** the tokens.

## Tokens: expiry and rotation

App tokens do not refresh; they expire after at most `TAVRN_APP_TOKEN_MAX_DAYS` (365 by default). Seven days and one
day before, the bot gets `tokenExpiring` (and the owner a notice). Two ways out:

- the owner resets the token in the application (new secret, same device and encryption state), or
- the bot calls `await bot.rotateToken()` (at most once per 24 hours): same token row and device, a new secret, the
  old one stays valid for 24 hours. The runtime switches at once and emits `tokenRotated` with the secret: store it
  where the next start reads `TAVRN_BOT_TOKEN` from.

A revoked or reset token ends the connection (`error` with `token_refused`); a second process with the same token
replaces the older connection after two (`replaced`). Run one process per token and state directory.

## Federation: installations on other nodes

A bot lives on its owner's node but can be installed in rooms of other nodes (if both nodes allow foreign bots). The
runtime lists its installations (`GET /applications/me/installations`), opens a **federated session** on every room
node (a federation token from the home node, exchanged at that node), keeps it renewed and listens there; a new
installation elsewhere (`application.install`) connects that node right away. Messages, commands and `send()` work
the same on every node; `m.node` tells where a message came from.

## Hook requests

Bots that receive requests from the node (interactions URL, event subscriptions, §6.3) verify them with
`verifyHookRequest()` / `HookVerifier`, re-exported from `@tavrn/sdk`.

## Development

```sh
pnpm --filter @tavrn/bot test          # unit tests against a fake node (test/fake-node.ts); integration tests skipped without a node binary
pnpm --filter @tavrn/bot typecheck
TAVRN_NODE_BIN=/path/to/tavrn-node pnpm --filter @tavrn/bot test   # also the tests against real nodes
```

The integration tests in `test/node/` are opt-in: they run only when `TAVRN_NODE_BIN` names a `tavrn-node` binary (a
debug build of [tavrn-node](https://github.com/just-tavrn/tavrn-node), or the binary copied out of its container
image; `just test-node` in the repository root). `test/node/harness.ts` starts it with `--dev` on a free port with
its own SQLite database (two federated nodes for the remote installation test).
