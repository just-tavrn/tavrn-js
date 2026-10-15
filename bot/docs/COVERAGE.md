# What a bot can do: protocol coverage of `@tavrn/bot`

This table maps every protocol feature a bot may use (the route table and scopes of `APPLICATIONS.md` §2.4–§2.5)
to what `@tavrn/bot` offers. **Typed** = a documented helper or event of the runtime (validated input, encryption
where the conversation needs it, errors as `BotError` / `TavrnApiError`); **raw** = reachable only through
`bot.api(node)` (the `@tavrn/sdk` client with the bot's credentials on that node) or the raw `event` stream;
**closed** = the node does not let bots do it (not in the route table, or no scope unlocks it).

"Before" is the state of the gap analysis (`@tavrn/bot` 0.2.1), "now" what this package offers. Every typed helper
has unit tests against the fake node (`test/fake-node.ts`); the encrypted paths are covered by `test/node/coverage.test.ts`
against a real node.

| Feature | Protocol | Scope | Before | Now |
|---|---|---|---|---|
| Messages: receive (decrypted), send text/content, reply, mentions | PROTOCOL.md §7, APPLICATIONS.md §3.3 | `messages:read` / `messages:write` | typed (`message`, `send`, `reply`) | typed |
| Message history (context reading) | PROTOCOL.md §6 "read markers", §7 | `messages:read` | missing (no API access at all) | typed: `messages()` |
| Message edit (own) / delete (own; others with `manage_messages`) | PROTOCOL.md §7, ENCRYPTION.md §5.2 | `messages:write` (+ `moderation`) | missing | typed: `edit()`, `deleteMessage()` |
| Edit and delete events | PROTOCOL.md §6 | `messages:read` | raw `event` only | typed: `messageEdit`, `messageDelete` |
| Reactions: add / remove | PROTOCOL.md §7 | `messages:write` | missing | typed: `react()`, `unreact()`, `m.react()` |
| Reaction events (js #18) | PROTOCOL.md §6 (`message.update`) | `messages:read` | raw `event` only; the node does not say who reacted | typed: `reaction` / `onReaction()` with the reactor (`user`, `userId`; null only from older nodes), `reactionsOf()` |
| Reactors of a message (who reacted with an emoji) | PROTOCOL.md §7 "Reactions" | `messages:read` | missing | typed: `reactors()` (paged; `api.reactions.list` in `@tavrn/sdk`) |
| Embeds | APPLICATIONS.md §6.4 | `messages:write` | content object passed through, no validation | typed: checked before sending (`checkContent`, `EmbedsInvalidError`) |
| Attachments: upload (plaintext and encrypted), download (decrypted) | PROTOCOL.md §7, §7a, ENCRYPTION.md §6 | `messages:write` / `messages:read` | missing ("not supported yet") | typed: `send(…, { files })`, `m.attachments`, `m.download()` |
| Pins: pin, unpin, list | PROTOCOL.md §7 | `messages:write` / `messages:read` | missing | typed: `pin()`, `unpin()`, `pins()` |
| Typing indicator, read marker | PROTOCOL.md §6 | `messages:write` | missing | typed: `typing()`, `markRead()` |
| Threads: reply in thread, start from a message | PROTOCOL.md §7e | `messages:*` | typed (`replyInThread`, `threadId`) | typed |
| Threads: create standalone / forum post, list, get, rename, archive, lock, delete, follow | PROTOCOL.md §7e | `messages:*` (+ `moderation` for others' threads) | missing | typed: `createThread()`, `threads()`, `thread()`, `updateThread()`, `archiveThread()`, `deleteThread()`, `followThread()` |
| Thread events | PROTOCOL.md §7e | `messages:read` | raw `event` only | typed: `thread` |
| Polls: create, vote, retract, checked votes and tally, vote events | PROTOCOL.md §7g | `messages:*`, `create_polls` | typed | typed |
| Polls: close early | PROTOCOL.md §7g | author or `manage_messages` | missing (sdk `polls.close` unreachable) | typed: `closePoll()` |
| Search | PROTOCOL.md §7d, SEARCH.md | `messages:read` | missing | typed: `search()` (plaintext channels; the node indexes no encrypted content) |
| Commands, ephemeral replies, defer, follow-ups, locale | APPLICATIONS.md §5 | `commands` | typed | typed |
| Rooms, channels, roles, member list, profiles (reads) | APPLICATIONS.md §2.4 "always", `members:read` | always / `members:read` | missing | typed: `rooms()`, `room()`, `members()`, `profile()` |
| Member join / leave events | PROTOCOL.md §6 | `members:read` | raw `event` only | typed: `memberJoin`, `memberLeave` |
| Moderation: timeout, kick, ban, unban, ban list, audit log | MODERATION.md, APPLICATIONS.md §2.4 | `moderation` | missing | typed: `timeout()`, `kick()`, `ban()`, `unban()`, `bans()`, `auditLog()` |
| Moderation: purge, nickname moderation | MODERATION.md | `moderation` | missing | raw: `bot.api(node).rooms.purge`, `.members.moderateProfile` |
| Reports: the room's inbox (read-only, metadata only; reporter as a pseudonym), report events | MODERATION.md §1.4a, §1.5 | `moderation` + `moderate_members` in the room | closed (`report.bot_forbidden`) | typed: `reports()`, `report()`, `report` / `onReport()` (tavrn-protocol#45) |
| Reports: create, triage, action shortcuts, forward, delete | MODERATION.md §1 | — | closed (`report.bot_forbidden`) | closed by design: acting on reports stays with people |
| Auto-moderation rules | MODERATION.md §2 | — | closed (not in the route table) | closed |
| Presence: status, custom status, activity | APPLICATIONS.md §7.1, PROTOCOL.md §6a | `presence` | missing | typed: `setPresence()`, `setActivity()`, `clearActivity()` (every connected node) |
| Presence of others | PROTOCOL.md §6a | `members:read` | missing | raw: `bot.api(node).presence.list()` |
| DMs: open a DM with a user, accept / decline message requests | PROTOCOL.md §8a, APPLICATIONS.md §2.5 | `dms` (+ `messages:*`) | missing (answers in DMs a user opened work) | typed: `openDm()`, `dm()`, `dmRequest`, `acceptDm()`, `declineDm()` |
| Voice channel status | VOICE.md §2a | `rooms:manage` (`voice_status`) | missing | typed: `setVoiceStatus()` |
| Voice: join with media, soundboard | VOICE.md | `voice` | closed in practice: the runtime has no media stack | closed in practice |
| Voice moderation: mute, move, disconnect | VOICE.md §7 | `moderation` | missing | raw: `bot.api(node).voice.serverMute/move/disconnect` |
| Room management: channels, roles, overrides, invites, emojis | APPLICATIONS.md §2.4 | `rooms:manage` | missing | raw: `bot.api(node).channels/roles/invites/emojis` |
| Webhooks: create, list, reset, delete (management) | APPLICATIONS.md §6.1 | `webhooks:manage` | missing | raw: `bot.api(node).webhooks` |
| Files channels | FILES.md | — | closed (`FILES.md` §2: not in the route table) | closed; proposal tavrn-protocol#44 |
| Whiteboard | WHITEBOARD.md | `whiteboard` | missing | raw (no drawing support in the runtime) |
| Hook requests (interactions URL, subscriptions) | APPLICATIONS.md §6.3 | — | typed (`verifyHookRequest`) | typed |
| Token expiry / rotation | APPLICATIONS.md §2.2 | always | typed (`tokenExpiring`, `rotateToken`) | typed |
| Rate limits (`429 Retry-After`) | APPLICATIONS.md §2.7 | — | missing: errors surface at once | typed: retried after `Retry-After` (option `rateLimit`) |
| Reconnect, resync, replaced connections | PROTOCOL.md §6, APPLICATIONS.md §2.6 | always | typed (socket backoff, resync reload, `replaced`) | typed |
| Federated installations (rooms on other nodes) | APPLICATIONS.md §2.8, §4.5 | always | typed | typed |
| Friends, blocks, group DMs, account settings | APPLICATIONS.md §2.5 | — | closed by design | closed |
