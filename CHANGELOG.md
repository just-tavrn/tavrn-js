# Changelog

Changes of `@tavrn/sdk`, `@tavrn/e2ee` and `@tavrn/bot`, newest first. The three packages share one version; the
tags of this repository are `vX.Y.Z`. The protocol they implement is versioned separately in
[tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol/blob/main/CHANGELOG.md).

## Unreleased

First public release, published to npm (with provenance). `@tavrn/crypto` becomes a version range of the published
package instead of a git dependency.

- **`@tavrn/sdk`**: `rooms.preview(roomId)` (`GET /rooms/{room_id}/preview`: room, rules, privacy notice and legal
  notice before joining) and the room's `privacy_notice` / `legal_notice` in `rooms.update` (protocol PROTOCOL.md
  §6b); `InvitePreview` carries the documents too.
- **`@tavrn/sdk`**: typed HTTP client generated from the protocol's `openapi.json` with hand-written wrappers
  (threads and forum posts, moderation and reports, web push, age assurance, files channels, history restore,
  layered permissions, voice moves and `/users/me/voice`), the WebSocket client with reconnection, permission
  evaluation, federation discovery, hook and directory signature checks, JCS.
- **`@tavrn/e2ee`**: MLS session manager across nodes with the state shared between browser tabs, account and
  device setup, recovery keys and passkeys, key storage, message, attachment and command codecs with signed context,
  encrypted files channels, history keys for new members (sealed per recipient device, including members who open a
  channel only after their room join) and history restore after a key reset, sealed webhooks, the encrypted local
  search index.
- **`@tavrn/bot`**: the bot runtime for Node.js (its own key file, full encryption membership, events, commands,
  replies in threads, signed answers to interactions, token rotation, installations on other nodes) and the example
  bots.

### Changed

- **`@tavrn/e2ee` costs per message**: `decrypt` makes one call into the crypto core (the core compares the attested
  key with the author's leaf, §3.3) instead of `hasGroup`, `roster` and `decryptContent`, and the core keeps its
  groups loaded; `contentHeader` reads the 28 header characters in JavaScript; `encrypt` takes the epoch from the
  encryption.
- **Bounded session caches**: decrypted messages and plaintext signature checks keep at most `DECRYPT_CACHE_LIMIT`
  (5000) results. A decryption result is keyed by message id, author, device and epoch, with a (non-cryptographic)
  fingerprint of the ciphertext instead of the ciphertext itself; a signature check is keyed by message id and
  signature with the SHA-256 of the signed input. Message nonces of the replay rule are kept for the last
  `NONCE_WINDOW` (50,000) messages; a re-render with the same, unchanged envelope objects does not canonicalize
  plaintext messages again.
- **A failed device lookup is no verdict**: `decrypt` answers the new reason `retry` (not cached) instead of a
  permanent `invalid` when the author's keys cannot be fetched; the bot runtime tries such a message once more.
- **Background writes**: failed `saveMeta` writes are reported through the new `onError` option instead of unhandled
  rejections (which ended a Node.js process); the bot runtime logs them and stops with `BotError("state_unwritable")`
  after three in a row.
- **Attachments** are encrypted and decrypted with WebCrypto AES-GCM (same format, checked against the `file` vector):
  no copy of the file through the WebAssembly memory, which never shrinks.
- **History keys**: each key is checked with one decryption (`decryptContentWithKey`, no throwaway MLS client and
  device key per epoch), and up to six epochs are checked at once.
- **Identity chains**: `chainKeys` verifies each continuity statement once in the crypto core (`continuityKeys`)
  instead of one chain walk per statement; chains longer than 10,000 statements are not followed.
- **`FileKeyStore`** coalesces bursts of writes: a write that has not started yet takes the newest state, so a burst
  of changes rewrites the state file once or twice instead of once per secret (two fsyncs each).
- **Replay windows** of signed command arguments and component values are swept from the oldest end instead of
  scanning the whole window on every check.

### Added

- `@tavrn/sdk`: request deadlines and abort signals. `ApiOptions.timeoutMs` (default 30 s), `transferTimeoutMs` (file
  uploads and downloads, default 10 minutes), `maxResponseBytes` (JSON answers, default 32 MiB, checked against
  `Content-Length` and while reading) and `signal`; `api.withSignal(signal)` binds every call of a client to one
  signal. Failures on the way are `TavrnApiError` with status 0 and the codes `network.timeout`, `request.aborted`,
  `response.too_large` and `request.invalid_path` (next to `network.error`). Discovery (`resolveNode`, `discoverNode`,
  `identityOfHost`: `timeoutMs`, `signal`, default `DISCOVERY_TIMEOUT_MS` = 15 s) and the hook verifier's key fetch
  (`timeoutMs`) read at most `MAX_DISCOVERY_BYTES` within their deadline.
- `@tavrn/sdk`: the upload category table of PROTOCOL.md §7a in one place, `uploads.ts`: `classifyUpload(name, type,
  head?)` (content first when the first bytes are given, then the extension, then the type, as the node does),
  `declaredCategory`, `executableKind`, `extensionOf`, `extensionsOf`, `DANGEROUS_EXTENSIONS`, `UPLOAD_HEAD_BYTES`;
  it runs the protocol's new `testvectors/upload_categories.json`. `isUlid` for canonical ULIDs.
- `@tavrn/sdk`: `TavrnSocket` watches the connection: without any frame for `livenessMs` (default 75 s, two missed
  pings of the node; 0 turns it off) it closes the connection locally (code 4000) and reconnects, which resyncs.
  `onListenerError` receives the errors of event listeners.
- `@tavrn/bot`: `requestTimeoutMs` (default 30 s per API request, rate-limit waits on top) and `stopTimeoutMs`
  (default 30 s: `stop()` no longer waits forever for a handler that never finishes); the error code
  `encryption_unavailable`.
- **Files channels for bots** (tavrn-protocol#44): `bot.files.list(channel, folder?)` (every page, decrypted and
  sorted in encrypted channels, unreadable records as `locked` entries), `get`, `download(entry)`, `upload(channel,
  { name, data | path, mime, folder, rename })`, `createFolder` and `delete` (own entries; others' with
  `rooms:manage`), and the event `files` for `files.update`. Encrypted files channels use the records and chunked
  encryption of `@tavrn/e2ee` like the web client; taken names are refused (`files.name_taken`) or numbered. The bot
  joins encrypted files channels eagerly like text channels (`JOINABLE_KINDS` includes `files`).

- **Moderation bots read the room's report inbox** (tavrn-protocol#45, `MODERATION.md` §1.4a): `bot.reports(room,
  { status, limit, before })`, `bot.report(id, node?)` and the `report` event (`bot.onReport`) for bots with
  `moderation` and "Moderate members" in the room; metadata only (`AppReport`: kind, category, target, status, counts,
  times, the reported message's id, the reporter as a pseudonym). `api.reports.roomForApp` and `api.reports.getForApp`
  in `@tavrn/sdk`. Reports stay read-only for bots.
- **Reactors** (tavrn-protocol#43, tavrn-node#83): the `reaction` event names the reactor from the node's `reaction`
  field (`user`, the new `userId`), also on messages the bot has never seen, and no longer reports the bot's own
  reactions; `bot.reactors(conversation, messageId, emoji, { after, limit })` and `api.reactions.list(conversationId,
  messageId, emoji, { after, limit })` page who reacted with an emoji (`GET /conversations/{id}/messages/{message_id}/reactions/{emoji}`).
- **Bot coverage** (`@tavrn/bot`, `bot/docs/COVERAGE.md` maps every feature a bot may use to the runtime): the typed
  `reaction` event (`bot.onReaction`, fixes #18; the reacting user once the node names it, tavrn-protocol#43) and
  `messageEdit`, `messageDelete`, `memberJoin`, `memberLeave`, `thread` and `dmRequest` events; helpers `messages`
  (history, decrypted), `edit` (re-encrypted with the signed context), `deleteMessage`, `react`/`unreact`,
  `pin`/`unpin`/`pins`, `typing`, `markRead`, files on `send` and `m.download()` (encrypted in encrypted
  conversations), `createThread`/`threads`/`thread`/`updateThread`/`archiveThread`/`deleteThread`/`followThread`
  (encrypted titles, client thread ids), `closePoll`, `rooms`/`room`/`members`/`profile`/`search`,
  `timeout`/`kick`/`ban`/`unban`/`bans`/`auditLog`, `setVoiceStatus`, `setPresence`/`setActivity`/`clearActivity`,
  `openDm`/`dm`/`acceptDm`/`declineDm` and `bot.api(node)` for the remaining routes. Inputs are checked with the
  protocol's limits (embeds, body length, presence, timeouts, reasons) before anything is sent; `429` answers are
  repeated after `Retry-After` (option `rateLimit`). New example bot `examples/proposals` (embed, thread, 👍 tally,
  edit, presence); unit tests run against a fake node (`bot/test/fake-node.ts`).
- Message components (protocol APPLICATIONS.md §5.10, capability `components.v1`): `@tavrn/sdk` `components.ts`
  (the types `Row`, `Button`, `Select`, `Modal`, `ModalInput`, `ComponentInvokeData`, `ModalSubmitData`;
  `validateComponents` and `validateModal` with the node's codes and `meta.path`, run against the protocol's
  `components.json`; `validateComponentValues`, `validateModalValues`, `readComponents` for bots' messages only),
  `api.components.invoke`, `api.interactions.submit`, and the permission `USE_COMPONENTS` (bit 40: channel-scoped,
  in the text group, in DMs, covered by no scope; `CHANNEL_SCOPED` is now `2027195138559`); `@tavrn/e2ee`
  `components.ts` (`component.values` and `modal.values` content, `encryptComponentValues`, `encryptModalValues`,
  `ComponentValuesVerifier`); `@tavrn/bot` `bot.component()`, `bot.modal()`, `ComponentInteraction`,
  `Interaction.update()` and `Interaction.modal()`, and the builders `row`, `button`, `select`, `textInput`, `modal`,
  `withComponents`.
- Polls and date polls (protocol PROTOCOL.md §7g, capability `polls.v1`): `@tavrn/sdk` `api.polls` (`vote`,
  `retract`, `votes`, `close`), `poll_closes_at` on messages, sends and edits, the `PollVote` types and the
  permission `CREATE_POLLS` (bit 39: channel-scoped, in the text group, in DMs, covered by `messages:write`, denied
  in system channels; `CHANNEL_SCOPED` is now `927683510783`); `@tavrn/e2ee` `poll.ts` (poll and vote codecs, the
  poll hash, `checkPollVote`, `tallyPoll`, `pollVisibility`) and `MlsManager.decryptPollVote` (vote records are
  decrypted for their own purpose: vote content is never a message, a message never a vote); `@tavrn/bot`
  `createPoll`, `votes`, `vote`, `retractVote` and the `pollVote` event (`onPollVote`).
- `@tavrn/sdk`: the voice session start and the voice channel status (protocol VOICE.md §5, §2a):
  `VoiceChannelState.session_started_at` and `VoiceJoin.session_started_at` (when the channel's current session
  began, `null` while it is empty), `Channel.status` with `UpdateChannelRequest.status`, and the permission
  `VOICE_STATUS` (bit 38, channel-scoped, in the voice group of the override editors, covered by `rooms:manage`;
  `CHANNEL_SCOPED` is now `377927696895`).
- `@tavrn/sdk`: screen publishers (protocol VOICE.md §4b): `voice.join`, `voice.leave`, `calls.join` and
  `calls.leave` take an optional `role` (`"device"` by default, `"screen"` for the device's screen publisher, which
  only publishes its screen share), and `VoiceParticipant.screen_of` names the device a screen publisher belongs to.
- `@tavrn/sdk`: the types of the node policy "files channels on external stores only" (protocol FILES.md §5):
  `NodeInfo.files_internal`, `Policies.files_internal`, `BackendInfo.internal_allowed`, and the store kind `none` of
  `FilesInfo.backend` / `BackendInfo.kind`.
- `@tavrn/sdk`: `BackendInfo.max_bytes` and `BackendRequest.max_bytes`, the optional limit of a files channel on an
  external store (protocol FILES.md §5); `FilesInfo.limit_bytes` is that limit for external channels.

### Changed

- `@tavrn/sdk`: every route goes through one request layer. Downloads (attachments, files, emoji, sounds, whiteboards,
  backups) and uploads now refresh the token on `401`, send `Tavrn-Client`, report network failures as
  `TavrnApiError` (never a raw `TypeError`) and pass Blobs through without copying them. An aborted upload reports
  `request.aborted` (was `upload.aborted`); `files.downloadResponse` takes an optional signal; `exchange` takes an
  optional `signal` and lost its internal retry parameters. Ids in paths are percent-encoded, and a request whose
  path would hold an empty or dot segment is refused before it is sent.
- `@tavrn/sdk`: the generated fetch client (`src/generated/client`, `core`, `client.gen.ts`) is gone; only the types
  are generated, `TavrnApi` is the client.
- `@tavrn/bot`: encrypted uploads declare the category from the file's first bytes, name and type with the SDK's
  table (`uploadCategory(name, mime, head?)`). A malformed conversation id is a `RangeError`; errors of the session
  manager surface as `BotError` (`not_member`, `encryption_unavailable`, with the `MlsError` as `cause`), node
  refusals stay `TavrnApiError`. Resyncs of a node never overlap (one more run when requested during one), rooms load
  with bounded concurrency, an unknown conversation id reloads the rooms once and is then remembered for 30 s. DMs
  claim KeyPackages for a member's missing device only while that device is due: after a claim that left it missing
  the bot waits (1 minute, doubling up to 30 minutes, or until `devices.changed`). Failures of background work are
  logged. Rate-limit waits end when the request's signal aborts.
- `just protocol` also updates a stale checkout of the protocol submodule (the pin moved), not only a missing one.
- `@tavrn/e2ee`: fewer round trips before a voice join. `ghostCheck` looks the members' devices up in parallel (one
  round trip instead of one per user); `LeafCleaner` skips the fresh lookups when the roster is unchanged since its
  last check without findings (`FRESH_REUSE_MS`, not with a pending removal of a leaf in the group); `selfUpdate` does
  not fetch the handshake log again within `CAUGHT_UP_REUSE_MS` of a complete catch-up at the same epoch (the
  `ensureJoined` right before it), an epoch conflict still brings a missed commit. `ensureJoined` and `selfUpdate`
  take `priority` (a voice join): such an operation runs before the waiting background work (group-join probes,
  Welcome processing, key uploads) instead of after it, and `ensureJoined` without a local group requests the
  Welcomes and the GroupInfo at once (one round trip less for every probe and for the first join of a new channel).

### Fixed

- `@tavrn/sdk`: `inheritedOverrideValue` (the hint of the override editors) applies the overrides of the edited layer
  (#42): the new required `InheritedInput.layer_overrides` takes them, and the `@everyone` override of that layer
  (for every subject but `@everyone`) and, for a member subject, the overrides of the member's roles apply before the
  subject's own, which is skipped. `source` (`InheritedSource`) gains `everyone` and `roles`. A category whose
  `@everyone` override denies `view_channel` showed a neutral role as allowed; the evaluation was always right.
- `@tavrn/sdk`: a socket whose token provider failed once (or whose WebSocket could not be created) never connected
  again; it retries with backoff now. A throwing event listener no longer keeps the other listeners from the event.
- `@tavrn/e2ee`: `LeafCleaner.clean` takes `noWait` for a voice join, which must not wait for the election: it joins
  a running cleanup and ends its election wait, runs at once when this device is elected and otherwise returns the new
  outcome `postponed` without committing (the caller cleans again later, in the background); `isRunning(q)` tells
  whether a cleanup runs. A voice join shared a running background cleanup and inherited up to ten seconds of its
  election wait.
- `@tavrn/e2ee`: the cleanup election counts only devices that may commit the removal and are online:
  `CleanupRequest.managers` (users who may remove departed members' leaves) and `onlineUsers` (users known to be
  online), next to the existing `online` devices; `electedFirst` takes `onlineUsers`. A lower device id of a member
  who may not remove a departed member's leaf, or of a user who is offline, held every other device back for ten
  seconds.
- `@tavrn/sdk`: `TavrnSocket` no longer leaks a live socket when `close()` (or a second `connect()`) happens while
  `getToken()` is still pending: the obsolete attempt creates no socket, a socket replaced by a newer one is closed
  and its frames are ignored. Before, a page load in React's development StrictMode or a session change could leave
  two sockets that both delivered every event (tavrn-js#26).
- `@tavrn/e2ee`: `LeafCleaner.clean` takes `urgent` for content that waits for a departed member's leaf to go: it
  skips the election wait and cuts the wait of a running cleanup short. A device that was not elected otherwise
  waited ten seconds before it removed the leaf itself, and a message sent meanwhile was refused by the ghost check
  (tavrn-web#86).
- `@tavrn/e2ee`: a device whose local key store was lost while its session lived on no longer creates a second device
  key for the same device id after a recovery-key or passkey unlock (every commit it signed was refused with "The
  commit is not from this device", tavrn-web#83). `ensureDevice` compares the local key with the device's key on the
  node and throws `E2eeError` `device_key_lost` instead, dropping a mismatching client state that earlier versions
  stored; `localDeviceLost(ctx)` tells before an unlock. Such a device needs a new device id: sign in again.

### Security

- `@tavrn/e2ee`: a cached decryption result is only returned for an envelope with the same author, device and epoch
  as the one it was decrypted for (messages, thread titles, poll votes, sealed webhook messages, `peek`, and so command
  arguments and component values of bots); any other envelope under the same id is decrypted and checked again.
- `@tavrn/e2ee`: plaintext signature results are cached under the SHA-256 of the signed input instead of a 53-bit
  non-cryptographic fingerprint, and the per-object fast path checks that the envelope was not changed in place (nested content by its
  canonical form).
- `@tavrn/bot`: DMs and group DMs are never written in plaintext, nor any conversation whose encryption group the bot
  holds or that it saw encrypted in the session, whatever the node's `encrypted` flag says: such a send, edit, poll
  vote, thread or files-channel write fails with `BotError("encryption_downgrade")` and nothing is sent. Edits follow
  the conversation, not the edited message's flag.
- `@tavrn/sdk`: binary downloads are capped (`ApiOptions.maxDownloadBytes`, default 2 GiB, and a per-call `maxBytes` on
  `attachments.download` and `files.download`); WebSocket text frames above `SocketOptions.maxFrameLength` (default
  16 Mi characters) are not parsed and the connection is replaced (the cap goes to a given `WebSocketImpl` such as
  `ws` as `maxPayload`; the platform's own WebSocket is constructed with the URL only, since a browser's constructor
  rejects that third argument). `@tavrn/bot` downloads at most
  `maxDownloadBytes` (default 256 MiB) and never more than a file's declared size; files-channel decryption refuses
  bytes after the last chunk at once.
- `@tavrn/e2ee`: keys documents with more than 100 devices, 1000 retired devices or 100 continuity statements are
  refused before any signature in them is checked (`KeysDocumentError`, kept for the lookup's lifetime).
- `@tavrn/sdk`: `reports.roomForApp` percent-encodes the room id like every other path parameter.
- `@tavrn/sdk`: the dangerous-extension list of the upload categories (protocol PROTOCOL.md §7a) gains 20 types that
  run code when opened (`chm`, `hlp`, `jnlp`, `appref-ms`, `library-ms`, `searchconnector-ms`, `diagcab`, `msu`,
  `mst`, `ps1xml`, `vb`, `ws`, `xbap`, `ade`, `adp`, `mde`, `shb`, `shs`, `iqy`, `slk`): such files are classified as
  executables whatever their declared type.
- `@tavrn/sdk`: response bodies from other nodes are read with a size cap (discovery documents, hook keys, JSON
  answers) and within a deadline.
- `@tavrn/e2ee`: key pins and verified contacts that decrypt but cannot be parsed are no longer replaced by empty
  ones (which would trust every key again without a warning): `openMlsManager` throws `E2eeError`
  `state_unreadable` and the stored blob stays.
- `@tavrn/e2ee`: content (messages, thread titles, ephemeral events) waits for an explicit `acknowledgeGhosts` while
  the roster has a ghost leaf; a ghost check alone no longer counts as shown, and `encrypt` lost `knownGhosts`.
- `@tavrn/e2ee`: a claimed KeyPackage is added only when its leaf carries the attested key and identity of its device.
- `@tavrn/e2ee`: the ghost cleanup attests a leaf key again as retired only when the account recorded that device key
  itself; leaves are removed by identity and signature key.
- `@tavrn/e2ee`: history shares are sent only in format 2 (sealed per attested recipient device); the window of an
  automatic share is bounded by the client's own knowledge of the member.
- `@tavrn/e2ee`: the plaintext signature cache keys on the signed input, so an altered envelope is verified again.
- `@tavrn/e2ee`: pins, verified contacts and own devices are kept as an encrypted trust record with the backups and
  survive a sign-out.
- `@tavrn/e2ee`: `setupAccount` refuses to replace an existing account's local data (`already_set_up`).
- `@tavrn/e2ee`: `verifyPlainAttachment` checks plaintext attachment bytes against their signed hash.
- `@tavrn/bot`: unknown devices in an encryption group follow the new `ghostPolicy` option (`strict` by default: only
  retired devices awaiting cleanup are accepted, anything else refuses with `BotError("ghost")`; `accept` sends and logs).
- The npm token and the provenance permission live only in a publish job of a protected `release` environment that
  publishes the tarballs of a credential-free build job after comparing them with the tag, without any install.
- The self-hosted bot integration job uses no Actions cache and refuses `dependabot/*` branches.
- The publication check prints only file and line of a private match, never the matching text.

