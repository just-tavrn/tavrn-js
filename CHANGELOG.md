# Changelog

Changes of `@tavrn/sdk`, `@tavrn/e2ee` and `@tavrn/bot`, newest first. The three packages share one version; the
tags of this repository are `vX.Y.Z`. The protocol they implement is versioned separately in
[tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol/blob/main/CHANGELOG.md).

## Unreleased

First public release, published to npm (with provenance). `@tavrn/crypto` becomes a version range of the published
package instead of a git dependency.

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

### Added

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

### Fixed

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

