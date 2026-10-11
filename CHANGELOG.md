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
