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

- The npm token and the provenance permission live only in a publish job of a protected `release` environment that
  publishes the tarballs of a credential-free build job after comparing them with the tag, without any install.
- The self-hosted bot integration job uses no Actions cache and refuses `dependabot/*` branches.
- The publication check prints only file and line of a private match, never the matching text.
