# @tavrn/sdk

The TypeScript client of the [tavrn protocol](https://github.com/just-tavrn/tavrn-protocol): a typed HTTP API client,
the WebSocket client, the permission logic and the helpers every client and bot needs. It runs in browsers and in
Node.js and is shared by the web client, [`@tavrn/e2ee`](../e2ee/README.md) and the bot runtime
[`@tavrn/bot`](../bot/README.md).

| Module | Contents |
|---|---|
| `TavrnApi` | one instance per node: route groups (`auth`, `rooms`, `channels`, `conversations`, `threads`, `keys`, `mls`, `history`, `historyRequests`, `files`, `voice`, `calls`, `invites`, `applications`, `admin`, …), Problem Details as `TavrnApiError`, token refresh on 401, re-authentication on `403 auth.reauth_required`; one request layer for JSON and binary routes with a deadline (`timeoutMs`, 30 s; `transferTimeoutMs`, 10 minutes for files), a size cap for JSON answers (`maxResponseBytes`) and for binary answers (`maxDownloadBytes`, 2 GiB, lower per download with `maxBytes`), abort signals (`signal`, `withSignal`) and percent-encoded ids |
| `TavrnSocket` | `/api/v1/ws`: hello/ready, events, ping/pong, a liveness watchdog (`livenessMs`), a frame length cap (`maxFrameLength`), reconnection with backoff, token refresh on close code 4001, isolated event listeners (`onListenerError`) |
| uploads | `classifyUpload`, `declaredCategory`, `executableKind`: the upload categories of PROTOCOL.md §7a (the node's table and order, checked against `testvectors/upload_categories.json`) for the `Tavrn-Upload-Category` of encrypted uploads and for file pickers |
| `createRefresher` | single-flight token refresh shared between tabs (Web Locks when available) |
| permissions | `Permission` bits, `computePermissions` (roles, category and channel overrides for roles and members), the channel-scoped set (`CHANNEL_SCOPED`, `isChannelScoped`), `inheritedOverrideValue` for override editors, bot caps and app token scopes ([`permissions.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/permissions.md)) |
| age | `ageOn`, `ADULT_AGE`, `AGE_ERRORS` and the age gate type: the rules of `age.v1` (PROTOCOL.md §5e) for form hints and locked channels; the node decides |
| `newUlid`, `ulidTime` | ULIDs, for ids a client chooses itself (thread ids with `threads.client_ids`) |
| federation | addresses (`parseAddress`), `discoverNode` (`.well-known/tavrn`, delegation) and node endpoints (FEDERATION.md §1) |
| `verifyHookRequest`, `HookVerifier` | signed hook requests a node sends to an application (APPLICATIONS.md §6.3) |
| `verifyListing`, `verifyDirectoryRooms` | signed listings of the node directory |
| `jcs` | RFC 8785 JSON canonicalization for plaintext signatures (FEDERATION.md §10.3) |
| WebAuthn helpers | base64url, option parsing, `credentialToJSON`, PRF output |
| types | every schema of [`openapi.json`](https://github.com/just-tavrn/tavrn-protocol/blob/main/openapi.json) (`import type { Message, RoomDetail } from "@tavrn/sdk"`) |

```ts
import { TavrnApi, TavrnSocket } from "@tavrn/sdk";

const api = new TavrnApi({ baseUrl: "https://node.example", getToken: () => token });
const rooms = await api.rooms.list();

const socket = new TavrnSocket({
  url: "wss://node.example/api/v1/ws",
  getToken: () => token,
  onEvent: (e) => console.log(e.type, e.data),
});
socket.connect();
```

A few route groups that recent protocol versions added:

| Call | Route | Protocol |
|---|---|---|
| `api.keys.putShareKey(deviceId, req)` | `PUT /users/me/devices/{id}/share-key`: the share key of a device attested before share keys existed, once | ENCRYPTION.md §3.1, `history.shares2` |
| `api.history.share`, `shares`, `ack`, `pending` | `…/history-keys`, `…/history-pending`: history shares for new members | ENCRYPTION.md §7b |
| `api.historyRequests.create`, `mine`, `cancel`, `list`, `approve`, `deny` | `/rooms/{id}/history-requests`: history restore after a key reset | ENCRYPTION.md §7b, `history.restore` |
| `api.voice.mine()` | `GET /users/me/voice`: the occupied voice channels of every room of this node the user may view, in one request | VOICE.md §5 |
| `api.invites.direct(roomId, user)` | `POST /rooms/{id}/invites/direct`: a single-use invite bound to one user of any node | FEDERATION.md §3.4 |
| `api.polls.vote`, `retract`, `votes`, `close` | `PUT`/`DELETE …/messages/{id}/poll/vote`, `GET …/poll/votes`, `PATCH …/messages/{id} { poll_closes_at }`: vote records of polls and date polls, closing a poll early (the poll itself is a message sent with `conversations.send`; contents and votes are built and checked with `@tavrn/e2ee` `poll.ts`) | PROTOCOL.md §7g, `polls.v1` |
| `api.components.invoke(conversationId, messageId, { custom_id, values })`, `api.interactions.submit(interactionId, { values })` | `POST …/messages/{id}/interactions`, `POST /interactions/{id}/submit`: buttons, select menus and modals of applications' messages; `components.ts` has the types (`Row`, `Button`, `Select`, `Modal`, …), `validateComponents`/`validateModal` with the node's error paths (`ModalInput` also includes private single-choice inputs under `components.modal_select.v1`) and `readComponents`, which yields components only on bots' messages | APPLICATIONS.md §5.10, `components.v1` |
| `api.channels.update(roomId, channelId, { status })` | `PATCH /rooms/{id}/channels/{id}`: the status line of a voice channel, with `voice_status` alone; `VoiceChannelState.session_started_at` is when the channel's session began | VOICE.md §2a, §5 |
| `api.voice.join(roomId, channelId, "screen")`, `api.calls.join(conversationId, "screen")` | the device's screen publisher, which only publishes its screen share (`leave` with `"screen"` ends it alone; `VoiceParticipant.screen_of` names its device) | VOICE.md §4b |

The package ships TypeScript sources (`main: src/index.ts`); the consumer's bundler or test runner compiles them.
The types in `src/generated/` are generated from the protocol's `openapi.json` with
[`@hey-api/openapi-ts`](https://heyapi.dev) and committed: after the protocol submodule moves, `just generate` in the
repository root regenerates them and `just generate-check` (part of `just check`) fails when they are stale (see the
repository README, "Generated code").

License: [Apache-2.0](LICENSE) (see [NOTICE](NOTICE)).
