# @tavrn/sdk

The TypeScript client of the [tavrn protocol](https://github.com/just-tavrn/tavrn-protocol): a typed HTTP API client,
the WebSocket client, the permission logic and the helpers every client and bot needs. It runs in browsers and in
Node.js and is shared by the web client, [`@tavrn/e2ee`](../e2ee) and the bot runtime [`@tavrn/bot`](../bot).

| Module | Contents |
|---|---|
| `TavrnApi` | one instance per node: route groups (`auth`, `rooms`, `channels`, `conversations`, `keys`, `applications`, …), Problem Details as `TavrnApiError`, token refresh on 401, re-authentication on `403 auth.reauth_required` |
| `TavrnSocket` | `/api/v1/ws`: hello/ready, events, ping/pong, reconnection with backoff, token refresh on close code 4001 |
| `createRefresher` | single-flight token refresh shared between tabs (Web Locks when available) |
| permissions | `Permission` bits, `computePermissions` (roles and overrides), bot caps and app token scopes ([`permissions.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/permissions.md)) |
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

The package ships TypeScript sources (`main: src/index.ts`); the consumer's bundler or test runner compiles them.
The types in `src/generated/` are generated from the protocol's `openapi.json` with
[`@hey-api/openapi-ts`](https://heyapi.dev) and committed (see the repository README, "Generated code").

License: [Apache-2.0](LICENSE) (see [NOTICE](NOTICE)).
