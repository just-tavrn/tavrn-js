# tavrn-js

The JavaScript and TypeScript packages of [tavrn](https://github.com/just-tavrn/tavrn), a decentralized, open-source
community chat with end-to-end encryption: everything a client or a bot needs to talk to tavrn nodes, without any
user interface. The web client ([tavrn-web](https://github.com/just-tavrn/tavrn-web)) is built on them, and so are
bots.

> **Status: in private review.** Nothing is published to npm yet; until then the packages are consumed as git
> dependencies by tag (see [Installation](#installation)).

| Package | Directory | What it is for | License |
|---|---|---|---|
| [`@tavrn/sdk`](sdk) | `sdk/` | The protocol client: typed HTTP API client (types generated from the protocol's `openapi.json`), WebSocket client with reconnection, permission evaluation, federation discovery, hook and directory signature checks, JCS. Browsers and Node.js. | Apache-2.0 |
| [`@tavrn/e2ee`](e2ee) | `e2ee/` | The client side of the end-to-end encryption: MLS session manager across nodes, account and device setup, recovery keys and passkeys, key storage (in memory, or a state directory in Node.js), message, attachment and command codecs, encrypted files channels, history keys for new members (sealed to each recipient device) and history restore after a key reset, sealed webhooks, the encrypted local search index. Builds on [`@tavrn/crypto`](https://github.com/just-tavrn/tavrn-crypto) (WebAssembly). | MPL-2.0 |
| [`@tavrn/bot`](bot) | `bot/` | The bot runtime for Node.js: turns an app token into a running bot with its own key file, full end-to-end encryption membership, events, commands, token rotation and installations on other nodes. Example bots in [`bot/examples/`](bot/examples). | Apache-2.0 |

The protocol they implement lives in [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol)
([`PROTOCOL.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/PROTOCOL.md),
[`ENCRYPTION.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/ENCRYPTION.md),
[`FEDERATION.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/FEDERATION.md),
[`APPLICATIONS.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/APPLICATIONS.md)), included here as the git
submodule `protocol/`: the SDK types are generated from its `openapi.json`, and the tests check its test vectors.

## Installation

The packages ship TypeScript sources (no build step): use them through a bundler or a TypeScript-aware runner (Vite,
Vitest, esbuild, `tsx`, `vite-node`). The packages are tested on Node.js 24 (and in browsers through the web client's end-to-end suite).

During the private phase, install them from this repository by tag with pnpm (the examples use `v0.2.1`; take the
newest release tag):

```sh
pnpm add "github:just-tavrn/tavrn-js#v0.2.1&path:sdk"
```

`@tavrn/e2ee` and `@tavrn/bot` depend on their siblings (`workspace:*` inside this repository) and on the git
dependency `@tavrn/crypto`. A project that installs them from git tells pnpm where the siblings come from and allows
git dependencies below the top level (pnpm blocks them by default) in its `pnpm-workspace.yaml`:

```yaml
# Private phase: the @tavrn packages are git dependencies of each other.
blockExoticSubdeps: false
overrides:
  "@tavrn/sdk": "github:just-tavrn/tavrn-js#v0.2.1&path:sdk"
  "@tavrn/e2ee": "github:just-tavrn/tavrn-js#v0.2.1&path:e2ee"
```

```sh
pnpm add "github:just-tavrn/tavrn-js#v0.2.1&path:bot"     # or &path:e2ee
```

While the repositories are private, git needs read access to `just-tavrn` (your GitHub credentials, for example
through `gh auth setup-git`). Once the packages are on npm this becomes `pnpm add @tavrn/sdk @tavrn/e2ee @tavrn/bot`.

## Quick start: a bot

1. **Create an application** in the web client: settings → *Applications* → *New application*. The bot account
   (`<username>@<your node>`) is created with it.
2. **Create a token** in the application (*Tokens* → *New token*). The secret is shown once: keep it like a password.
3. **Add the bot to a room** through the application's add link (`https://<node>/add/<application id>`).
4. **Run the bot:**

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

The first start creates the bot's **key file**: it holds the bot's identity and is the only way to read its
encrypted channels, so back it up like a private key and never commit it. Everything else (configuration, events,
commands, encryption, history backups, token rotation, federation) is in [`bot/README.md`](bot/README.md); the
runnable example is [`bot/examples/echo-weather`](bot/examples/echo-weather/README.md) (`just bot-example`).

## Development

Requirements: Node.js 24, pnpm (the version in `package.json`, for example through `corepack enable`),
[`just`](https://github.com/casey/just), and read access to the `just-tavrn` repositories during the private phase
(the protocol submodule and `@tavrn/crypto`). No Rust toolchain: `@tavrn/crypto` comes with its built WebAssembly
module.

```sh
git clone --recurse-submodules https://github.com/just-tavrn/tavrn-js
cd tavrn-js
pnpm install
just check       # everything the CI runs: licenses, generated types, typecheck, tests
```

| Recipe | What it does |
|---|---|
| `just check` | `license-check`, `generate-check`, `typecheck`, `test` |
| `just license-check` | SPDX headers per package (`scripts/check-spdx.sh`) and the licenses of all production dependencies (`scripts/check-js-licenses.mjs`; no (A)GPL/LGPL) |
| `just generate` | regenerates `sdk/src/generated` from `protocol/openapi.json` with `@hey-api/openapi-ts` |
| `just generate-check` | fails when `sdk/src/generated` is stale (`scripts/check-generated.sh`) |
| `just typecheck`, `just test` | `tsc --noEmit` and Vitest in all three packages |
| `just test-node` | the bot runtime's integration tests against real nodes (needs `TAVRN_NODE_BIN`, see below) |
| `just pack-dry-run` | contents of the three npm tarballs |
| `just publish-check` | pre-publication hygiene (`scripts/publish-check.sh`: no private files, domains or secrets) |
| `just bot-example` | runs `bot/examples/echo-weather` against a node |

### Tests

- `@tavrn/sdk`: the API and WebSocket clients against fake servers, the permission engine against
  `protocol/testvectors/permissions.json` and `no_bots.json`, JCS against `federation.json`, hooks, directory
  listings, session refresh, WebAuthn helpers.
- `@tavrn/e2ee`: loads the WebAssembly module of `@tavrn/crypto` in Node.js and runs the session manager across
  several in-memory nodes (`test/fake-node.ts`), the account flows, both key stores, the codecs and the search index.
- `@tavrn/bot`: unit tests always; the **integration tests** in `bot/test/node/` start real `tavrn-node --dev`
  processes (two federated ones for remote installations) and are **opt-in**: they run only when `TAVRN_NODE_BIN`
  names a node binary, otherwise Vitest prints that they were skipped. Build the binary from
  [tavrn-node](https://github.com/just-tavrn/tavrn-node) (`cargo build`) or copy it out of the node's container image,
  then `TAVRN_NODE_BIN=/path/to/tavrn-node just test-node`. In the CI they run on the self-hosted test runner with
  the binary from the node image once that image is published (`docs/GITHUB.md`).

### Generated code

`sdk/src/generated/` holds the TypeScript types and the fetch client core generated from the protocol's
`openapi.json`. It is **generated, but committed**: projects that install `@tavrn/sdk` from git get no generation
step. Do not edit it by hand. After bumping the `protocol` submodule to a new tavrn-protocol tag, run
`just generate` and commit the result; `just check` (and the CI) fail when the committed files are stale.

## Releases

Versions follow the release train of the protocol (protocol, then crypto and these packages, then the node and the
web client). The three packages share one version; a tag `vX.Y.Z` on a commit whose `package.json` files carry
`X.Y.Z` makes a GitHub release with the three npm tarballs (`.github/workflows/release.yml`). Publishing to npm with
provenance is prepared and switched on when the repositories go public; the git references (`@tavrn/crypto`, the
overrides above) then become version ranges.

## Licensing

`@tavrn/sdk` and `@tavrn/bot` are [Apache-2.0](sdk/LICENSE): your client or bot may use any license. `@tavrn/e2ee`
is [MPL-2.0](e2ee/LICENSE), a file-level copyleft like the encryption core it builds on: changes to its files are
published under the MPL-2.0, the application that uses it keeps its own license. Details in [LICENSE.md](LICENSE.md);
the name "tavrn" and the logo are not covered by the licenses ([TRADEMARK.md](TRADEMARK.md)).

## Security

The encryption code has **not been audited yet**; treat it as pre-release cryptography. Please report
vulnerabilities privately through GitHub's private vulnerability reporting ("Report a vulnerability" on the Security
tab), not as public issues; see the [security policy](https://github.com/just-tavrn/.github/blob/main/SECURITY.md).

## Contributing

Contributions are welcome: see the [contributing guide](https://github.com/just-tavrn/.github/blob/main/CONTRIBUTING.md)
and the [code of conduct](https://github.com/just-tavrn/.github/blob/main/CODE_OF_CONDUCT.md). Changes to routes,
events or wire formats start in [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol). Contributions are
accepted under the [contributor license agreement](CLA.md), signed once through the CLA bot on your first pull
request. Run `just check` before opening a pull request.
