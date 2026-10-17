# Licensing of tavrn-js

This repository holds three npm packages under two licenses. Each package directory carries its own license text
(and a `NOTICE` where Apache-2.0 asks for one), each `package.json` the matching `license` field, and every
hand-written source file an SPDX header (`// SPDX-License-Identifier: …`, checked by `scripts/check-spdx.sh`, part
of `just check`).

| Directory | Package | License | License files |
|---|---|---|---|
| `sdk/` | `@tavrn/sdk`: API client, WebSocket client, permissions, generated protocol types | Apache-2.0 | [sdk/LICENSE](sdk/LICENSE), [sdk/NOTICE](sdk/NOTICE) |
| `e2ee/` | `@tavrn/e2ee`: client side of the end-to-end encryption (MLS session manager, key storage, codecs, search index) | MPL-2.0 | [e2ee/LICENSE](e2ee/LICENSE) |
| `bot/` | `@tavrn/bot`: bot runtime for Node.js and the example bots in `bot/examples/` | Apache-2.0 | [bot/LICENSE](bot/LICENSE), [bot/NOTICE](bot/NOTICE) |
| everything else | workspace and build files (`package.json`, `pnpm-workspace.yaml`, `justfile`), `scripts/`, `.github/`, documentation | Apache-2.0 | [sdk/LICENSE](sdk/LICENSE) (the same text) |

`protocol/` is a git submodule of [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol) and keeps that
repository's licenses (Apache-2.0 for `openapi.json` and the test vectors, CC-BY-4.0 for the prose). The SDK types
in `sdk/src/generated/` are generated from its `openapi.json` and carry the license of `@tavrn/sdk` (Apache-2.0).

Why two licenses: `@tavrn/sdk` and `@tavrn/bot` are what every client and bot builds on, so they are permissive
(Apache-2.0, with its patent grant): your client or bot may use any license, open or proprietary. `@tavrn/e2ee`,
like the encryption core [`@tavrn/crypto`](https://github.com/just-tavrn/tavrn-crypto) it builds on, is MPL-2.0: a
file-level copyleft, so distributed modifications to its files must be available in source form, while the application that embeds it keeps its own
license. None of the packages depends on (A)GPL or LGPL code (`scripts/check-js-licenses.mjs` refuses it).

The name "tavrn" and the logo are not covered by these licenses: see [TRADEMARK.md](TRADEMARK.md). Contributions
are accepted under the [contributor license agreement](CLA.md).
