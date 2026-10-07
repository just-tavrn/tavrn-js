## What and why

<!-- What does this change, and why? Link the issue (Fixes #123). -->

## Checklist

- [ ] `just check` passes locally (SPDX headers, dependency licenses, generated types, typecheck, Vitest)
- [ ] Bot runtime changes: the integration tests pass against a node (`TAVRN_NODE_BIN=… just test-node`)
- [ ] Protocol changes (routes, events, wire formats) are specified in [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol) first; after bumping the `protocol` submodule, `just generate` was run and `sdk/src/generated` is committed
- [ ] New source files carry the SPDX header of their package (`Apache-2.0` in `sdk/` and `bot/`, `MPL-2.0` in `e2ee/`)
- [ ] No secrets, tokens, key files or private hosts in code, tests or logs
- [ ] I have signed the [CLA](https://github.com/just-tavrn/tavrn-js/blob/main/CLA.md) (the CLA bot asks on your first pull request)
