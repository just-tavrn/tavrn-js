# tavrn-js: developer tasks. `just --list` shows all of them.

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Every check of the CI: licenses (SPDX headers, dependency licenses), generated types up to date, typecheck, tests
check: license-check generate-check typecheck test

# SPDX headers per package (scripts/check-spdx.sh, map in sync with LICENSE.md) and the licenses of the production
# dependencies of every package (scripts/check-js-licenses.mjs)
license-check: install
    scripts/check-spdx.sh
    node scripts/check-js-licenses.mjs

# Regenerate the SDK types (sdk/src/generated, committed) from the protocol submodule's openapi.json
generate: install protocol
    pnpm --filter @tavrn/sdk generate

# Fail when sdk/src/generated differs from what protocol/openapi.json generates (run `just generate` and commit)
generate-check: install protocol
    scripts/check-generated.sh

typecheck: install
    pnpm -r typecheck

# Vitest: @tavrn/sdk, @tavrn/e2ee (loads the WebAssembly module of @tavrn/crypto) and @tavrn/bot (unit tests; the
# integration tests against real nodes run only with TAVRN_NODE_BIN, see `just test-node`)
test: install protocol
    pnpm -r test

# The bot runtime's integration tests against real nodes: TAVRN_NODE_BIN must name a tavrn-node binary
test-node: install
    @[ -n "${TAVRN_NODE_BIN:-}" ] || { echo "set TAVRN_NODE_BIN to a tavrn-node binary (debug build or from the node image)" >&2; exit 1; }
    pnpm --filter @tavrn/bot test

# Contents of the three npm tarballs (nothing is written)
pack-dry-run: install
    for p in sdk e2ee bot; do (cd "$p" && pnpm pack --dry-run); done

# Pre-publication hygiene: no private files, domains or secrets (needs .publish-check.private or PUBLISH_CHECK_PRIVATE)
publish-check:
    scripts/publish-check.sh

# Run the example bot (bot/examples/echo-weather) against a node: TAVRN_BOT_NODE, TAVRN_BOT_TOKEN,
# TAVRN_BOT_KEY_FILE and TAVRN_BOT_STATE_DIR (see bot/README.md)
bot-example: install
    pnpm --filter @tavrn/bot example

# Check out the protocol submodule (openapi.json, test vectors) if it is missing
protocol:
    @[ -f protocol/openapi.json ] || git submodule update --init protocol

[private]
install:
    @[ -d node_modules/.pnpm ] || pnpm install --frozen-lockfile
