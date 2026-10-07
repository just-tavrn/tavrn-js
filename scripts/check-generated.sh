#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fails when the committed SDK types (sdk/src/generated) differ from what the protocol submodule's openapi.json
# generates. Generates into a temporary directory (TAVRN_SDK_GENERATED_DIR, read by sdk/openapi-ts.config.ts) and
# compares; nothing in the working tree changes. Fix: `just generate` and commit the result.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f protocol/openapi.json ] || { echo "protocol/openapi.json is missing: git submodule update --init protocol" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
(cd sdk && TAVRN_SDK_GENERATED_DIR="$tmp/generated" pnpm exec openapi-ts --silent)
if ! diff -r "$tmp/generated" sdk/src/generated >/dev/null; then
  diff -r "$tmp/generated" sdk/src/generated | head -n 40 >&2 || true
  echo "sdk/src/generated is out of date with protocol/openapi.json: run 'just generate' and commit" >&2
  exit 1
fi
echo "generated SDK types up to date"
