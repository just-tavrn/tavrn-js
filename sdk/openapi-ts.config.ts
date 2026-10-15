// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "@hey-api/openapi-ts";

// The source is always the protocol's OpenAPI description (submodule protocol/, pinned to a tavrn-protocol tag).
// The output in src/generated/ is committed so that git-dependency consumers need no generation step: run
// `just generate` after bumping the submodule and commit the result. `just generate-check` writes to a temporary
// directory (TAVRN_SDK_GENERATED_DIR) and compares, so a stale src/generated fails the checks.
export default defineConfig({
  input: "../protocol/openapi.json",
  output: process.env.TAVRN_SDK_GENERATED_DIR || "src/generated",
  // Types only: the hand-written TavrnApi is the client (one request layer with refresh, timeouts and size caps).
  plugins: ["@hey-api/typescript"],
});
