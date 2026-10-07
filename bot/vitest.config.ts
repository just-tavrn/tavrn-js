// SPDX-License-Identifier: Apache-2.0
import { configDefaults, defineConfig } from "vitest/config";

// The integration tests in test/node/ start real nodes: they run only when TAVRN_NODE_BIN names a tavrn-node binary
// (a debug build, or the binary from the node image), one file at a time with generous timeouts. Without it the unit
// tests run alone, so `just check` needs no Rust toolchain.
const nodeBin = process.env.TAVRN_NODE_BIN?.trim();
if (!nodeBin) {
  console.warn("@tavrn/bot: integration tests in test/node/ skipped (set TAVRN_NODE_BIN to a tavrn-node binary to run them)");
}

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    exclude: nodeBin ? configDefaults.exclude : [...configDefaults.exclude, "test/node/**"],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
