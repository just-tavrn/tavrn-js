// SPDX-License-Identifier: MPL-2.0
import init, { initSync } from "@tavrn/crypto";

let ready: Promise<void> | null = null;

/** True in Node.js (also under jsdom test environments), false in browsers and workers. */
function isNode(): boolean {
  const p = (globalThis as { process?: { versions?: { node?: unknown } } }).process;
  return typeof p?.versions?.node === "string";
}

/**
 * Node.js: reads `tavrn_crypto_bg.wasm` from the installed `@tavrn/crypto` package and instantiates it
 * synchronously. The Node built-ins are imported at run time under computed names, so that browser
 * bundlers never try to resolve them.
 */
async function loadInNode(): Promise<void> {
  const fsName = "node:fs/promises";
  const moduleName = "node:module";
  const { readFile } = (await import(/* @vite-ignore */ fsName)) as typeof import("node:fs/promises");
  const { createRequire } = (await import(/* @vite-ignore */ moduleName)) as typeof import("node:module");
  const path = createRequire(import.meta.url).resolve("@tavrn/crypto/tavrn_crypto_bg.wasm");
  initSync({ module: await readFile(path) });
}

/**
 * Loads and instantiates the WebAssembly module of `@tavrn/crypto` once, in browsers with `init()`
 * (fetches the .wasm next to the module, which bundlers emit as an asset) and in Node.js from the
 * package directory. Every function that uses the crypto package awaits this first. When the module was
 * already initialized (e.g. by a test with `initSync`), this resolves immediately.
 */
export function ensureCrypto(): Promise<void> {
  ready ??= (isNode() ? loadInNode() : init().then(() => undefined)).catch((e: unknown) => {
    ready = null;
    throw e;
  });
  return ready;
}
