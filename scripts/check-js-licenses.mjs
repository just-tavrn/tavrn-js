// SPDX-License-Identifier: Apache-2.0
// Checks the licenses of the production dependencies of every package (@tavrn/sdk, @tavrn/e2ee, @tavrn/bot) against
// the allow-list (`pnpm licenses list --prod` per package). (A)GPL/LGPL is refused (an application embedding these
// packages must be free to choose its license); an unknown license fails until it is verified by hand and recorded
// in VERIFIED below. Development dependencies (TypeScript, Vitest, the OpenAPI generator) are not shipped.
// Usage: node scripts/check-js-licenses.mjs [--table]   (--table prints every direct dependency)
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES = ["sdk", "e2ee", "bot"];
const ALLOWED = new Set([
  "MIT", "MIT-0", "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "Zlib", "CC0-1.0",
  "Unlicense",
]);
// Packages whose metadata carries no SPDX license, verified against their license file.
const VERIFIED = {};

/** True when the SPDX expression is satisfiable with allowed licenses (OR: one side, AND: both sides). */
function allowed(expr) {
  const clean = expr.replace(/[()]/g, " ").trim();
  return clean.split(/\s+OR\s+/).some((alt) => alt.split(/\s+AND\s+/).every((l) => ALLOWED.has(l.trim())));
}

let failures = 0;
const table = process.argv.includes("--table");
for (const pkg of PACKAGES) {
  const dir = join(root, pkg);
  const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const out = execFileSync("pnpm", ["licenses", "list", "--prod", "--json"], { cwd: dir, encoding: "utf8" });
  const byLicense = JSON.parse(out || "{}");
  const direct = new Set(Object.keys(manifest.dependencies ?? {}));
  let count = 0;
  for (const [license, entries] of Object.entries(byLicense)) {
    for (const e of entries) {
      count++;
      const effective = license === "Unknown" ? VERIFIED[e.name] ?? "Unknown" : license;
      if (!allowed(effective)) {
        failures++;
        console.error(`${pkg} (${manifest.license}): ${e.name}@${e.versions.join(",")} has license '${license}', not allowed`);
      }
      if (table && direct.has(e.name)) console.log(`| ${pkg} | ${e.name} | ${e.versions.join(", ")} | ${effective} |`);
    }
  }
  if (!table) console.log(`${pkg} (${manifest.license}): ${count} production dependencies checked`);
}
if (failures > 0) {
  console.error(`JS license check failed: ${failures} dependencies with licenses outside the allow-list`);
  process.exit(1);
}
if (!table) console.log("JS licenses ok");
