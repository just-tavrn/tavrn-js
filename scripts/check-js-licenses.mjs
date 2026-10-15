// SPDX-License-Identifier: Apache-2.0
// Shared script of the tavrn repositories, version 1. The source is scripts/check-js-licenses.mjs of just-tavrn/.github;
// every repository with JavaScript packages carries an identical copy (apart from the SPDX line above), and what differs
// per repository lives in scripts/js-licenses.config.mjs next to it. Change the source first, then run its
// scripts/sync-shared.sh (docs/GITHUB.md "Shared scripts"); the CI job "Shared scripts in sync" fails while a copy differs.
//
// Checks the licenses of the production dependencies (`pnpm licenses list --prod`, per package of the configuration)
// against the allow-list: the permissive licenses below plus the configuration's `allowed`. (A)GPL/LGPL is never on it.
// An SPDX expression passes when it is satisfiable with allowed licenses: OR needs one side, AND both, parentheses
// group, `X WITH Y` must be allowed as a whole; anything that does not parse fails. A package without license metadata
// ("Unknown") fails until it is verified by hand and recorded in the configuration's `verified`; `exceptions` allows a
// single package with one named license outside the list (with the reason in a comment there).
// Usage: node scripts/check-js-licenses.mjs [--table]   (--table prints every direct dependency)
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** Permissive licenses without copyleft (MPL-2.0: file-level copyleft only, used by @tavrn/crypto and @tavrn/e2ee). */
export const COMMON_ALLOWED = [
  "MIT", "MIT-0", "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "Zlib", "CC0-1.0", "Unlicense",
];

/** Splits an SPDX expression into parentheses and words. */
function tokenize(expr) {
  return expr.replace(/[()]/g, " $& ").trim().split(/\s+/).filter(Boolean);
}

/**
 * Parses an SPDX license expression (`MIT`, `(MIT OR Apache-2.0)`, `GPL-3.0-only AND (MIT OR Apache-2.0)`,
 * `Apache-2.0 WITH LLVM-exception`) into a tree of { or: [...] }, { and: [...] } and { id } nodes. AND binds tighter
 * than OR; the operators are accepted in upper or lower case. Throws on anything else.
 */
export function parseExpression(expr) {
  const tokens = tokenize(String(expr));
  let pos = 0;
  const peek = () => tokens[pos];
  const op = (t) => (t === undefined ? undefined : t.toUpperCase());
  const isOperator = (t) => ["AND", "OR", "WITH"].includes(op(t));
  const atom = () => {
    const t = tokens[pos++];
    if (t === undefined) throw new Error(`unexpected end of '${expr}'`);
    if (t === "(") {
      const inner = orExpr();
      if (tokens[pos++] !== ")") throw new Error(`missing ')' in '${expr}'`);
      return inner;
    }
    if (t === ")" || isOperator(t)) throw new Error(`unexpected '${t}' in '${expr}'`);
    if (op(peek()) === "WITH") {
      pos++;
      const exception = tokens[pos++];
      if (exception === undefined || exception === "(" || exception === ")" || isOperator(exception)) {
        throw new Error(`missing exception after WITH in '${expr}'`);
      }
      return { id: `${t} WITH ${exception}` };
    }
    return { id: t };
  };
  const andExpr = () => {
    const parts = [atom()];
    while (op(peek()) === "AND") {
      pos++;
      parts.push(atom());
    }
    return parts.length === 1 ? parts[0] : { and: parts };
  };
  const orExpr = () => {
    const parts = [andExpr()];
    while (op(peek()) === "OR") {
      pos++;
      parts.push(andExpr());
    }
    return parts.length === 1 ? parts[0] : { or: parts };
  };
  const tree = orExpr();
  if (pos !== tokens.length) throw new Error(`unexpected '${tokens[pos]}' in '${expr}'`);
  return tree;
}

/** True when the SPDX expression is satisfiable with licenses of `allowedSet`; false when it does not parse. */
export function satisfies(expr, allowedSet) {
  let tree;
  try {
    tree = parseExpression(expr);
  } catch {
    return false;
  }
  const ok = (node) => {
    if (node.or) return node.or.some(ok);
    if (node.and) return node.and.every(ok);
    return allowedSet.has(node.id);
  };
  return ok(tree);
}

/** Runs the check for the repository at `root` with its configuration; returns the number of failures. */
export function check(root, config, { table = false, log = console.log, error = console.error } = {}) {
  const allowedSet = new Set([...COMMON_ALLOWED, ...(config.allowed ?? [])]);
  const verified = config.verified ?? {};
  const exceptions = config.exceptions ?? {};
  let failures = 0;
  for (const pkg of config.packages ?? ["."]) {
    const dir = join(root, pkg);
    const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    const out = execFileSync("pnpm", ["licenses", "list", "--prod", "--json"], { cwd: dir, encoding: "utf8" });
    const byLicense = JSON.parse(out || "{}");
    const direct = new Set(Object.keys(manifest.dependencies ?? {}));
    const label = `${pkg === "." ? manifest.name : pkg} (${manifest.license})`;
    let count = 0;
    for (const [license, entries] of Object.entries(byLicense)) {
      for (const e of entries) {
        count++;
        const effective = license === "Unknown" ? (verified[e.name] ?? "Unknown") : license;
        if (!satisfies(effective, allowedSet) && exceptions[e.name] !== effective) {
          failures++;
          error(`${label}: ${e.name}@${e.versions.join(",")} has license '${license}', not allowed`);
        }
        if (table && direct.has(e.name)) log(`| ${pkg} | ${e.name} | ${e.versions.join(", ")} | ${effective} |`);
      }
    }
    if (!table) log(`${label}: ${count} production dependencies checked`);
  }
  return failures;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const config = (await import(pathToFileURL(join(root, "scripts", "js-licenses.config.mjs")).href)).default;
  const table = process.argv.includes("--table");
  const failures = check(root, config, { table });
  if (failures > 0) {
    console.error(`JS license check failed: ${failures} dependencies with licenses outside the allow-list`);
    process.exit(1);
  }
  if (!table) console.log("JS licenses ok");
}
