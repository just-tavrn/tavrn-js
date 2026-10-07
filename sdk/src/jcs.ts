// SPDX-License-Identifier: Apache-2.0
/**
 * JSON Canonicalization Scheme (RFC 8785, "JCS"): the canonical text of a JSON value, used for the
 * device signatures on plaintext messages (protocol/FEDERATION.md §10.3). The Rust crate
 * `tavrn-crypto` implements the same; both pass `protocol/testvectors/federation.json`.
 *
 * - Object members are sorted by the UTF-16 code units of their names (JavaScript's default string
 *   order), arrays keep their order, no whitespace.
 * - Numbers use the ECMAScript `Number.prototype.toString` form (`1e+30`, `0.002`, `-0` → `0`);
 *   `NaN` and infinities are not JSON and are refused.
 * - Strings are escaped like `JSON.stringify` (only `"`, `\` and control characters); lone
 *   surrogates are refused because they cannot be encoded as UTF-8.
 */

/** Thrown for values that have no JSON representation. */
export class JcsError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "JcsError";
  }
}

/** Lone (unpaired) UTF-16 surrogates. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function quote(s: string): string {
  if (LONE_SURROGATE.test(s)) throw new JcsError("string contains a lone surrogate");
  return JSON.stringify(s);
}

/** Canonical JSON text of `value` (a value as produced by `JSON.parse`). */
export function jcs(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new JcsError("non-finite number");
      // ECMAScript number serialization, as required by RFC 8785 §3.2.2.3 (also maps -0 to "0").
      return JSON.stringify(value);
    case "string":
      return quote(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map((v) => jcs(v)).join(",")}]`;
      const proto = Object.getPrototypeOf(value) as unknown;
      if (proto !== Object.prototype && proto !== null) throw new JcsError("only plain objects can be canonicalized");
      const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined);
      // Default sort compares UTF-16 code units, exactly what RFC 8785 §3.2.3 asks for.
      entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return `{${entries.map(([k, v]) => `${quote(k)}:${jcs(v)}`).join(",")}}`;
    }
    default:
      throw new JcsError(`${typeof value} has no JSON representation`);
  }
}
