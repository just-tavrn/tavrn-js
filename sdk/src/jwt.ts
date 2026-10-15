// SPDX-License-Identifier: Apache-2.0
/** Decoding of compact JWT parts, shared by the hook and directory verifiers. */
import { b64urlDecode } from "./webauthn";

/** UTF-8 bytes → string, without TextDecoder (whose typed-array realm checks differ between runtimes). */
export function utf8(bytes: Uint8Array): string {
  let escaped = "";
  for (const b of bytes) escaped += `%${b.toString(16).padStart(2, "0")}`;
  return decodeURIComponent(escaped);
}

/** A base64url JWT part holding a JSON object, or null. */
export function decodeJsonPart(part: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(utf8(b64urlDecode(part)));
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
