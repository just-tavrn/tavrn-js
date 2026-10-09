// SPDX-License-Identifier: Apache-2.0
/** Thread helpers shared by messages and commands (PROTOCOL.md §7e). */

/** A thread title from free text: one line, at most 100 characters, never empty (PROTOCOL.md §7e). */
export function threadTitle(text: string): string {
  const line = Array.from(text.replace(/\s+/g, " ").trim());
  const title = line.length > 100 ? `${line.slice(0, 99).join("")}…` : line.join("");
  return title || "Thread";
}
