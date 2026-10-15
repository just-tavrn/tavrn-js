// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  findComponent,
  readComponents,
  validComponentEmoji,
  validateComponents,
  validateComponentValues,
  validateModal,
  validateModalValues,
  type Modal,
  type Row,
} from "../src/components";

interface Case {
  name: string;
  input: { components?: unknown; modal?: unknown };
  expected: { code: string; path: string } | null;
}

const doc = JSON.parse(readFileSync(new URL("../../protocol/testvectors/components.json", import.meta.url), "utf8")) as { validation: Case[] };

describe("validateComponents and validateModal", () => {
  it.each(doc.validation.map((c) => [c.name, c] as const))("protocol test vector: %s", (_, c) => {
    const issue = "modal" in c.input ? validateModal(c.input.modal) : validateComponents(c.input.components);
    expect(issue === null ? null : { code: issue.code, path: issue.path }).toEqual(c.expected);
  });
});

const rows: Row[] = [
  { type: "row", components: [
    { type: "button", style: "success", label: "Sign up", custom_id: "signup" },
    { type: "button", style: "secondary", label: "Later", custom_id: "later", disabled: true },
    { type: "button", style: "link", label: "Guide", url: "https://guide.example/" },
  ] },
  { type: "row", components: [{ type: "select", custom_id: "class", min: 1, max: 2, options: [{ label: "Tank", value: "tank" }, { label: "Healer", value: "healer" }, { label: "Damage", value: "dps" }] }] },
];

describe("validateComponentValues (the node's check 3)", () => {
  const code = (id: string, v: unknown) => validateComponentValues(rows, id, v)?.path ?? null;
  it("accepts a button without values and fitting select values", () => {
    expect(code("signup", null)).toBeNull();
    expect(code("signup", undefined)).toBeNull();
    expect(code("class", ["healer"])).toBeNull();
    expect(code("class", ["dps", "tank"])).toBeNull();
  });
  it("refuses unknown, disabled and link components", () => {
    expect(code("nope", null)).toBe("custom_id");
    expect(code("later", null)).toBe("custom_id");
    expect(code("", null)).toBe("custom_id");
  });
  it("refuses values that do not fit", () => {
    expect(code("signup", [])).toBe("values");
    expect(code("class", null)).toBe("values");
    expect(code("class", [])).toBe("values");
    expect(code("class", ["tank", "healer", "dps"])).toBe("values");
    expect(code("class", ["tank", "mage"])).toBe("values[1]");
    expect(code("class", ["tank", "tank"])).toBe("values[1]");
    expect(validateComponentValues(rows, "class", [1])?.code).toBe("component.values_invalid");
  });
  it("finds components but never link buttons", () => {
    expect(findComponent(rows, "class")?.type).toBe("select");
    expect(findComponent(null, "class")).toBeUndefined();
  });
});

describe("validateModalValues", () => {
  const modal: Modal = { custom_id: "m", title: "Note", inputs: [
    { custom_id: "note", label: "Note", style: "paragraph", max_length: 10, required: false },
    { custom_id: "name", label: "Name", style: "short", min_length: 2 },
  ] };
  const path = (v: unknown) => validateModalValues(modal, v)?.path ?? null;
  it("accepts filled required inputs and absent or empty optional ones", () => {
    expect(path({ name: "Al" })).toBeNull();
    expect(path({ name: "Al", note: "" })).toBeNull();
    expect(path({ name: "Al", note: "line\nline" })).toBeNull();
  });
  it("names the offending input", () => {
    expect(path(null)).toBe("values");
    expect(path({})).toBe("values.name");
    expect(path({ name: "A" })).toBe("values.name");
    expect(path({ name: "Al", note: "x".repeat(11) })).toBe("values.note");
    expect(path({ name: "Al", extra: "x" })).toBe("values.extra");
    expect(path({ name: 5 })).toBe("values.name");
    expect(validateModalValues(modal, {})?.code).toBe("interaction.values_invalid");
  });
});

describe("readComponents", () => {
  const content = { type: "text", body: "", components: rows };
  it("returns the components of a bot's message only", () => {
    expect(readComponents(content, "bot")).toHaveLength(2);
    expect(readComponents(content, "user")).toEqual([]);
    expect(readComponents(content, "webhook")).toEqual([]);
    expect(readComponents({ ...content, type: "action" }, "bot")).toEqual([]);
    expect(readComponents({ ...content, components: [{ type: "row", components: [] }] }, "bot")).toEqual([]);
  });
  it("checks emojis like the node", () => {
    expect(validComponentEmoji("👍🏽")).toBe(true);
    expect(validComponentEmoji(":tada:")).toBe(true);
    expect(validComponentEmoji(":x:")).toBe(false);
    expect(validComponentEmoji("<b>")).toBe(false);
    expect(validComponentEmoji("")).toBe(false);
  });
});
