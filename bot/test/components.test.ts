// SPDX-License-Identifier: Apache-2.0
// Message components in the bot runtime (APPLICATIONS.md §5.10) against recorded `component.invoke` and
// `modal.submit` data: routing by custom_id or pattern, update and modal answers, encrypted values, the builders.
import { describe, expect, it } from "vitest";
import { componentValuesContent, modalValuesContent, type Decrypted, type EncryptedEnvelope } from "@tavrn/e2ee";
import type { CommandCrypto, InvokeContext } from "../src/commands";
import { ComponentRouter, button, modal, row, select, selectInput, textInput, withComponents, type ComponentInteraction } from "../src/components";
import { silentLogger } from "../src/logger";

const CONV = "01J9ZK3G5M8Q2W4E6R8T0Y2CV1";
const MSG = "01J9ZK3G5M8Q2W4E6R8T0Y2MS1";

function data(over: Record<string, unknown> = {}) {
  return {
    interaction_id: "01J9ZK3G5M8Q2W4E6R8T0Y2IN1",
    application_id: "01J9ZK3G5M8Q2W4E6R8T0Y2AP1",
    message_id: MSG,
    custom_id: "raid:signup",
    values: null,
    values_ciphertext: null,
    epoch: null,
    conversation_id: CONV,
    room_id: "01J9ZK3G5M8Q2W4E6R8T0Y2RM1",
    channel_id: CONV,
    thread_id: null,
    encrypted: false,
    user: "alice@t.test",
    user_id: "01J9ZK3G5M8Q2W4E6R8T0Y2US1",
    device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2DV1",
    permissions: "3",
    locale: "de",
    expires_at: "2026-10-15T12:15:00.000Z",
    ...over,
  };
}

interface Call {
  method: string;
  path: string;
  body: Record<string, unknown>;
}

function context(crypto: CommandCrypto | null = null) {
  const calls: Call[] = [];
  const ctx: InvokeContext = {
    node: "t.test",
    appRef: "h.test/01J9ZK3G5M8Q2W4E6R8T0Y2AP1",
    deviceId: "01J9ZK3G5M8Q2W4E6R8T0Y2BD1",
    crypto,
    request: async <T>(method: string, path: string, body?: unknown) => {
      calls.push({ method, path, body: body as Record<string, unknown> });
      return { outcome: (body as Record<string, unknown>)?.type ?? "reply" } as T;
    },
  };
  return { ctx, calls };
}

const router = () => new ComponentRouter({ logger: silentLogger, autoDeferMs: 50 });

describe("ComponentRouter", () => {
  it("routes by custom_id and pattern, first match wins, and answers with update", async () => {
    const r = router();
    const seen: ComponentInteraction[] = [];
    r.component("raid:signup", async (i) => {
      seen.push(i);
      await i.update(withComponents("Raid: 1 signed up", row(button({ label: "Sign up", customId: "raid:signup", style: "success", disabled: true }))));
    });
    r.component(/^raid:/, async (i) => {
      seen.push(i);
      await i.ephemeral(`Class: ${i.values?.join(", ")}`);
    });
    const { ctx, calls } = context();
    await r.handle("component.invoke", data(), ctx);
    expect(calls[0]!.path).toBe("/interactions/01J9ZK3G5M8Q2W4E6R8T0Y2IN1/callback");
    expect(calls[0]!.body).toMatchObject({ type: "update", content: { type: "text", body: "Raid: 1 signed up" } });
    await r.handle("component.invoke", data({ custom_id: "raid:class", values: ["healer"] }), ctx);
    expect(calls[1]!.body).toMatchObject({ type: "reply", ephemeral: true, content: { body: "Class: healer" } });
    expect(seen.map((i) => [i.kind, i.messageId, i.customId])).toEqual([["component", MSG, "raid:signup"], ["component", MSG, "raid:class"]]);
    expect(seen[1]!.values).toEqual(["healer"]);
  });

  it("opens modals and routes their submits; a modal answers no modal", async () => {
    const r = router();
    r.component("raid:note", (i) => i.modal(modal("raid:note-form", "A note", textInput("note", "Note", { style: "paragraph", maxLength: 500, required: false }))).then(() => undefined));
    let submitted: ComponentInteraction | null = null;
    r.modal("raid:note-form", async (i) => {
      submitted = i;
      await expect(i.modal(modal("x", "y", textInput("a", "b")))).rejects.toThrow();
      await i.reply("Noted");
    });
    const { ctx, calls } = context();
    await r.handle("component.invoke", data({ custom_id: "raid:note" }), ctx);
    expect(calls[0]!.body).toMatchObject({ type: "modal", modal: { custom_id: "raid:note-form", inputs: [{ custom_id: "note", style: "paragraph", max_length: 500, required: false }] } });
    await r.handle("modal.submit", data({ interaction_id: "01J9ZK3G5M8Q2W4E6R8T0Y2IN2", parent_interaction_id: "01J9ZK3G5M8Q2W4E6R8T0Y2IN1", modal_custom_id: "raid:note-form", custom_id: "raid:note", values: { note: "late", junk: 5 } }), ctx);
    expect(submitted!.fields).toEqual({ note: "late" });
    expect(submitted!.parentInteractionId).toBe("01J9ZK3G5M8Q2W4E6R8T0Y2IN1");
    expect(calls.at(-1)!.body).toMatchObject({ type: "reply", content: { body: "Noted" } });
  });

  it("answers generic errors without a handler, after a throwing handler and without an answer", async () => {
    const r = router();
    r.component("boom", () => {
      throw new Error("x");
    });
    r.component("silent", () => undefined);
    const { ctx, calls } = context();
    await r.handle("component.invoke", data({ custom_id: "nope" }), ctx);
    await r.handle("component.invoke", data({ custom_id: "boom" }), ctx);
    await r.handle("component.invoke", data({ custom_id: "silent" }), ctx);
    expect(calls.map((c) => c.body.type)).toEqual(["error", "error", "error"]);
    expect(await r.handle("component.invoke", { nope: 1 }, ctx)).toBeNull();
  });

  it("decrypts and checks encrypted values; moved values are refused", async () => {
    const plain = new Map<string, Record<string, unknown>>();
    const crypto: CommandCrypto = {
      hasGroup: () => true,
      decrypt: async (_q: string, e: EncryptedEnvelope): Promise<Decrypted> => ({ ok: true, content: plain.get(String(e.content))! }),
      encrypt: async (_q, content, opts) => ({ content: `CT(${JSON.stringify({ content, opts })})`, epoch: 4 }),
      join: () => undefined,
    };
    plain.set("V1", { ...componentValuesContent(MSG, "raid:class", ["tank"]) });
    plain.set("V2", { ...componentValuesContent("01J9ZK3G5M8Q2W4E6R8T0Y2MS9", "raid:class", ["tank"]) });
    plain.set("V3", { ...modalValuesContent("01J9ZK3G5M8Q2W4E6R8T0Y2IN1", "form", { note: "x" }) });
    const r = router();
    const got: ComponentInteraction[] = [];
    r.component("raid:class", async (i) => {
      got.push(i);
      await i.update("Tank it is");
    });
    r.modal("form", async (i) => {
      got.push(i);
      await i.reply("ok");
    });
    const { ctx, calls } = context(crypto);
    await r.handle("component.invoke", data({ encrypted: true, custom_id: "raid:class", values_ciphertext: "V1", epoch: 4, thread_id: "01J9ZK3G5M8Q2W4E6R8T0Y2TH1" }), ctx);
    expect(got[0]!.values).toEqual(["tank"]);
    expect(calls[0]!.body).toMatchObject({ type: "update", epoch: 4, device_id: "01J9ZK3G5M8Q2W4E6R8T0Y2BD1" });
    expect(String(calls[0]!.body.content)).toContain('"ctx":{"thread_id":"01J9ZK3G5M8Q2W4E6R8T0Y2TH1","reply_to":null}');
    await r.handle("component.invoke", data({ encrypted: true, custom_id: "raid:class", values_ciphertext: "V2", epoch: 4 }), ctx);
    expect(calls[1]!.body.type).toBe("error");
    await r.handle("modal.submit", data({ encrypted: true, parent_interaction_id: "01J9ZK3G5M8Q2W4E6R8T0Y2IN1", modal_custom_id: "form", values_ciphertext: "V3", epoch: 4 }), ctx);
    expect(got[1]!.fields).toEqual({ note: "x" });
    expect(got).toHaveLength(2);
  });
});

describe("builders", () => {
  it("builds personal select forms without text-only limits or shared option defaults", () => {
    const input = selectInput("spec", "Paladin spec", [{ label: "Holy", value: "holy", description: "Healer", emoji: "💚" }, "Protection"], { placeholder: "Choose your spec", required: false, value: "holy" });
    expect(input).toEqual({ custom_id: "spec", label: "Paladin spec", style: "select", options: [{ label: "Holy", value: "holy", description: "Healer", emoji: "💚" }, { label: "Protection", value: "Protection" }], placeholder: "Choose your spec", required: false, value: "holy" });
    expect(modal("raid:spec", "Choose your spec", input).inputs).toEqual([input]);
    expect(() => modal("x", "Title", selectInput("spec", "Spec", []))).toThrow(/options/);
    expect(() => modal("x", "Title", selectInput("spec", "Spec", ["Holy"], { value: "nope" }))).toThrow(/value/);
  });

  it("build valid components and refuse invalid ones", () => {
    const content = withComponents(
      "Raid on Friday",
      row(button({ label: "Sign up", customId: "signup", style: "success", emoji: "✅" }), button({ label: "Decline", customId: "decline", style: "danger" }), button({ label: "Guide", url: "https://guide.example/" })),
      row(select("class", ["Tank", { label: "Healer", value: "healer", description: "Keeps everyone alive" }], { placeholder: "Your class", min: 1, max: 1 })),
    );
    expect(content).toMatchObject({ type: "text", components: [{ components: [{ style: "success" }, { style: "danger" }, { style: "link", url: "https://guide.example/" }] }, { components: [{ options: [{ value: "Tank" }, { value: "healer" }] }] }] });
    expect(() => withComponents("x", row(button({ label: "a", customId: "same" }), button({ label: "b", customId: "same" })))).toThrow(/components\[0\]\.components\[1\]\.custom_id/);
    expect(() => modal("m", "t".repeat(46), textInput("a", "b"))).toThrow(/title/);
    expect(modal("m", "Title", textInput("a", "Label", { minLength: 1, maxLength: 10, value: "pre" })).inputs[0]).toEqual({ custom_id: "a", label: "Label", style: "short", min_length: 1, max_length: 10, value: "pre" });
  });
});

describe("the raid planner example", () => {
  it("builds a valid card and registers its handlers", async () => {
    const { card, register } = await import("../examples/raid-planner/index");
    const { createBot } = await import("../src");
    const signups = new Map([["alice@t.test", "tank"]]);
    expect(card(signups)).toMatchObject({ body: "Raid on Friday 20:00 · 1 signed up" });
    const bot = createBot({ node: "http://127.0.0.1:1", token: "t" });
    expect(register(bot, signups)).toBe(bot);
  });
});
