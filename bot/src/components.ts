// SPDX-License-Identifier: Apache-2.0
/**
 * Message components for bots (APPLICATIONS.md §5.10): `bot.component(customId | RegExp, handler)` and
 * `bot.modal(customId | RegExp, handler)` register handlers; `component.invoke` and `modal.submit` events run them with
 * a {@link ComponentInteraction}, the command {@link Interaction} with the component's facts, which answers with
 * `reply`, `ephemeral`, `defer`, `error`, `update` (edit the message) or `modal` (open a form, components only). In
 * encrypted conversations the values arrive as ciphertext and are decrypted and checked like command arguments.
 *
 * The builders (`row`, `button`, `select`, `modal`, `textInput`) produce the shapes of `@tavrn/sdk`'s `components.ts`
 * and check them with the node's rules, so a mistake throws here instead of failing at the node.
 */
import { ComponentValuesVerifier, qualify } from "@tavrn/e2ee";
import { validateComponents, validateModal, type Button, type ButtonStyle, type Component, type InputStyle, type Modal, type ModalInput, type Row, type Select, type SelectOption } from "@tavrn/sdk";
import { Interaction, type CommandInvokeData, type InteractionResult, type InvokeContext } from "./commands";
import type { BotLogger } from "./logger";

/** `data` of `component.invoke` and `modal.submit` (§5.10.2, §5.10.4) as the runtime reads it. */
export interface ComponentEventData {
  interaction_id: string;
  application_id: string;
  message_id: string | null;
  custom_id: string | null;
  values: unknown;
  values_ciphertext: string | null;
  epoch: number | null;
  conversation_id: string;
  room_id: string | null;
  channel_id: string | null;
  thread_id?: string | null;
  encrypted: boolean;
  user: string;
  user_id: string;
  device_id: string | null;
  permissions: string;
  locale: string | null;
  expires_at: string;
  /** `modal.submit` only. */
  parent_interaction_id?: string;
  modal_custom_id?: string;
  command?: { id: string; name: string } | null;
}

/** A component interaction or a modal submit: an {@link Interaction} with the component's facts. */
export class ComponentInteraction extends Interaction {
  readonly kind: "component" | "modal";
  /** The message that carries the component (null for a modal opened by a command). */
  readonly messageId: string | null;
  /** The component's `custom_id` (for a modal submit: the component that opened it, if any). */
  readonly customId: string | null;
  /** Components: null for buttons, the selected option values for selects. */
  readonly values: string[] | null;
  /** Modal submits: the modal's `custom_id`, the interaction that opened it, the form's values. */
  readonly modalCustomId: string | null;
  readonly parentInteractionId: string | null;
  readonly fields: Record<string, string>;

  constructor(kind: "component" | "modal", data: ComponentEventData, values: string[] | null, fields: Record<string, string>, ctx: InvokeContext) {
    const command = data.command ?? { id: "", name: "" };
    super({ ...data, command, args: null, args_ciphertext: null } as CommandInvokeData, {}, ctx);
    this.kind = kind;
    this.messageId = data.message_id ?? null;
    this.customId = data.custom_id ?? null;
    this.values = values;
    this.modalCustomId = data.modal_custom_id ?? null;
    this.parentInteractionId = data.parent_interaction_id ?? null;
    this.fields = fields;
  }

  /** Opens a modal (component interactions only: the node refuses a modal as the answer to a modal submit). */
  override modal(m: Modal): Promise<InteractionResult> {
    if (this.kind === "modal") return Promise.reject(new TypeError("A modal cannot answer a modal submit (interaction.modal_nested)"));
    return super.modal(m);
  }
}

export type ComponentHandler = (interaction: ComponentInteraction) => void | Promise<void>;
export type Matcher = string | RegExp;

const MSG = {
  unknown: "This control is not available right now.",
  failed: "The action failed.",
  noAnswer: "The action did not answer.",
  joining: "The bot is joining this channel's encryption. Try again in a moment.",
  values: "The input could not be verified.",
};

function isEvent(data: unknown): data is ComponentEventData {
  if (!data || typeof data !== "object") return false;
  const d = data as Record<string, unknown>;
  return typeof d.interaction_id === "string" && typeof d.conversation_id === "string" && typeof d.user === "string";
}

const strings = (v: unknown): string[] | null => (Array.isArray(v) && v.every((x) => typeof x === "string") ? v : null);
const fieldsOf = (v: unknown): Record<string, string> =>
  v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).filter(([, x]) => typeof x === "string")) as Record<string, string> : {};

/** The registered component and modal handlers and the interaction flow. */
export class ComponentRouter {
  private readonly components: [Matcher, ComponentHandler][] = [];
  private readonly modals: [Matcher, ComponentHandler][] = [];
  private readonly verifier: ComponentValuesVerifier;
  private readonly autoDeferMs: number;

  constructor(private readonly opts: { logger: BotLogger; autoDeferMs?: number; now?: () => number }) {
    this.verifier = new ComponentValuesVerifier({ now: opts.now });
    this.autoDeferMs = opts.autoDeferMs ?? 2000;
  }

  component(matcher: Matcher, handler: ComponentHandler): void {
    this.components.push([matcher, handler]);
  }

  modal(matcher: Matcher, handler: ComponentHandler): void {
    this.modals.push([matcher, handler]);
  }

  private find(list: [Matcher, ComponentHandler][], id: string): ComponentHandler | undefined {
    return list.find(([m]) => (typeof m === "string" ? m === id : m.test(id)))?.[1];
  }

  /** Handles one `component.invoke` or `modal.submit` event. Never throws; failures answer a generic notice. */
  async handle(event: "component.invoke" | "modal.submit", data: unknown, ctx: InvokeContext): Promise<ComponentInteraction | null> {
    const log = this.opts.logger;
    if (!isEvent(data)) {
      log.warn(`malformed ${event} ignored`, { node: ctx.node });
      return null;
    }
    const kind = event === "component.invoke" ? "component" : "modal";
    const answerError = (message: string) =>
      ctx.request("POST", `/interactions/${encodeURIComponent(data.interaction_id)}/callback`, { type: "error", message }).catch((e: unknown) => log.warn("could not answer the interaction", { interaction: data.interaction_id, error: e }));
    const id = (kind === "component" ? data.custom_id : data.modal_custom_id) ?? "";
    const handler = this.find(kind === "component" ? this.components : this.modals, id);
    if (!handler) {
      log.warn(`${kind} without a handler`, { custom_id: id, interaction: data.interaction_id });
      await answerError(MSG.unknown);
      return null;
    }
    const values = await this.values(kind, data, ctx);
    if (!values.ok) {
      await answerError(values.reason === "joining" ? MSG.joining : MSG.values);
      return null;
    }
    const interaction = new ComponentInteraction(kind, data, kind === "component" ? strings(values.values) : null, kind === "modal" ? fieldsOf(values.values) : {}, ctx);
    const timer = setTimeout(() => void interaction.autoDefer(), this.autoDeferMs);
    try {
      await handler(interaction);
      if (!interaction.answered) {
        log.warn(`${kind} handler returned without answering`, { custom_id: id, interaction: data.interaction_id });
        await interaction.error(MSG.noAnswer).catch(() => undefined);
      }
    } catch (e) {
      log.error(`${kind} handler failed`, { custom_id: id, interaction: data.interaction_id, error: e });
      if (!interaction.answered) await interaction.error(MSG.failed).catch(() => undefined);
    } finally {
      clearTimeout(timer);
    }
    return interaction;
  }

  /** The values: as sent in unencrypted conversations, decrypted and checked in encrypted ones. */
  private async values(kind: "component" | "modal", data: ComponentEventData, ctx: InvokeContext): Promise<{ ok: true; values: unknown } | { ok: false; reason: "joining" | "invalid" }> {
    const log = this.opts.logger;
    if (!data.encrypted) return { ok: true, values: data.values ?? null };
    const q = qualify(ctx.node, data.conversation_id);
    if (!ctx.crypto) return { ok: false, reason: "invalid" };
    if (!ctx.crypto.hasGroup(q)) {
      ctx.crypto.join(q);
      return { ok: false, reason: "joining" };
    }
    if (typeof data.values_ciphertext !== "string" || !data.device_id) return { ok: false, reason: "invalid" };
    const decrypted = await ctx.crypto.decrypt(q, { id: `interaction:${data.interaction_id}`, author: data.user, device_id: data.device_id, epoch: data.epoch, content: data.values_ciphertext });
    if (!decrypted.ok) {
      log.warn("component values could not be decrypted", { interaction: data.interaction_id, reason: decrypted.reason });
      return { ok: false, reason: "invalid" };
    }
    const check =
      kind === "component"
        ? this.verifier.checkComponent(decrypted.content, { messageId: data.message_id ?? "", customId: data.custom_id ?? "" })
        : this.verifier.checkModal(decrypted.content, { interactionId: data.parent_interaction_id ?? "", customId: data.modal_custom_id ?? "" });
    if (!check.ok) {
      log.warn("component values refused", { interaction: data.interaction_id, reason: check.reason });
      return { ok: false, reason: "invalid" };
    }
    return { ok: true, values: check.values };
  }
}

// ---------------------------------------------------------------- builders

/** A row of 1–5 buttons or one select. */
export function row(...components: Component[]): Row {
  return { type: "row", components };
}

/**
 * A button: `customId` for every style but `link`, `url` for link buttons (the style is `link` when only a URL is
 * given, else `secondary` by default).
 */
export function button(opts: { label?: string; customId?: string; url?: string; style?: ButtonStyle; emoji?: string; disabled?: boolean }): Button {
  const style = opts.style ?? (opts.url && !opts.customId ? "link" : "secondary");
  const b: Button = { type: "button", style, label: opts.label ?? "" };
  if (opts.emoji) b.emoji = opts.emoji;
  if (opts.customId !== undefined) b.custom_id = opts.customId;
  if (opts.url !== undefined) b.url = opts.url;
  if (opts.disabled) b.disabled = true;
  return b;
}

/** A select menu; options as `{ label, value, … }` or plain strings (label = value). */
export function select(customId: string, options: (SelectOption | string)[], opts: { placeholder?: string; min?: number; max?: number; disabled?: boolean } = {}): Select {
  const s: Select = { type: "select", custom_id: customId, options: options.map((o) => (typeof o === "string" ? { label: o, value: o } : o)) };
  if (opts.placeholder !== undefined) s.placeholder = opts.placeholder;
  if (opts.min !== undefined) s.min = opts.min;
  if (opts.max !== undefined) s.max = opts.max;
  if (opts.disabled) s.disabled = true;
  return s;
}

/** A text input of a modal (`short` by default, required by default). */
export function textInput(customId: string, label: string, opts: { style?: InputStyle; placeholder?: string; minLength?: number; maxLength?: number; required?: boolean; value?: string } = {}): ModalInput {
  const i: ModalInput = { custom_id: customId, label, style: opts.style ?? "short" };
  if (opts.placeholder !== undefined) i.placeholder = opts.placeholder;
  if (opts.minLength !== undefined) i.min_length = opts.minLength;
  if (opts.maxLength !== undefined) i.max_length = opts.maxLength;
  if (opts.required !== undefined) i.required = opts.required;
  if (opts.value !== undefined) i.value = opts.value;
  return i;
}

/** A modal (checked; throws `TypeError` naming the offending field). */
export function modal(customId: string, title: string, ...inputs: ModalInput[]): Modal {
  const m: Modal = { custom_id: customId, title, inputs };
  const issue = validateModal(m);
  if (issue) throw new TypeError(`invalid modal at ${issue.path || "the modal"}: ${issue.message}`);
  return m;
}

/** A text content object with components (checked; throws `TypeError` naming the offending field). */
export function withComponents(body: string, ...rows: Row[]): Record<string, unknown> {
  const issue = validateComponents(rows);
  if (issue) throw new TypeError(`invalid components at ${issue.path}: ${issue.message}`);
  return { type: "text", body, components: rows };
}
