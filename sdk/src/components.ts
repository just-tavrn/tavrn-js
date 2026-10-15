// SPDX-License-Identifier: Apache-2.0
/**
 * Message components (protocol/APPLICATIONS.md §5.10, capability `components.v1`): buttons and select menus in the
 * `text` content of an application's messages, and modals (forms) an application opens on the invoker's device.
 *
 * The validators mirror the node's rules exactly (`tavrn-node` `src/components.rs`) and report the same error code
 * and `meta.path` (the first offending field); both run `protocol/testvectors/components.json`. The node checks
 * plaintext content; encrypted content is invisible to it, so bots validate before encrypting and clients after
 * decrypting (and render components only on messages whose author is a bot).
 */

export const MAX_ROWS = 5;
export const MAX_BUTTONS_PER_ROW = 5;
export const MAX_OPTIONS = 25;
/** The serialized `components` array (UTF-8 JSON) at most. */
export const MAX_COMPONENTS_BYTES = 8 * 1024;
export const MAX_CUSTOM_ID = 100;
export const MAX_BUTTON_LABEL = 80;
export const MAX_PLACEHOLDER = 150;
export const MAX_OPTION_LABEL = 100;
export const MAX_OPTION_VALUE = 100;
export const MAX_OPTION_DESCRIPTION = 100;
export const MAX_URL = 2048;
export const MAX_EMOJI = 32;
export const MAX_MODAL_TITLE = 45;
export const MAX_MODAL_INPUTS = 5;
export const MAX_INPUT_LABEL = 45;
export const MAX_INPUT_PLACEHOLDER = 100;
export const MAX_INPUT_LENGTH = 4000;

export const BUTTON_STYLES = ["primary", "secondary", "success", "danger", "link"] as const;
export type ButtonStyle = (typeof BUTTON_STYLES)[number];
export const INPUT_STYLES = ["short", "paragraph"] as const;
export type InputStyle = (typeof INPUT_STYLES)[number];

/** A button; link buttons carry `url` and no `custom_id`, every other style a `custom_id` and no `url`. */
export interface Button {
  type: "button";
  style: ButtonStyle;
  /** 0–80 characters; empty only with an `emoji`. */
  label?: string;
  /** One Unicode emoji or `:shortcode:` (at most 32 characters). */
  emoji?: string | null;
  /** 1–100 characters, unique within the message; not on link buttons. */
  custom_id?: string | null;
  /** Link buttons only: `https://` without credentials, at most 2048 characters. */
  url?: string | null;
  disabled?: boolean | null;
}

export interface SelectOption {
  label: string;
  /** 1–100 characters, unique within the select. */
  value: string;
  description?: string | null;
  emoji?: string | null;
  default?: boolean | null;
}

/** A select menu: 1–25 options, `min`–`max` of them selected (defaults 1 and 1). */
export interface Select {
  type: "select";
  custom_id: string;
  placeholder?: string | null;
  options: SelectOption[];
  min?: number | null;
  max?: number | null;
  disabled?: boolean | null;
}

export type Component = Button | Select;

/** A row: 1–5 buttons or exactly one select. */
export interface Row {
  type: "row";
  components: Component[];
}

export interface ModalInput {
  custom_id: string;
  /** 1–45 characters. */
  label: string;
  style: InputStyle;
  placeholder?: string | null;
  /** 0–4000 (default 0). */
  min_length?: number | null;
  /** 1–4000 (default 4000), at least `min_length`. */
  max_length?: number | null;
  /** Default `true`. */
  required?: boolean | null;
  /** Prefilled text, at most `max_length` characters. */
  value?: string | null;
}

/** A modal (a form on the invoking device), the `modal` of a `modal` response. */
export interface Modal {
  custom_id: string;
  /** 1–45 characters. */
  title: string;
  /** 1–5 inputs. */
  inputs: ModalInput[];
}

/** The `data` of a `component.invoke` event (WebSocket or interactions URL, §5.10.2). */
export interface ComponentInvokeData {
  interaction_id: string;
  application_id: string;
  message_id: string;
  custom_id: string;
  /** Plaintext conversations: null for buttons, the selected option values for selects. */
  values: string[] | null;
  /** Encrypted conversations: the `component.values` content object, encrypted by the invoker. */
  values_ciphertext: string | null;
  epoch: number | null;
  conversation_id: string;
  room_id: string | null;
  channel_id: string | null;
  thread_id: string | null;
  encrypted: boolean;
  user: string;
  user_id: string;
  device_id: string;
  /** The invoker's effective permissions in the channel (decimal). */
  permissions: string;
  locale: string;
  expires_at: string;
}

/** The `data` of a `modal.submit` event (§5.10.4). */
export interface ModalSubmitData extends Omit<ComponentInvokeData, "message_id" | "custom_id" | "values"> {
  /** The interaction that answered with the modal. */
  parent_interaction_id: string;
  modal_custom_id: string;
  /** The component's message; null for a modal opened by a command. */
  message_id: string | null;
  /** The component that opened the modal; null for commands. */
  custom_id: string | null;
  /** The command that opened the modal; null for components. */
  command: { id: string; name: string } | null;
  /** Plaintext conversations: input `custom_id` → text. */
  values: Record<string, string> | null;
}

/** `POST /conversations/{id}/messages/{message_id}/interactions` (until the generated type exists). */
export interface ComponentInvokeRequest {
  custom_id: string;
  values?: string[] | null;
  values_ciphertext?: string | null;
  epoch?: number | null;
  thread_id?: null;
}

/** `POST /interactions/{id}/submit` (until the generated type exists). */
export interface ModalSubmitRequest {
  values?: Record<string, string> | null;
  values_ciphertext?: string | null;
  epoch?: number | null;
}

/** A refused component, modal or value: the node's error code and `meta.path`. */
export interface ComponentIssue {
  code: "message.components_invalid" | "interaction.modal_invalid" | "component.values_invalid" | "interaction.values_invalid";
  path: string;
  message: string;
}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
/** Characters as the node counts them (Unicode scalar values). */
const chars = (s: string) => Array.from(s).length;
const CONTROL = /\p{Cc}/u;
const absent = (v: unknown) => v === undefined || v === null;

/** A string of `min`–`max` characters without control characters. */
function text(v: unknown, min: number, max: number): boolean {
  if (typeof v !== "string") return false;
  const n = chars(v);
  return n >= min && n <= max && !CONTROL.test(v);
}

/** `custom_id`: 1–100 characters without control characters. */
export function validCustomId(v: unknown): v is string {
  return text(v, 1, MAX_CUSTOM_ID);
}

/** One Unicode emoji (1–16 characters without whitespace, control characters, `:`, `<`, `>`) or `:name:`. */
export function validComponentEmoji(v: unknown): v is string {
  if (typeof v !== "string" || chars(v) > MAX_EMOJI) return false;
  if (v.startsWith(":") && v.endsWith(":") && v.length >= 2) return /^:[a-z0-9_]{2,30}:$/.test(v);
  const n = chars(v);
  return n >= 1 && n <= 16 && !/[\p{Cc}\s:<>]/u.test(v);
}

/** `https://` with a host, without credentials or whitespace, at most 2048 characters. */
export function validLinkUrl(v: unknown): v is string {
  if (typeof v !== "string" || v.length > MAX_URL || !v.startsWith("https://") || /\s/.test(v)) return false;
  try {
    const u = new URL(v);
    return u.protocol === "https:" && u.hostname !== "" && u.username === "" && u.password === "";
  } catch {
    return false;
  }
}

const int = (v: unknown, min: number, max: number): v is number => typeof v === "number" && Number.isInteger(v) && v >= min && v <= max;

function unknownKey(o: Obj, allowed: readonly string[]): string | undefined {
  return Object.keys(o).find((k) => !allowed.includes(k));
}

const ROW_KEYS = ["type", "components"] as const;
const BUTTON_KEYS = ["type", "style", "label", "emoji", "custom_id", "url", "disabled"] as const;
const SELECT_KEYS = ["type", "custom_id", "placeholder", "options", "min", "max", "disabled"] as const;
const OPTION_KEYS = ["label", "value", "description", "emoji", "default"] as const;
const MODAL_KEYS = ["custom_id", "title", "inputs"] as const;
const INPUT_KEYS = ["custom_id", "label", "style", "placeholder", "min_length", "max_length", "required", "value"] as const;

class Refused {
  constructor(readonly path: string, readonly message: string) {}
}

function check(ok: boolean, path: string, message: string): void {
  if (!ok) throw new Refused(path, message);
}

function checkButton(b: Obj, p: string): void {
  const k = unknownKey(b, BUTTON_KEYS);
  check(k === undefined, `${p}.${k}`, "Unknown field");
  check(typeof b.style === "string" && (BUTTON_STYLES as readonly string[]).includes(b.style), `${p}.style`, "style: primary, secondary, success, danger or link");
  const hasEmoji = !absent(b.emoji);
  const label = absent(b.label) ? "" : b.label;
  check(text(label, hasEmoji ? 0 : 1, MAX_BUTTON_LABEL), `${p}.label`, `label: 1 to ${MAX_BUTTON_LABEL} characters (empty only with an emoji)`);
  check(!hasEmoji || validComponentEmoji(b.emoji), `${p}.emoji`, "emoji: one Unicode emoji or :shortcode:");
  const link = b.style === "link";
  if (link) check(absent(b.custom_id), `${p}.custom_id`, "Link buttons carry no custom_id");
  else check(validCustomId(b.custom_id), `${p}.custom_id`, `custom_id: 1 to ${MAX_CUSTOM_ID} characters`);
  if (link) check(validLinkUrl(b.url), `${p}.url`, "url: an https:// URL without credentials");
  else check(absent(b.url), `${p}.url`, "Only link buttons carry a url");
  check(absent(b.disabled) || typeof b.disabled === "boolean", `${p}.disabled`, "disabled: a boolean");
}

function checkSelect(s: Obj, p: string): void {
  const k = unknownKey(s, SELECT_KEYS);
  check(k === undefined, `${p}.${k}`, "Unknown field");
  check(validCustomId(s.custom_id), `${p}.custom_id`, `custom_id: 1 to ${MAX_CUSTOM_ID} characters`);
  check(absent(s.placeholder) || text(s.placeholder, 0, MAX_PLACEHOLDER), `${p}.placeholder`, `placeholder: at most ${MAX_PLACEHOLDER} characters`);
  const options = s.options;
  check(Array.isArray(options) && options.length >= 1 && options.length <= MAX_OPTIONS, `${p}.options`, `options: 1 to ${MAX_OPTIONS}`);
  const list = options as unknown[];
  const values = new Set<string>();
  list.forEach((o, i) => {
    const q = `${p}.options[${i}]`;
    check(isObj(o), q, "An option is an object");
    const opt = o as Obj;
    const k2 = unknownKey(opt, OPTION_KEYS);
    check(k2 === undefined, `${q}.${k2}`, "Unknown field");
    check(text(opt.label, 1, MAX_OPTION_LABEL), `${q}.label`, `label: 1 to ${MAX_OPTION_LABEL} characters`);
    check(text(opt.value, 1, MAX_OPTION_VALUE) && !values.has(opt.value as string), `${q}.value`, `value: 1 to ${MAX_OPTION_VALUE} characters, unique`);
    values.add(opt.value as string);
    check(absent(opt.description) || text(opt.description, 0, MAX_OPTION_DESCRIPTION), `${q}.description`, `description: at most ${MAX_OPTION_DESCRIPTION} characters`);
    check(absent(opt.emoji) || validComponentEmoji(opt.emoji), `${q}.emoji`, "emoji: one Unicode emoji or :shortcode:");
    check(absent(opt.default) || typeof opt.default === "boolean", `${q}.default`, "default: a boolean");
  });
  const min = absent(s.min) ? 1 : s.min;
  check(int(min, 0, MAX_OPTIONS) && min <= list.length, `${p}.min`, "min: 0 to 25, at most the number of options");
  const max = absent(s.max) ? 1 : s.max;
  check(int(max, 1, MAX_OPTIONS) && max >= (min as number) && max <= list.length, `${p}.max`, "max: 1 to 25, at least min, at most the number of options");
  check(absent(s.disabled) || typeof s.disabled === "boolean", `${p}.disabled`, "disabled: a boolean");
}

const utf8Length = (s: string) => new TextEncoder().encode(s).length;

function run(code: ComponentIssue["code"], f: () => void): ComponentIssue | null {
  try {
    f();
    return null;
  } catch (e) {
    if (e instanceof Refused) return { code, path: e.path, message: e.message };
    throw e;
  }
}

/**
 * Checks the `components` value of a `text` content object (§5.10.1): null when valid, else the node's
 * `message.components_invalid` with the `meta.path` of the first offending field.
 */
export function validateComponents(rows: unknown): ComponentIssue | null {
  return run("message.components_invalid", () => {
    check(Array.isArray(rows), "components", "components is an array of rows");
    check(utf8Length(JSON.stringify(rows)) <= MAX_COMPONENTS_BYTES, "components", `components: at most ${MAX_COMPONENTS_BYTES} bytes`);
    const list = rows as unknown[];
    check(list.length <= MAX_ROWS, "components", `At most ${MAX_ROWS} rows`);
    const ids = new Set<string>();
    list.forEach((r, i) => {
      const rp = `components[${i}]`;
      check(isObj(r), rp, "A row is an object");
      const row = r as Obj;
      const k = unknownKey(row, ROW_KEYS);
      check(k === undefined, `${rp}.${k}`, "Unknown field");
      check(row.type === "row", `${rp}.type`, 'type: "row"');
      const items = row.components;
      check(Array.isArray(items) && items.length >= 1 && items.length <= MAX_BUTTONS_PER_ROW, `${rp}.components`, `A row holds 1 to ${MAX_BUTTONS_PER_ROW} buttons or one select`);
      const els = items as unknown[];
      check(!(els.length > 1 && els.some((e) => isObj(e) && e.type === "select")), `${rp}.components`, "A select fills its row alone");
      els.forEach((e, j) => {
        const p = `${rp}.components[${j}]`;
        check(isObj(e), p, "A component is an object");
        const el = e as Obj;
        if (el.type === "button") checkButton(el, p);
        else if (el.type === "select") checkSelect(el, p);
        else check(false, `${p}.type`, "type: button or select");
        if (typeof el.custom_id === "string") {
          check(!ids.has(el.custom_id), `${p}.custom_id`, "custom_id is unique within the message");
          ids.add(el.custom_id);
        }
      });
    });
  });
}

/**
 * Checks a modal definition (§5.10.3): null when valid, else the node's `interaction.modal_invalid` with the
 * `meta.path` below the modal ("" for the modal itself).
 */
export function validateModal(modal: unknown): ComponentIssue | null {
  return run("interaction.modal_invalid", () => {
    check(isObj(modal), "", "The modal is an object");
    const m = modal as Obj;
    const k = unknownKey(m, MODAL_KEYS);
    check(k === undefined, `${k}`, "Unknown field");
    check(validCustomId(m.custom_id), "custom_id", `custom_id: 1 to ${MAX_CUSTOM_ID} characters`);
    check(text(m.title, 1, MAX_MODAL_TITLE), "title", `title: 1 to ${MAX_MODAL_TITLE} characters`);
    check(Array.isArray(m.inputs) && m.inputs.length >= 1 && m.inputs.length <= MAX_MODAL_INPUTS, "inputs", `inputs: 1 to ${MAX_MODAL_INPUTS}`);
    const ids = new Set<string>();
    (m.inputs as unknown[]).forEach((x, i) => {
      const p = `inputs[${i}]`;
      check(isObj(x), p, "An input is an object");
      const input = x as Obj;
      const k2 = unknownKey(input, INPUT_KEYS);
      check(k2 === undefined, `${p}.${k2}`, "Unknown field");
      check(validCustomId(input.custom_id), `${p}.custom_id`, `custom_id: 1 to ${MAX_CUSTOM_ID} characters`);
      check(text(input.label, 1, MAX_INPUT_LABEL), `${p}.label`, `label: 1 to ${MAX_INPUT_LABEL} characters`);
      check(typeof input.style === "string" && (INPUT_STYLES as readonly string[]).includes(input.style), `${p}.style`, "style: short or paragraph");
      check(absent(input.placeholder) || text(input.placeholder, 0, MAX_INPUT_PLACEHOLDER), `${p}.placeholder`, `placeholder: at most ${MAX_INPUT_PLACEHOLDER} characters`);
      const min = absent(input.min_length) ? 0 : input.min_length;
      check(int(min, 0, MAX_INPUT_LENGTH), `${p}.min_length`, `min_length: 0 to ${MAX_INPUT_LENGTH}`);
      const max = absent(input.max_length) ? MAX_INPUT_LENGTH : input.max_length;
      check(int(max, 1, MAX_INPUT_LENGTH) && max >= (min as number), `${p}.max_length`, `max_length: 1 to ${MAX_INPUT_LENGTH}, at least min_length`);
      check(absent(input.required) || typeof input.required === "boolean", `${p}.required`, "required: a boolean");
      check(absent(input.value) || (typeof input.value === "string" && chars(input.value) <= (max as number)), `${p}.value`, "value: at most max_length characters");
      check(!ids.has(input.custom_id as string), `${p}.custom_id`, "custom_id is unique within the modal");
      ids.add(input.custom_id as string);
    });
  });
}

/** The button or select with `customId` (link buttons have none). */
export function findComponent(rows: readonly Row[] | null | undefined, customId: string): Button | Select | undefined {
  for (const row of rows ?? []) {
    for (const c of row.components ?? []) {
      if (c.custom_id === customId && !(c.type === "button" && c.style === "link")) return c;
    }
  }
  return undefined;
}

/**
 * The node's check 3 of §5.10.2 for plaintext conversations (bots use it for decrypted values too): `customId` names
 * an enabled button or select of `rows`, and `values` fit it (null for buttons; `min`–`max` distinct option values).
 */
export function validateComponentValues(rows: readonly Row[] | null | undefined, customId: string, values: unknown): ComponentIssue | null {
  return run("component.values_invalid", () => {
    const c = findComponent(rows, customId);
    check(c !== undefined && c.disabled !== true, "custom_id", "No enabled component with this custom_id");
    if (c!.type === "button") {
      check(absent(values), "values", "Buttons carry no values");
      return;
    }
    const s = c as Select;
    check(Array.isArray(values), "values", "values: the selected option values");
    const list = values as unknown[];
    const min = s.min ?? 1;
    const max = s.max ?? 1;
    check(list.length >= min && list.length <= max, "values", `values: ${min} to ${max} options`);
    const seen = new Set<string>();
    list.forEach((v, i) => {
      check(typeof v === "string" && s.options.some((o) => o.value === v) && !seen.has(v), `values[${i}]`, "An option value of the select, once");
      seen.add(v as string);
    });
  });
}

/**
 * The node's check of a plaintext modal submit (§5.10.4): an object of input `custom_id` → text, every required
 * input filled, lengths within `min_length`–`max_length` (optional inputs may be absent or empty).
 */
export function validateModalValues(modal: Modal, values: unknown): ComponentIssue | null {
  return run("interaction.values_invalid", () => {
    check(isObj(values), "values", "values: an object of input custom_id to text");
    const v = values as Obj;
    for (const [key, value] of Object.entries(v)) {
      check(modal.inputs.some((i) => i.custom_id === key) && typeof value === "string", `values.${key}`, "An input of the modal, as text");
    }
    for (const input of modal.inputs) {
      const value = (v[input.custom_id] as string | undefined) ?? "";
      const n = chars(value);
      const required = input.required ?? true;
      if (n === 0) {
        check(!required, `values.${input.custom_id}`, "This input is required");
        continue;
      }
      check(n >= (input.min_length ?? 0) && n <= (input.max_length ?? MAX_INPUT_LENGTH), `values.${input.custom_id}`, "The text is too short or too long");
    }
  });
}

/** The checked components of a content object of a bot's message, or none (clients render nothing else). */
export function readComponents(content: unknown, authorKind: string | null | undefined): Row[] {
  if (authorKind !== "bot" || !isObj(content) || content.type !== "text" || absent(content.components)) return [];
  return validateComponents(content.components) === null ? (content.components as Row[]) : [];
}
