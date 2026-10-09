// SPDX-License-Identifier: Apache-2.0
/**
 * Date of birth, the private age status and the age gates of rooms and channels (protocol PROTOCOL.md §5e, `age.v1`).
 * The node decides; these helpers let clients show the same rules before they ask (form hints, locked channels).
 */
import type { AgeStatus } from "./generated/types.gen";

/** `none` or `adults_only`. */
export type AgeGate = "none" | "adults_only";
/** Ages are counted from this age on as adult. */
export const ADULT_AGE = 18;
/** The error codes of `age.v1`. */
export const AGE_ERRORS = ["age.restricted", "age.status_required", "age.below_minimum", "age.date_of_birth_set"] as const;

function parse(dob: string): { y: number; m: number; d: number } | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dob);
  if (!match) return null;
  const [y, m, d] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const date = new Date(Date.UTC(y, m - 1, d));
  if (date.getUTCFullYear() !== y || date.getUTCMonth() !== m - 1 || date.getUTCDate() !== d) return null;
  return { y, m, d };
}

/** Whole years on `today` (UTC) of someone born on `dob` (`YYYY-MM-DD`); 29 February counts on 1 March. */
export function ageOn(dob: string, today: Date = new Date()): number | null {
  const b = parse(dob);
  if (!b) return null;
  const [ty, tm, td] = [today.getUTCFullYear(), today.getUTCMonth() + 1, today.getUTCDate()];
  let years = ty - b.y;
  if (tm < b.m || (tm === b.m && td < b.d)) years -= 1;
  return years;
}

/**
 * The node's checks of a date of birth (PROTOCOL.md §5e): `invalid` for anything but a real date between 1900-01-01
 * and today (UTC), `below_minimum` under the node's `minimum_age`, otherwise null.
 */
export function checkDateOfBirth(dob: string, minimumAge: number, today: Date = new Date()): "invalid" | "below_minimum" | null {
  const b = parse(dob);
  if (!b || b.y < 1900) return "invalid";
  const age = ageOn(dob, today);
  if (age === null || age < 0) return "invalid";
  const todayKey = today.toISOString().slice(0, 10);
  if (dob > todayKey) return "invalid";
  return age < minimumAge ? "below_minimum" : null;
}

/** Only `adult` passes a gate; `unknown` counts as `minor`. */
export function isAdult(status: AgeStatus | null | undefined): boolean {
  return status?.tier === "adult";
}

/** The channel is locked for this user: its effective gate is `adults_only` and the user is not an adult. */
export function channelLocked(channel: { age_gate_effective?: string | null }, status: AgeStatus | null | undefined): boolean {
  return channel.age_gate_effective === "adults_only" && !isAdult(status);
}

/** A Problem Details object (or `TavrnApiError`) with one of the `age.v1` codes. */
export function isAgeError(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && (AGE_ERRORS as readonly string[]).includes(code);
}
