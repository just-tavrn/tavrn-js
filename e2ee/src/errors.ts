// SPDX-License-Identifier: MPL-2.0
/** Errors of the account flows (ENCRYPTION.md §2.4, §9, §9a) with stable codes for the UI. */

export type E2eeErrorCode =
  | "recovery_key_invalid"
  | "recovery_key_wrong"
  | "passkey_wrong"
  | "no_recovery_entry"
  | "no_passkey_entry"
  | "identity_mismatch"
  | "rotation_devices"
  | "locked"
  /** Setup refused: this device holds the account's master secret, or the node has its recovery entry (unlock). */
  | "already_set_up";

export class E2eeError extends Error {
  constructor(readonly code: E2eeErrorCode) {
    super(code);
    this.name = "E2eeError";
  }
}
