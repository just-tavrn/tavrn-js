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
  | "already_set_up"
  /**
   * The session's device has a key on the node that this device no longer holds (its local key store was lost):
   * a device key is immutable (ENCRYPTION.md §3.1), so encryption needs a new device, i.e. signing in again.
   */
  | "device_key_lost"
  /**
   * A local secret that must not be reset silently (the key pins, the verified contacts) decrypts but cannot be read:
   * the manager does not start over with empty pins (that would trust every changed key again). The blob stays stored.
   */
  | "state_unreadable";

export class E2eeError extends Error {
  constructor(readonly code: E2eeErrorCode) {
    super(code);
    this.name = "E2eeError";
  }
}
