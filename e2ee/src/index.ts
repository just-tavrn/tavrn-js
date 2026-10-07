// SPDX-License-Identifier: MPL-2.0
/**
 * @tavrn/e2ee – the client side of tavrn's end-to-end encryption, shared by the web client and bots:
 * the MLS session manager, the content and attachment codecs, plaintext signatures, the account flows
 * (device attestation, KeyPackages, secret storage, recovery key) and the {@link KeyStore} abstraction.
 * Environment-neutral (browsers and Node.js); the file store for Node.js is exported from
 * `@tavrn/e2ee/node`.
 */
export { ensureCrypto } from "./wasm";
export {
  LocalKeyMismatchError,
  localAad,
  localStorageKey,
  readJsonSecret,
  withBackupKey,
  withMasterSecret,
  writeJsonSecret,
  type CryptoStatus,
  type KeyStore,
} from "./keystore";
export { MemoryKeyStore } from "./storage/memory";
export {
  CLIENT_STATE,
  E2eeError,
  KEY_PACKAGE_BATCH,
  KEY_PACKAGE_MIN,
  addPasskeySecret,
  deviceLoginProof,
  ensureDevice,
  forgetIdentityKeepDevice,
  loadClient,
  localIdentityKey,
  localStatus,
  passkeyEntryIds,
  regenerateRecoveryKey,
  resetIdentity,
  saveClient,
  setupAccount,
  unlockWithPasskeyPrf,
  unlockWithRecoveryKey,
  wipeLocal,
  type DeviceProof as LocalDeviceProof,
  type E2eeContext,
  type E2eeErrorCode,
} from "./account";
export * from "./mls";
export * from "./cleanup";
export { META, PINS, VERIFIED, openMlsManager, reloadOwnIdentity, type OpenMlsOptions } from "./session";
export * from "./content";
export * from "./embeds";
export * from "./sealed";
export * from "./commands";
export * from "./plaintext";
export * from "./history";
export * from "./search";
export {
  IDENTITY_SEED,
  chainKeys,
  chainReaches,
  derivedIdentityKey,
  ownIdentityPublicKey,
  resolveIdentity,
  rotateIdentity,
  syncIdentity,
  withIdentityKey,
  type ContinuityStatement,
  type IdentityDocument,
  type RotationContext,
} from "./identity";
