# @tavrn/e2ee

The client side of tavrn's end-to-end encryption ([`ENCRYPTION.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/ENCRYPTION.md)),
shared by the web client and bots (the bot runtime [`@tavrn/bot`](../bot), [`APPLICATIONS.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/APPLICATIONS.md)
§3). It builds on the WebAssembly core [`@tavrn/crypto`](https://github.com/just-tavrn/tavrn-crypto) and the API client
[`@tavrn/sdk`](../sdk), and runs unchanged in browsers and in Node.js (24+). Everything that needs the DOM
(WebAuthn ceremonies, React hooks, UI stores, IndexedDB) stays in the web client
([tavrn-web](https://github.com/just-tavrn/tavrn-web)).

Like `@tavrn/sdk`, the package ships TypeScript source (the consumer's bundler or test runner compiles it: Vite,
Vitest, Playwright, `vite-node`); it is not compiled to JavaScript yet. License: MPL-2.0 (file-level copyleft; the
application that uses it may have any license).

## Entry points

| Import | Environment | Contents |
|---|---|---|
| `@tavrn/e2ee` | browser and Node.js | everything below except the file store |
| `@tavrn/e2ee/node` | Node.js only | `FileKeyStore`, `StateDirInUseError`, `STATE_FILE` |

## API

**WebAssembly** — `ensureCrypto(): Promise<void>` loads `@tavrn/crypto` once: `init()` in browsers (the bundler
emits `tavrn_crypto_bg.wasm` as an asset), `initSync` with the file read from the installed package in Node.js.
Every function of this package awaits it itself; call it before using `@tavrn/crypto` directly.

**Key storage** (`keystore.ts`, `storage/`)

- `interface KeyStore`: per account the device id, the master secret and named secrets, encrypted at rest under
  the local storage key (ENCRYPTION.md §2.1). Methods: `status(account)` → `"none" | "locked" | "unlocked"`,
  `deviceIdOf`, `resume` (open without user interaction, if the store has a persisted key), `saveMaster(account,
  deviceId, master)`, `unlockWithMaster(account, master)` (throws `LocalKeyMismatchError`), `isUnlocked`, `lock`,
  `wipe`, `account`, `deviceId`, `masterSecret` (a copy; zero it), `putSecret` / `getSecret` / `deleteSecret`.
- `MemoryKeyStore`: in memory (tests, one-shot tools).
- `FileKeyStore(dir)` (`@tavrn/e2ee/node`): a state directory (mode 0700) with one file `state.json` (mode 0600):
  a plaintext header `{ v, account, device_id, iv, data }` and AES-256-GCM over all secrets under
  `MasterSecret.localStorageKey(device_id)`, bound to the account by the additional data. The key is never
  stored: `resume()` is always false and the process unlocks with the master secret on every start. Every
  change is written atomically (temporary file, fsync, rename, directory fsync) and writes are serialized;
  `close()` waits for them. One account per directory (`StateDirInUseError`), one process per directory.
- The IndexedDB store of the web client (`src/crypto/store.ts` in tavrn-web, `CryptoStore implements KeyStore`) adds
  "lock on close" (persisted non-extractable WebCrypto key or none).
- Helpers: `withMasterSecret(store, fn)`, `withBackupKey(store, fn)`, `readJsonSecret` / `writeJsonSecret`,
  `localStorageKey(master, deviceId)`, `localAad(account, name)`.

**Account flows** (`account.ts`, ENCRYPTION.md §2.4, §3, §8, §9) — all take an `E2eeContext { api, username,
address, deviceId, store, clientName? }`, where `api` needs the `keys` and `secretStorage` routes of a
`TavrnApi`:
`ensureDevice` (create the MLS client, attest the device, keep ≥ `KEY_PACKAGE_MIN` KeyPackages, uploading up to
`KEY_PACKAGE_BATCH`), `setupAccount`, `unlockWithRecoveryKey`, `unlockWithPasskeyPrf`, `addPasskeySecret`,
`regenerateRecoveryKey`, `resetIdentity`, `passkeyEntryIds(api)`; store-only helpers `localStatus(store, address,
deviceId)`, `loadClient(store)` / `saveClient(store, client)` (secret `CLIENT_STATE = "mls-client"`),
`localIdentityKey(store)`, `forgetIdentityKeepDevice(store, address)`, `wipeLocal(store, address)`. Errors:
`E2eeError` with `code` (`recovery_key_invalid`, `recovery_key_wrong`, `passkey_wrong`, `no_recovery_entry`,
`no_passkey_entry`, `identity_mismatch`, `locked`).

**MLS session manager** (`mls.ts`, ENCRYPTION.md §4–§7, FEDERATION.md §3.5, §6, §10) — `MlsManager(deps:
MlsDeps)` with the node API injected (`MlsApi`: `node(domain)` → `MlsNodeApi` delivery service of the hosting
node, `keys(address)` from the user's home node, backups on the own home node; `mlsApiOf({ home, node, keys })`
adapts `@tavrn/sdk` clients) and persistence injected (`persist`, `savePins`, `saveMeta`, `saveVerified`).
`openMlsManager(store, { api, address, deviceId, homeDomain, onEvent?, backupDelayMs? })` wires it to a
`KeyStore` (secrets `PINS`, `META`, `VERIFIED`) and returns null when the device has no MLS client yet.
Conversation ids are qualified (`qualify(domain, ulid)`, `splitQualified`). Methods:

- joining: `ensureJoined(q, { canCreate })`, `processWelcomes(domain)`, `catchUp(q)`, `addMissingDevices(q, members)`,
  `removeLeaves(q, identities)`, `selfUpdate(q)`, `hasGroup`, `epoch`;
- content: `encrypt(q, content)`, `decrypt(q, envelope)` → `Decrypted`, `peek`, `encryptEphemeral`,
  `decryptEphemeral` (replay window), `voiceKey(q)`, `contentHeader(content)`;
- plaintext signatures: `signPlaintext(q, fields, content)`, `verifyPlaintext(q, envelope)` → `PlainStatus`;
- identities: `verifiedDevices(address)`, `ghostCheck(q, members)`, `changedKeys()`, `acknowledgeKeyChange`,
  `identityChanged`, `forgetDevices`, `safetyNumber`, `comparePayload`, `markVerified`, `removeVerification`,
  `acceptNewKey`, `verification(address)`, `verificationStates()`;
- backups: `flushBackups()`, `hasPendingBackups()`, `restoreBackups()`; `dispose()`.

Events (`onEvent`): `epoch`, `rejoined`, `removed`, `key_changed`, `verification`.

**Codecs** — `content.ts` (ENCRYPTION.md §6): `encryptAttachment(file)` → ciphertext `Blob` and metadata,
`decryptAttachment(ciphertext, meta)` (checks the SHA-256 first, `AttachmentIntegrityError`),
`contentAttachments(content, envelope)` (only entries matching the envelope), `safeFileName`. `plaintext.ts`
(FEDERATION.md §10.3): `signedAttachments`, `envelopeFields`, `signatureNonce`, `plainMarker`.

## How a bot uses it

The bot runtime ([`@tavrn/bot`](../bot), `createBot()`) does, with an app token whose device id is `dev`:

```ts
import { ensureDevice, mlsApiOf, openMlsManager } from "@tavrn/e2ee";
import { FileKeyStore } from "@tavrn/e2ee/node";

const store = new FileKeyStore(process.env.TAVRN_BOT_STATE_DIR ?? "./.tavrn-state");
const master = /* MasterSecret bytes from TAVRN_BOT_KEY or the key file (§3.1) */;
if ((await store.status(address)) === "none") await store.saveMaster(address, dev, master);
else await store.unlockWithMaster(address, master); // LocalKeyMismatchError: key file and state differ
await ensureDevice({ api, username, address, deviceId: dev, store, clientName: "tavrn-bot" });
const mls = await openMlsManager(store, { api: mlsApiOf({ home: api, node, keys }), address, deviceId: dev, homeDomain });
await mls!.ensureJoined(conversation, { canCreate: false });
const reply = await mls!.encrypt(conversation, { type: "text", body: "hello" });
// on shutdown: mls.dispose(); await store.close();
```

There is no recovery key and no secret storage for bots; the key file is the backup.

## Tests

`pnpm --filter @tavrn/e2ee test` (part of `just test`; the WebAssembly module comes prebuilt with `@tavrn/crypto`). The suites run in Node.js
against in-memory nodes (`test/fake-node.ts`): the session manager across several nodes, two parties end to
end with the in-memory and the file store (setup, join, messages, ephemeral events, plaintext signatures,
backup restore on a new device, restart from the state directory), the account flows, the `KeyStore` contract
and the file store's guarantees (encryption at rest, permissions, atomic and serialized writes, tampering).
