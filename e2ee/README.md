# @tavrn/e2ee

The client side of tavrn's end-to-end encryption ([`ENCRYPTION.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/ENCRYPTION.md)),
shared by the web client and bots (the bot runtime [`@tavrn/bot`](../bot/README.md), [`APPLICATIONS.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/APPLICATIONS.md)
§3). It builds on the WebAssembly core [`@tavrn/crypto`](https://github.com/just-tavrn/tavrn-crypto) and the API client
[`@tavrn/sdk`](../sdk/README.md), and runs unchanged in browsers and in Node.js (24+). Everything that needs the DOM
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
address, deviceId, store, clientName?, keyPackages? }`, where `api` needs the `keys` and `secretStorage` routes of a
`TavrnApi`:
`ensureDevice` (create the MLS client, attest the device together with its share key (§3.1; a device attested
before share keys existed publishes it once with `keys.putShareKey`), keep ≥ `KEY_PACKAGE_MIN` KeyPackages, uploading
up to `KEY_PACKAGE_BATCH`; a device key is immutable, so when the node holds another key for the session's device
than the local one, or a key while the store has none, the device lost its key: `device_key_lost`, nothing new is
stored and a mismatching stored client is dropped, and the session has to sign in again as a new device), `setupAccount`, `unlockWithRecoveryKey`, `unlockWithPasskeyPrf`, `addPasskeySecret`,
`regenerateRecoveryKey`, `resetIdentity`, `passkeyEntryIds(api)`; store-only helpers `localStatus(store, address,
deviceId)`, `loadClient(store)` / `saveClient(store, client)` (secret `CLIENT_STATE = "mls-client"`),
`localIdentityKey(store)`, `forgetIdentityKeepDevice(store, address)`, `wipeLocal(store, address)`;
`localDeviceLost(ctx)` (the node lists the session's device with a key this store does not hold: no unlock helps,
sign in again; false while locked). Errors: `E2eeError` with `code` (`recovery_key_invalid`, `recovery_key_wrong`,
`passkey_wrong`, `no_recovery_entry`, `no_passkey_entry`, `identity_mismatch`, `rotation_devices`, `locked`,
`already_set_up`, `device_key_lost`).

**MLS session manager** (`mls.ts`, ENCRYPTION.md §4–§7, FEDERATION.md §3.5, §6, §10) — `MlsManager(deps:
MlsDeps)` with the node API injected (`MlsApi`: `node(domain)` → `MlsNodeApi` delivery service of the hosting
node, `keys(address)` from the user's home node, backups on the own home node; `mlsApiOf({ home, node, keys })`
adapts `@tavrn/sdk` clients) and persistence injected (`persist`, `savePins`, `saveMeta`, `saveVerified`).
`openMlsManager(store, { api, address, deviceId, homeDomain, onEvent?, backupDelayMs?, tabs? })` wires it to a
`KeyStore` (secrets `PINS`, `META`, `VERIFIED`) and returns null when the device has no MLS client yet.
Conversation ids are qualified (`qualify(domain, ulid)`, `splitQualified`). Methods:

- joining: `ensureJoined(q, { canCreate, priority? })`, `processWelcomes(domain)`, `catchUp(q)`,
  `addMissingDevices(q, members)`, `removeLeaves(q, identities, keys?)` (with `keys`, exactly the leaves with those
  signature keys), `selfUpdate(q, { priority? })`, `hasGroup`, `epoch`. Operations that change the client run one at a
  time; `priority` (a voice join, somebody waits) runs before the waiting background work, not before the running
  operation. Without a local group `ensureJoined` requests the Welcomes and the GroupInfo at once. `addMissingDevices` adds a claimed KeyPackage only when its leaf carries the identity and the
  attested key of the device it was claimed for (`keyPackageLeaf`);
- content: `encrypt(q, content, opts?)`, `decrypt(q, envelope)` → `Decrypted`, `peek`, `encryptEphemeral`,
  `decryptEphemeral` (replay window), `voiceKey(q)`, `contentHeader(content)`. `opts.ctx` is the message's **signed
  context** (`{ thread_id, reply_to }`, for answers of applications also `interaction`; ENCRYPTION.md §5.2): it is
  encrypted and signed with the content, and `decrypt` answers `{ ok: false, reason: "envelope_mismatch" }` when the
  envelope the node delivers names another thread or reply. Before anything leaves the device (`encrypt`, thread
  titles, `encryptEphemeral`) the ghost check runs again (`opts.members`, `opts.noBots`; without them the members of
  the last `ghostCheck`, or every leaf's user) and refuses with `MlsError("ghost")` while a violation is not
  acknowledged: only `acknowledgeGhosts(q, identities)`, called by the warning's button, lets content out to it
  (`unacknowledgedGhosts(q)` lists the rest); a ghost check alone acknowledges nothing;
- plaintext signatures: `signPlaintext(q, fields, content)`, `verifyPlaintext(q, envelope)` → `PlainStatus`;
- identities: `verifiedDevices(address)`, `ghostCheck(q, members)` (a member whose security key changed stays a
  ghost with the reason `key_changed` until the user acknowledges the change; no device is added automatically
  meanwhile), `changedKeys()`, `acknowledgeKeyChange`, `identityChanged`, `forgetDevices`, `safetyNumber`,
  `comparePayload`, `markVerified`, `removeVerification`, `acceptNewKey`, `verification(address)`,
  `verificationStates()`;
- trust record (`trust.ts`, ENCRYPTION.md §7): the pins, the verified contacts and the account's own devices are
  kept as a backup blob under the backup key on the home node, so they survive a sign-out and reach new devices
  (`restoreBackups` brings them, `flushBackups` uploads changes, `syncTrust()` merges both ways);
  `knownOwnDevice(deviceId, key)` tells whether the account attested that device key itself (the cleanup re-attests
  only such keys as retired);
- share keys: `verifiedShareKeys(address)` (the share keys of a user's devices whose attestation by the device key
  checks out), `ownShareKey()`, `encryptHistory(q, json, shareKeys)` (format 2 with sealed boxes per recipient
  device; format 1 is not sent any more);
- backups: `flushBackups()`, `hasPendingBackups()`, `restoreBackups()`; `dispose()`;
- KeyPackages: `createKeyPackages(count)` (in the manager's state; `ensureDevice` tops up through it when its context
  has `keyPackages`, see below).

Events (`onEvent`): `epoch`, `rejoined`, `removed`, `added`, `key_changed`, `key_rotated`, `verification`.

**Tabs of one browser** (`tabs.ts`, option `tabs` of `openMlsManager`) — the tabs of a browser profile share one
IndexedDB store and so one MLS state. Without coordination every tab keeps its own copy in memory and writes it:
the last writer wins, and a tab whose copy is stale commits on an old epoch, joins once more with the same device
(which throws the other tab out of the group) or rejoins after an invalid commit. With `tabs: { name }`:

- **One owner.** Every tab requests the Web Lock `name` (`navigator.locks`; the web client uses
  `tavrn-mls|<home node origin>|<address>/<device id>`). The tab that holds it owns the state: it runs every
  state-changing operation and alone writes the client state and the MLS bookkeeping.
- **The others forward.** A tab without the lock keeps a read-only copy of the state (loaded from the store) for the
  synchronous reads (`hasGroup`, `epoch`, `roster`, `voiceKey`, …), decryption, ephemeral events and plaintext
  signatures: none of them changes the state (content keys are derived per epoch, ENCRYPTION.md §5). Everything that
  does (`FORWARDED_OPERATIONS`: joins, catch-ups, commits, `encrypt` with its catch-up and rotation, history keys,
  backups, KeyPackages, inbox keys) goes to the owner over the BroadcastChannel `name`: a request with an id, the
  response (result or error, rebuilt as `MlsError` / `TavrnApiError`) addressed to the asking tab, 30 s timeout
  (`MlsError("owner_unavailable")`). A decryption that misses an epoch key asks the owner to catch up or restore
  the backup, then reads again.
- **Following the owner.** After every write the owner announces `state`; the other tabs reload their copy before
  they read it next (after a forwarded call returns, before an event is passed on). The owner also passes on the
  events the views need (`epoch`, `rejoined`, `removed`); `added` stays with the owner (it shares the history once).
- **Hand-over.** When the owner tab closes (or signs out: `dispose()`) the browser releases the lock and the next
  waiting tab gets it. It reloads the state from the store before anything runs there, then announces itself.
  Operations in flight are retried once on the new owner (the tab that took over runs its own ones itself); losing
  a second owner fails the call with `owner_unavailable`. Retrying is safe because every forwarded operation can run
  twice: joins and catch-ups are idempotent, a second commit is one more epoch, and an encryption whose result never
  arrived was never sent. A new owner serves a request id only once.
- **Fallback.** Without Web Locks or BroadcastChannel (or when the lock request fails) every tab works alone, as
  before. The desktop app has one window: its tab always wins the lock, nothing else changes. Bots (one process per
  state directory) leave `tabs` out.
- **Not coordinated:** the pins and verified contacts (every tab reads them at start and writes them as before), and
  the account flows that replace the whole state (identity reset, `forgetIdentityKeepDevice`, `wipeLocal`), after
  which the web client opens a new manager anyway. Same-origin scripts can talk to the channel; they could read the
  same store (and the open tab's memory) anyway, and the owner serves only the listed operations with checked
  arguments.

`ensureDevice` writes the client state when it tops up KeyPackages. While a manager is open, pass
`keyPackages: (n) => manager.createKeyPackages(n)` in its context: the KeyPackages are then created in the manager's
state (in the owning tab), and their private keys are not lost when that state is written next.

**Codecs** — `content.ts` (ENCRYPTION.md §6): `encryptAttachment(file)` → ciphertext `Blob` and metadata,
`decryptAttachment(ciphertext, meta)` (checks the SHA-256 first, `AttachmentIntegrityError`),
`contentAttachments(content, envelope)` (only entries matching the envelope), `safeFileName`. `plaintext.ts`
(FEDERATION.md §10.3): `signedAttachments`, `envelopeFields`, `signatureNonce`, `plainMarker`.

**Encrypted files channels** — `files.ts` (FILES.md §8, WebCrypto only): `encryptFileStream(blob)` (1 MiB chunks,
one in memory at a time) → ciphertext `Blob` and the file key, `decryptFileChunks(key, part, storedSize)` (a
`TransformStream` for downloads, also for ranges from `ciphertextRange`), `encryptFileBytes`/`decryptFileBytes`
(thumbnails), `encryptedSize`/`plaintextSize`; entry records: `encryptFileRecord(manager, conversation, record)`
(under the current epoch, forwarded to the owning tab), `decryptFileRecord` (local; `withheld` when the node serves
no record), `parseFileRecord` (binds the record to its entry, kind and ciphertext size), `entryName`/`validEntryName`
(FILES.md §2) and `recordSamples` (records as the samples of history key checks).

**History for new members** — `history.ts` (ENCRYPTION.md §7b): members hand the content keys of past epochs to a
member who joined later, as far as the channel's policy allows (`parseHistoryPolicy`: `since_join`, `days:<n>`,
`all`; `historyWindowStart`, `epochsToShare`). Every policy, `since_join` included, covers the epochs between the
member's room join and its device's first leaf in the group, whose keys reach that device only through a share. `HistorySync` runs the flows of one device: `checkPending(q, policy)`
(which pending members this device shares with, elected by `sharerDelay` so that one online device does it),
`shareWith(q, to, joinedAtMs, policy)`, `receive(q)` (fetches the shares addressed to this device, checks every key
against a stored message of its epoch signed by its author's attested device, keeps accepted keys and acknowledges
the share), `noteAdded`, `dispose`. With the node capability `history.shares2` a share is **format 2**: a fresh key
sealed to the verified share key of every device of the recipient (at most `MAX_SHARE_BOXES`), so only those devices
can read it. Without the capability, or when a device of the recipient has no verified share key, nothing is sent
(`onLog("share_skipped")`): format 1 (under the current epoch, readable by every leaf) is never sent, only still read.
The window starts at the node's `since`, but never more than `MAX_JOIN_GAP_MS` (30 days) before this device first saw
the member waiting (`boundedJoin`). The payload codec is
`encodeHistoryPayload` / `parseHistoryPayload`, the key check `epochKeyOpens` with `pickSamples`.

**History after a key reset** — also `history.ts` (capability `history.restore`): `restorePlan(q, channel)` lists the
epochs of a requester's pre-reset range this device can share, `restore(q, to, channel)` sends them after an approved
request, and `shareSinceReset` / `epochsSinceReset` share the epochs since the reset. The requests themselves (ask,
approve, deny) are routes of `@tavrn/sdk` (`api.historyRequests`).

**Polls** — `poll.ts` (PROTOCOL.md §7g): `parsePoll` (both kinds, the limits), `pollContent` (a composer's input to
the content object), `pollHash` (hex SHA-256 of the JCS form without `ctx`), `pollVoteContent` (choices or answers,
bound to the poll by `ctx.poll` and `ctx.poll_hash`), `encryptPollVote` / `signPlainPollVote` (the body of `PUT
…/poll/vote`), `checkPollVote` (decrypts with `MlsManager.decryptPollVote` or checks the plaintext signature, then
binds the vote to the poll: `stale` for an edited poll, `envelope_mismatch` for another poll), `tallyPoll` (one vote
per member, the newest record; stale, late and unverifiable votes left out; per option counts and voters, date slots
scored `2 × yes + maybe` with the best ones) and `pollVisibility` (the cooperative `results_visible` and
`votes_visible`). Vote content is never shown as a message and a message is never a vote.

```ts
const d = await mls.decrypt(q, message);                          // the poll message
const poll = d.ok ? parsePoll(d.content) : null;
const hash = await pollHash(d.content);
const vote = pollVoteContent(poll, message.id, hash, { choices: ["o2"] });
await api.polls.vote(conversationId, message.id, await encryptPollVote(mls, q, vote));
const { items } = await api.polls.votes(conversationId, message.id);
const checked = await Promise.all(items.map(async (r) => ({ user: r.user, updated_at: r.updated_at, check: await checkPollVote(mls, q, r, poll, hash) })));
const tally = tallyPoll(poll, checked, { closesAt: message.poll_closes_at });
```

**Other codecs and helpers**

- `sealed.ts`: the stored form of sealed webhook posts in encrypted channels (`sealedContent`, `webhookPayload`,
  `validWebhookName`; APPLICATIONS.md §6.1a, ENCRYPTION.md §5b). The box is opened with the epoch's inbox key inside
  `decrypt`.
- `commands.ts`: encrypted command arguments (`encryptCommandArgs`, `CommandArgsVerifier`, which refuses payloads for
  another command, stale or future ones and replays; APPLICATIONS.md §5.8).
- `components.ts`: encrypted component values and modal input (`encryptComponentValues`, `encryptModalValues`,
  `ComponentValuesVerifier`, which refuses values made for another message, component or modal, stale or future ones
  and replays; APPLICATIONS.md §5.10.2, §5.10.4).
- `embeds.ts`: the embed rules of `text` content (`assertEmbeds` before encrypting, `withValidEmbeds` after
  decrypting, `readEmbeds` for renderers; APPLICATIONS.md §6.4).
- `cleanup.ts`: `LeafCleaner` removes ghost leaves the node allows and the client verified (ENCRYPTION.md §4.7), with an
  election among the devices that may do it; `urgent` (content waits for the removal) skips the election wait and ends
  the wait of a running cleanup; `noWait` (a voice join: nothing waits for the removal) ends the wait of a running
  cleanup too, runs at once when this device is elected and otherwise returns `postponed` without committing (the
  caller repeats the cleanup without `noWait` later); `isRunning(q)` tells whether a cleanup of a conversation runs.
  The election counts only valid leaves of devices that may commit every removal of the run (own ghost leaves: the
  same user; departed members: the users in `managers`, when given; deleted or unattested devices: any member) and,
  when the caller knows it, only online ones (`online`: device identities such as the voice participants;
  `onlineUsers`: user addresses such as the presence list). Without these lists every valid leaf counts. A cleanup
  looks the members' devices up again only when the roster (identities and signature keys) changed since the last
  check without findings, that check is older than `FRESH_REUSE_MS` or the node lists a pending removal of a leaf in
  the group.
- `identity.ts`: the current identity key and its rotation with continuity (`rotateIdentity`, `syncIdentity`,
  `resolveIdentity`; ENCRYPTION.md §9a).
- `search/`: the local encrypted search index (`SearchIndex` over a `SearchBackend`, `MemorySearchBackend` for tests;
  keys from `searchKeysFromStore`; SEARCH.md). Every stored value is sealed under the local key and every lookup key
  is an HMAC token, never an id or a word; the web client provides the IndexedDB backend.

## How a bot uses it

The bot runtime ([`@tavrn/bot`](../bot/README.md), `createBot()`) does, with an app token whose device id is `dev`:

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
and the file store's guarantees (encryption at rest, permissions, atomic and serialized writes, tampering), and the
tab coordination with an in-memory lock manager and BroadcastChannel (`test/fake-tabs.ts`: election, forwarding,
errors, timeouts, hand-over, fallback; several tabs of one account on one state, with a control case without it).
