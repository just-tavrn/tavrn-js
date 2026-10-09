// SPDX-License-Identifier: MPL-2.0
/**
 * MLS session manager (ENCRYPTION.md §4–§7), shared by the web client and bots: one `Client` per account and device,
 * persisted after every mutating call. It joins conversations (create, external commit, Welcome),
 * catches up with the handshake log, runs the two-phase commit protocol (§4.3), encrypts and decrypts
 * message content (§5) with replay detection, checks the roster for ghost devices (§4.6), verifies
 * device attestations against pinned identity keys (§3.3) and keeps the history backup (§7) in sync.
 * It also signs and verifies plaintext messages with the device key and keeps the verified contacts
 * (FEDERATION.md §10).
 *
 * Across nodes (FEDERATION.md §3.5, §3.6, §6) every conversation is addressed by its **qualified id**
 * `<node domain>/<ulid>`, the domain being the node that hosts it: group info, commits, the handshake
 * log, Welcomes and KeyPackage claims go to that node (with the federated session there); identity keys
 * and device attestations of any user always come from that user's own home node; backups stay on this
 * user's home node.
 *
 * The node API is injected ({@link MlsApi}) so that tests can run several clients against in-memory
 * delivery services of several nodes; persistence is injected too ({@link MlsDeps}, or `openMlsManager`
 * for a `KeyStore`).
 */
import { Client, contentEpoch, safetyNumber, verifyDeviceAttestation, verifyPayload, verifyPayloadMatches, verifyPlaintext, type CommitOutput } from "@tavrn/crypto";
import {
  TavrnApiError,
  b64urlDecode,
  b64urlEncode,
  jcs,
  type BackupList,
  type ClaimedKeyPackages,
  type CommitRequest,
  type EpochResponse,
  type GroupInfoResponse,
  type LogPage,
  type UserKeys,
  type WelcomeList,
} from "@tavrn/sdk";
import { chainKeys, chainReaches } from "./identity";
import { envelopeFields, signatureNonce, type PlainEnvelope, type PlainStatus, type SignedFields } from "./plaintext";
import { assertEmbeds, withValidEmbeds } from "./embeds";
import { sealedContent, webhookPayload, type SealedBy, type SealedContent } from "./sealed";

/** Delivery-service routes of the node that hosts a conversation (ENCRYPTION.md §4.4); ids are bare ULIDs. */
export interface MlsNodeApi {
  groupInfo(conversationId: string): Promise<GroupInfoResponse>;
  createGroup(conversationId: string, groupInfo: string): Promise<EpochResponse>;
  postCommit(conversationId: string, req: CommitRequest): Promise<EpochResponse>;
  log(conversationId: string, sinceEpoch: number): Promise<LogPage>;
  /** Welcomes for this device that wait on this node. */
  welcomes(): Promise<WelcomeList>;
  deleteWelcome(id: string): Promise<void>;
  /** KeyPackages of `address`, claimed through this node (its claim proxy for users of other nodes, §3.5). */
  claim(address: string): Promise<ClaimedKeyPackages>;
  /** `PUT …/inbox-key` (write-only webhooks, ENCRYPTION.md §5b); without it no inbox keys are published. */
  publishInboxKey?(conversationId: string, req: { epoch: number; public_key: string; signature: string }): Promise<unknown>;
}

/** The routes the manager needs (see {@link mlsApiOf}). */
export interface MlsApi {
  /** The delivery service of node `domain`, with this user's session on that node. */
  node(domain: string): MlsNodeApi;
  /**
   * Public keys of `address`, fetched from that user's **home node** (FEDERATION.md §3.5: clients never
   * rely on the view of the node that hosts a conversation).
   */
  keys(address: string): Promise<UserKeys>;
  /** Backups on this user's home node (§7). */
  backupList(): Promise<BackupList>;
  backupGet(domain: string, ulid: string): Promise<{ blob: Uint8Array; etag: string } | null>;
  backupPut(domain: string, ulid: string, blob: Uint8Array, etag: string | null): Promise<void>;
}

/** The parts of an SDK client that one node's delivery service needs. */
export interface MlsNodeClient {
  mls: {
    groupInfo: MlsNodeApi["groupInfo"];
    createGroup: (c: string, r: { group_info: string }) => Promise<EpochResponse>;
    postCommit: MlsNodeApi["postCommit"];
    log: (c: string, s: number) => Promise<LogPage>;
    welcomes: MlsNodeApi["welcomes"];
    deleteWelcome: (id: string) => Promise<void>;
    publishInboxKey?: (c: string, r: { epoch: number; public_key: string; signature: string }) => Promise<unknown>;
  };
  keys: { claim: (user: string) => Promise<ClaimedKeyPackages> };
}

/**
 * Adapter from the SDK: `home` is the client of this user's home node (backups), `node(domain)` the
 * client of any node (the home client or a federated session), `keys(address)` the public key lookup on
 * the address's home node.
 */
export function mlsApiOf(deps: {
  home: { backups: { list: MlsApi["backupList"]; get: MlsApi["backupGet"]; put: (d: string, u: string, b: Uint8Array, e: string | null) => Promise<unknown> } };
  node: (domain: string) => MlsNodeClient;
  keys: (address: string) => Promise<UserKeys>;
}): MlsApi {
  return {
    node: (domain) => {
      const api = deps.node(domain);
      return {
        groupInfo: (c) => api.mls.groupInfo(c),
        createGroup: (c, gi) => api.mls.createGroup(c, { group_info: gi }),
        postCommit: (c, r) => api.mls.postCommit(c, r),
        log: (c, s) => api.mls.log(c, s),
        welcomes: () => api.mls.welcomes(),
        deleteWelcome: (id) => api.mls.deleteWelcome(id),
        claim: (address) => api.keys.claim(address),
        publishInboxKey: (c, r) => (api.mls.publishInboxKey ? api.mls.publishInboxKey(c, r) : Promise.resolve(undefined)),
      };
    },
    keys: (address) => deps.keys(address),
    backupList: () => deps.home.backups.list(),
    backupGet: (d, u) => deps.home.backups.get(d, u),
    backupPut: async (d, u, b, e) => {
      await deps.home.backups.put(d, u, b, e);
    },
  };
}

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const DOMAIN = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/;

/** Qualified conversation id `<domain>/<ulid>` (ENCRYPTION.md §0.1), also the MLS group id. */
export function qualify(domain: string, conversationId: string): string {
  return `${domain}/${conversationId}`;
}

/** Splits a qualified conversation id; malformed ids are rejected (§0.1). */
export function splitQualified(qualified: string): { domain: string; id: string } {
  const slash = qualified.indexOf("/");
  const domain = qualified.slice(0, slash);
  const id = qualified.slice(slash + 1);
  if (slash < 1 || !DOMAIN.test(domain) || !ULID.test(id)) throw new MlsError("invalid_id");
  return { domain, id };
}

/**
 * A pinned identity key (TOFU, §3.3); `changed` until the user acknowledged the "security key changed" warning,
 * `rotated` until the soft notice of a rotation with a valid continuity statement was dismissed (§9a).
 */
export interface Pin {
  key: string;
  changed?: boolean;
  rotated?: boolean;
}

/**
 * A contact whose safety number was compared (FEDERATION.md §10.2), stored per device in the encrypted
 * local store next to the pins.
 */
export interface VerifiedContact {
  address: string;
  /** The identity key (base64url) that was verified. */
  identity_public_key: string;
  verified_at: string;
  method: "qr" | "numeric";
  /** The key the verified one was rotated to with a valid continuity statement (ENCRYPTION.md §9a). */
  rotated_to?: string;
  /** The user dismissed the "verification needs a refresh" notice. */
  refresh_dismissed?: boolean;
}

/**
 * `verified`: the pinned key is the verified one; `refresh`: the verified key was rotated with a valid continuity
 * statement (not blocking, verify again); `broken`: the key changed after the verification without one.
 */
export type VerificationState = "verified" | "refresh" | "broken" | "unverified";

/** Small per-account bookkeeping, stored encrypted next to the client state. */
export interface MlsMeta {
  /** Backups of all conversations were downloaded on this device (§8 step 3). */
  restored?: boolean;
  /** Per qualified conversation id: last own commit (rotation) and whether a rotation is due after a removal. */
  convs: Record<string, { rotatedAt: number; rotate?: boolean }>;
  /** Conversations with epoch keys not uploaded yet (survives a reload before the debounced upload). */
  pendingBackups?: string[];
}

/**
 * Older versions kept bare conversation ids of the home node in the meta data: qualify them (in place).
 */
export function normalizeMeta(meta: MlsMeta, homeDomain: string): MlsMeta {
  const q = (id: string) => (id.includes("/") ? id : qualify(homeDomain, id));
  meta.convs = Object.fromEntries(Object.entries(meta.convs ?? {}).map(([k, v]) => [q(k), v]));
  if (meta.pendingBackups) meta.pendingBackups = [...new Set(meta.pendingBackups.map(q))];
  return meta;
}

export interface MlsDeps {
  api: MlsApi;
  client: Client;
  /** Own user address `name@domain`. */
  address: string;
  deviceId: string;
  /** Domain of this user's home node. */
  homeDomain: string;
  /** Persists the client state (call after every mutation). */
  persist(client: Client): Promise<void>;
  /** The 32-byte backup key (fresh copy; the manager zeroes it after use). */
  backupKey(): Uint8Array;
  /** Own identity public key (base64url): own devices are verified against it instead of TOFU. */
  ownIdentityKey(): string;
  pins: Record<string, Pin>;
  savePins(pins: Record<string, Pin>): Promise<void>;
  meta: MlsMeta;
  saveMeta(meta: MlsMeta): Promise<void>;
  /** Verified contacts by address (§10.2); empty if omitted. */
  verified?: Record<string, VerifiedContact>;
  saveVerified?(verified: Record<string, VerifiedContact>): Promise<void>;
  /** Notifications for the UI. */
  onEvent?(e: MlsEvent): void;
  /** Debounce of the backup upload in milliseconds (default 1000). */
  backupDelayMs?: number;
  /** Clock (tests). */
  now?(): number;
  /**
   * Coordination with other tabs of the same browser profile (see `tabs.ts`, wired by `openMlsManager`): while
   * another tab owns the state, every state-changing operation runs there; this manager reads from a copy.
   */
  tabs?: MlsTabLink;
}

/** Operations a tab forwards to the tab that owns the MLS state (everything that changes the client state). */
export const FORWARDED_OPERATIONS = [
  "ensureJoined",
  "processWelcomes",
  "catchUp",
  "selfUpdate",
  "removeLeaves",
  "addMissingDevices",
  "encrypt",
  "encryptHistory",
  "importHistoryKeys",
  "publishInboxKey",
  "setInboxWanted",
  "flushBackups",
  "restoreBackups",
  "restoreBackup",
  "createKeyPackages",
] as const;
export type ForwardedOperation = (typeof FORWARDED_OPERATIONS)[number];

/** The manager's side of the tab coordination. */
export interface MlsTabLink {
  /** Whether this manager runs state-changing operations itself (it owns the state and has loaded it). */
  local(): boolean;
  /** Runs the operation in the owning tab; resolves once this tab's copy of the state is current. */
  forward(operation: ForwardedOperation, args: unknown[]): Promise<unknown>;
  /** Leaves the coordination (dispose). */
  close(): void;
}

/** Conversations are named by their qualified id. */
export type MlsEvent =
  | { type: "epoch"; conversationId: string }
  | { type: "rejoined"; conversationId: string }
  /** This device committed Adds of these users' devices (history sharing, ENCRYPTION.md §7b). */
  | { type: "added"; conversationId: string; addresses: string[] }
  | { type: "removed"; conversationId: string }
  | { type: "key_changed"; address: string }
  /** The key was rotated with a valid continuity statement and pinned (soft notice, ENCRYPTION.md §9a). */
  | { type: "key_rotated"; address: string }
  | { type: "verification"; address: string };

/** Why a message could not be shown (rendered as a neutral placeholder, never as content). */
export type DecryptFailure = "missing_key" | "bad_signature" | "unknown_device" | "replay" | "invalid" | "locked";
/**
 * `retired`: sent from a device that was deleted later; verified with its retired attestation (ENCRYPTION.md §5.2).
 * `sealedBy`: a sealed webhook message (APPLICATIONS.md §6.1a) with the per-message `webhookName` from inside the box.
 */
export type Decrypted =
  | { ok: true; content: Record<string, unknown>; retired?: true; sealedBy?: SealedBy; webhookName?: string }
  | { ok: false; reason: DecryptFailure };

/** `type` of an encrypted thread title (PROTOCOL.md §7e). */
const THREAD_TITLE_TYPE = "thread.title";
/** Content types that are never a message or an event: history shares (§7b) travel only through their own route. */
const NOT_CONTENT_TYPES = new Set(["history_keys"]);

/** Longest thread title in characters (PROTOCOL.md §7e). */
export const THREAD_TITLE_MAX = 100;

/** Messages of a retired device count until this long after its deletion (clock skew, messages in flight). */
export const RETIRED_SLACK_MS = 5 * 60 * 1000;

/**
 * `removed`: an `unattested` leaf whose device the node reports as deleted (cleanup pending, ENCRYPTION.md §4.7).
 * `bot`: a leaf of a bot (or of an account whose `kind` this client does not know) in a conversation whose effective
 * "no bots" flag is set (APPLICATIONS.md §3.5, ENCRYPTION.md §4.6).
 */
export type GhostReason = "not_member" | "unattested" | "duplicate" | "removed" | "bot";

/** Options of {@link MlsManager.ghostCheck}. */
export interface GhostCheckOptions {
  /** Look the users' devices up again before judging (before acting on a violation). */
  fresh?: boolean;
  /** The conversation's effective `no_bots` flag (channels; DMs never have it): bot leaves are ghosts. */
  noBots?: boolean;
}

/** Whether a `kind` of a keys document counts as a bot: `bot` and every kind this client does not know (§1.5). */
export function isBotKind(kind: string | null | undefined): boolean {
  return kind != null && kind !== "user";
}
export interface GhostViolation {
  identity: string;
  reason: GhostReason;
}

/** The parts of a message envelope the codec needs. */
export interface EncryptedEnvelope {
  id: string;
  author: string;
  device_id?: string | null;
  epoch?: number | null;
  content: unknown;
  /** Server time of the message: messages of retired devices are accepted only from before their deletion. */
  created_at?: string | null;
  /** Set on webhook messages (sealed ones carry `content.type = "webhook.sealed"`). */
  webhook?: unknown;
}

export class MlsError extends Error {
  /** `owner_unavailable`: the tab that owns the state did not answer in time (or left twice), see `tabs.ts`. */
  constructor(readonly code: "no_group" | "conflict" | "not_joined" | "invalid_id" | "owner_unavailable") {
    super(code);
    this.name = "MlsError";
  }
}

const ROTATE_AFTER_MS = 7 * 24 * 3600 * 1000;
/** Most KeyPackages {@link MlsManager.createKeyPackages} creates at once. */
export const MAX_KEY_PACKAGES = 100;
const MAX_TRIES = 3;
/** A forced lookup of a user's devices reuses a result younger than this. */
const KEY_REFETCH_MS = 2_000;
/** Device lists are looked up again after this (the key cache TTL of nodes, FEDERATION.md §3.5). */
export const KEY_TTL_MS = 3600 * 1000;
/** Ephemeral events whose nonces are remembered for replay detection. */
export const EPHEMERAL_REPLAY_WINDOW = 4096;

function apiCode(e: unknown): string | undefined {
  return e instanceof TavrnApiError ? e.code : undefined;
}

function cryptoCode(e: unknown): string {
  return e instanceof Error ? e.name : "unknown";
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Splits a device identity `user@domain/DEVICE` into address and device id. */
export function splitIdentity(identity: string): { address: string; deviceId: string } {
  const i = identity.lastIndexOf("/");
  return { address: identity.slice(0, i), deviceId: identity.slice(i + 1) };
}

/** Header epoch and nonce of an encrypted `content` value (§5.2), or null if malformed. */
export function contentHeader(content: string): { epoch: number; nonce: string } | null {
  try {
    const epoch = contentEpoch(content);
    // 0x01 || u64 epoch || nonce(12): the first 21 bytes are 28 base64url characters.
    const head = b64urlDecode(content.slice(0, 28));
    if (head.length < 21) return null;
    return { epoch, nonce: b64urlEncode(head.slice(9, 21)) };
  } catch {
    return null;
  }
}

export class MlsManager {
  private client: Client;
  private queue: Promise<unknown> = Promise.resolve();
  private readonly dirty = new Set<string>();
  private backupTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly keyCache = new Map<string, { at: number; pending: boolean; devices: Promise<Map<string, Uint8Array> | null> }>();
  /** Retired devices per address (verified like active ones, filled by the same lookup): key and deletion time. */
  private readonly retiredKeys = new Map<string, Map<string, { key: Uint8Array; deletedAt: number }>>();
  /** `kind` of every user whose keys were looked up (from the user's home node, APPLICATIONS.md §3.5). */
  private readonly kinds = new Map<string, string>();
  private readonly decrypted = new Map<string, Decrypted>();
  private readonly nonces = new Map<string, string>();
  private readonly backupTried = new Set<string>();
  private readonly plainChecked = new Map<string, PlainStatus>();
  private readonly plainNonces = new Map<string, string>();
  /** Recent `(conversation, epoch, nonce)` of ephemeral events (replay window, see decryptEphemeral). */
  private readonly ephemeralNonces = new Set<string>();
  /** Encrypted channels with webhooks (ENCRYPTION.md §5b) and the epoch whose inbox key this session published. */
  private readonly inboxWanted = new Set<string>();
  private readonly inboxSent = new Map<string, number>();
  private readonly verified: Record<string, VerifiedContact>;
  private disposed = false;

  constructor(private readonly deps: MlsDeps) {
    this.client = deps.client;
    this.verified = deps.verified ?? {};
    normalizeMeta(deps.meta, deps.homeDomain);
  }

  /** The delivery service of the node hosting the conversation `q` (qualified id). */
  private ds(q: string): { api: MlsNodeApi; id: string } {
    const { domain, id } = splitQualified(q);
    return { api: this.deps.api.node(domain), id };
  }

  get address(): string {
    return this.deps.address;
  }

  private now(): number {
    return this.deps.now?.() ?? Date.now();
  }

  /** The forwarded call when another tab owns the state, otherwise null (run it here). */
  private forwarded<T>(operation: ForwardedOperation, args: unknown[]): Promise<T> | null {
    const tabs = this.deps.tabs;
    return tabs && !tabs.local() ? (tabs.forward(operation, args) as Promise<T>) : null;
  }

  /**
   * Tab coordination, in the tab that owns the state: runs an operation another tab forwarded. Only the operations
   * of {@link FORWARDED_OPERATIONS}, with their arguments checked.
   */
  serveForwarded(operation: string, args: unknown[]): Promise<unknown> {
    const str = (v: unknown): string => {
      if (typeof v !== "string") throw new MlsError("invalid_id");
      return v;
    };
    const strs = (v: unknown): string[] => {
      if (!Array.isArray(v)) throw new MlsError("invalid_id");
      return v.map(str);
    };
    const obj = (v: unknown): Record<string, unknown> => {
      if (!v || typeof v !== "object" || Array.isArray(v)) throw new MlsError("invalid_id");
      return v as Record<string, unknown>;
    };
    try {
      const [a, b] = args;
      switch (operation as ForwardedOperation) {
        case "ensureJoined":
          return this.ensureJoined(str(a), { canCreate: obj(b).canCreate === true });
        case "processWelcomes":
          return this.processWelcomes(str(a));
        case "catchUp":
          return this.catchUp(str(a));
        case "selfUpdate":
          return this.selfUpdate(str(a));
        case "removeLeaves":
          return this.removeLeaves(str(a), strs(b));
        case "addMissingDevices":
          return this.addMissingDevices(str(a), strs(b));
        case "encrypt":
          return this.encrypt(str(a), obj(b));
        case "encryptHistory":
          return this.encryptHistory(str(a), str(b));
        case "importHistoryKeys": {
          if (!Array.isArray(b) || !b.every((k) => Array.isArray(k) && typeof k[0] === "number" && k[1] instanceof Uint8Array)) throw new MlsError("invalid_id");
          return this.importHistoryKeys(str(a), b as [number, Uint8Array][]);
        }
        case "publishInboxKey":
          return this.publishInboxKey(str(a));
        case "setInboxWanted":
          this.setInboxWanted(str(a), b === true);
          return Promise.resolve(undefined);
        case "flushBackups":
          return this.flushBackups();
        case "restoreBackups":
          return this.restoreBackups();
        case "createKeyPackages":
          if (typeof a !== "number") throw new MlsError("invalid_id");
          return this.createKeyPackages(a);
        case "restoreBackup": {
          const q = str(a);
          splitQualified(q);
          return this.run(() => this.restoreOne(q));
        }
        default:
          return Promise.reject(new MlsError("invalid_id"));
      }
    } catch (e) {
      return Promise.reject(e);
    }
  }

  /**
   * Tab coordination: replaces the client state and the bookkeeping with the stored ones (the owning tab wrote
   * them, or this tab takes the state over), after every earlier operation. `load` returns null to keep the
   * current state; `then` runs inside the same step (before any later operation).
   */
  reloadState(load: () => Promise<{ client: Client; meta: MlsMeta } | null>, then?: () => void): Promise<void> {
    return this.run(async () => {
      if (this.disposed) return;
      const next = await load();
      if (next && !this.disposed) {
        const old = this.client;
        this.client = next.client;
        old.free();
        const meta = this.deps.meta as unknown as Record<string, unknown>;
        for (const k of Object.keys(meta)) delete meta[k];
        Object.assign(meta, normalizeMeta(next.meta, this.deps.homeDomain));
        // Keys may have arrived with the new state: failed messages are tried again.
        for (const [k, v] of [...this.decrypted]) if (!v.ok) this.decrypted.delete(k);
      } else {
        next?.client.free();
      }
      then?.();
    });
  }

  /** Runs `fn` after every earlier operation: the client is mutated by one operation at a time. */
  private run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => undefined);
    return next;
  }

  private async persist(): Promise<void> {
    await this.deps.persist(this.client);
  }

  /** Runs a client call; restores the previous state if `check` rejects the result. */
  private async guarded<T>(call: () => T, check: (r: T) => boolean): Promise<T | null> {
    const snapshot = this.client.exportState();
    try {
      const r = call();
      if (check(r)) return r;
      this.client.free();
      this.client = Client.importState(snapshot);
      return null;
    } finally {
      snapshot.fill(0);
    }
  }

  /** All methods below take qualified conversation ids (`<hosting node>/<ulid>`). */
  hasGroup(q: string): boolean {
    return this.client.hasGroup(q);
  }

  epoch(q: string): number | null {
    return this.client.hasGroup(q) ? this.client.currentEpoch(q) : null;
  }

  // ---- Joining ------------------------------------------------------------------------------

  /**
   * Makes this device a member of the conversation's group: pending Welcomes on the hosting node first,
   * then catch-up of an existing local group, otherwise an external join, or the group creation if none
   * exists and `canCreate` (the user may post). Returns `no_group` when there is nothing to join yet.
   */
  ensureJoined(q: string, opts: { canCreate: boolean }): Promise<"joined" | "no_group"> {
    const remote = this.forwarded<"joined" | "no_group">("ensureJoined", [q, { canCreate: opts.canCreate }]);
    if (remote) return remote;
    return this.run(async () => {
      const { domain } = splitQualified(q);
      if (!this.client.hasGroup(q)) await this.processWelcomesInner(domain);
      if (this.client.hasGroup(q)) {
        await this.catchUpInner(q);
        if (this.client.hasGroup(q)) return "joined";
      }
      return this.joinInner(q, opts.canCreate);
    });
  }

  private noteJoined(q: string) {
    const meta = this.deps.meta;
    meta.convs[q] = { rotatedAt: this.now() };
    void this.deps.saveMeta(meta);
    this.markDirty(q);
    this.deps.onEvent?.({ type: "epoch", conversationId: q });
    this.afterOwnCommit(q);
  }

  private async joinInner(q: string, canCreate: boolean): Promise<"joined" | "no_group"> {
    const ds = this.ds(q);
    for (let attempt = 0; attempt < MAX_TRIES; attempt++) {
      let info: GroupInfoResponse;
      try {
        info = await ds.api.groupInfo(ds.id);
      } catch (e) {
        if (apiCode(e) !== "mls.no_group") throw e;
        if (!canCreate) return "no_group";
        // Create the group; roll back if another device was first (its epoch 0 key differs from ours).
        const snapshot = this.client.exportState();
        try {
          const groupInfo = this.client.createGroup(q);
          await ds.api.createGroup(ds.id, b64urlEncode(groupInfo));
          await this.persist();
          this.noteJoined(q);
          return "joined";
        } catch (e2) {
          this.client.free();
          this.client = Client.importState(snapshot);
          if (apiCode(e2) === "mls.group_exists") continue;
          throw e2;
        } finally {
          snapshot.fill(0);
        }
      }
      const out = this.client.joinByExternalCommit(q, b64urlDecode(info.group_info));
      try {
        await ds.api.postCommit(ds.id, commitRequest(out));
      } catch (e) {
        this.client.discardPendingCommit(q);
        await this.persist();
        if (apiCode(e) === "mls.epoch_conflict") continue;
        throw e;
      } finally {
        out.free();
      }
      this.client.mergePendingCommit(q);
      await this.persist();
      this.noteJoined(q);
      return "joined";
    }
    throw new MlsError("conflict");
  }

  /**
   * Fetches and applies the Welcomes addressed to this device that wait on node `domain` (`mls.welcome`
   * of that node's socket, or after connecting to it). Returns the qualified ids joined.
   */
  processWelcomes(domain: string): Promise<string[]> {
    const remote = this.forwarded<string[]>("processWelcomes", [domain]);
    if (remote) return remote;
    return this.run(() => this.processWelcomesInner(domain));
  }

  private async processWelcomesInner(domain: string): Promise<string[]> {
    const joined: string[] = [];
    const api = this.deps.api.node(domain);
    const { items } = await api.welcomes();
    for (const w of items) {
      // §4.4: the Welcome must name the node that delivered it and the conversation it was delivered
      // for, so that no node can plant a group for a conversation of another node.
      const expected = qualify(domain, w.conversation_id);
      try {
        splitQualified(expected);
        const ok = await this.guarded(
          () => {
            const j = this.client.joinByWelcome(b64urlDecode(w.welcome));
            const conversation = j.conversation;
            j.free();
            return conversation;
          },
          (conversation) => conversation === expected,
        );
        if (ok) {
          await this.persist();
          this.noteJoined(expected);
          joined.push(expected);
        }
      } catch {
        /* already a member (joined otherwise) or invalid: drop it */
      }
      await api.deleteWelcome(w.id).catch(() => undefined);
    }
    for (const c of joined) await this.catchUpInner(c);
    return joined;
  }

  // ---- Handshake log --------------------------------------------------------------------------

  /** Processes the handshake log from the local epoch (after `mls.commit`). No-op without a local group. */
  catchUp(q: string): Promise<void> {
    const remote = this.forwarded<void>("catchUp", [q]);
    if (remote) return remote;
    return this.run(() => this.catchUpInner(q));
  }

  private async catchUpInner(q: string): Promise<void> {
    if (!this.client.hasGroup(q)) return;
    const ds = this.ds(q);
    for (let page = 0; page < 1000; page++) {
      const since = this.client.currentEpoch(q);
      const log = await ds.api.log(ds.id, since);
      let progressed = false;
      for (const item of log.items) {
        let outcome;
        try {
          outcome = this.client.processHandshake(q, b64urlDecode(item.commit));
        } catch (e) {
          if (cryptoCode(e) === "stale_epoch") continue;
          if (cryptoCode(e) === "not_member") {
            this.client.deleteGroup(q);
            await this.persist();
            this.deps.onEvent?.({ type: "removed", conversationId: q });
            return;
          }
          // §4.3: a commit that fails validation stops processing; rejoin and warn.
          this.client.deleteGroup(q);
          await this.persist();
          await this.joinInner(q, false).catch(() => "no_group");
          this.deps.onEvent?.({ type: "rejoined", conversationId: q });
          return;
        }
        progressed = true;
        const selfRemoved = outcome.selfRemoved;
        const removedByOther = outcome.removed.length > 0 && outcome.committer !== this.client.identity;
        outcome.free();
        if (selfRemoved) {
          this.client.deleteGroup(q);
          await this.persist();
          this.deps.onEvent?.({ type: "removed", conversationId: q });
          return;
        }
        if (removedByOther) {
          const meta = this.deps.meta;
          meta.convs[q] = { rotatedAt: meta.convs[q]?.rotatedAt ?? this.now(), rotate: true };
          void this.deps.saveMeta(meta);
        }
      }
      if (progressed) {
        await this.persist();
        this.markDirty(q);
        this.deps.onEvent?.({ type: "epoch", conversationId: q });
      }
      if (log.next == null || !progressed) return;
    }
  }

  /**
   * Two-phase commit (§4.3): `make` builds the commit from the current state (null = nothing to do);
   * on `409 mls.epoch_conflict` the pending commit is discarded, the log processed and `make` asked again.
   */
  private async commitInner(q: string, make: () => CommitOutput | null): Promise<boolean> {
    const ds = this.ds(q);
    for (let attempt = 0; attempt < MAX_TRIES; attempt++) {
      const out = make();
      if (!out) return false;
      try {
        await ds.api.postCommit(ds.id, commitRequest(out));
      } catch (e) {
        this.client.discardPendingCommit(q);
        await this.persist();
        if (apiCode(e) === "mls.epoch_conflict") {
          await this.catchUpInner(q);
          if (!this.client.hasGroup(q)) return false;
          continue;
        }
        throw e;
      } finally {
        out.free();
      }
      this.client.mergePendingCommit(q);
      await this.persist();
      const meta = this.deps.meta;
      meta.convs[q] = { rotatedAt: this.now() };
      void this.deps.saveMeta(meta);
      this.markDirty(q);
      this.deps.onEvent?.({ type: "epoch", conversationId: q });
      this.afterOwnCommit(q);
      return true;
    }
    throw new MlsError("conflict");
  }

  // ---- Inbox keys of write-only webhooks (ENCRYPTION.md §5b) ----------------------------------------

  /**
   * Marks an encrypted channel as having webhooks (its `has_webhooks`): this device then publishes the inbox key of
   * every epoch it commits. Turning it on also publishes the current epoch's key once, so a webhook waiting for a
   * key gets one. Channels without webhooks cost nothing (no derivation, no request).
   */
  setInboxWanted(q: string, wanted: boolean): void {
    if (this.deps.tabs && !this.deps.tabs.local()) {
      // Remembered here too (for a take-over); the owner publishes.
      if (wanted) this.inboxWanted.add(q);
      else this.inboxWanted.delete(q);
      void this.deps.tabs.forward("setInboxWanted", [q, wanted]).catch(() => undefined);
      return;
    }
    if (!wanted) {
      this.inboxWanted.delete(q);
      return;
    }
    if (this.inboxWanted.has(q)) return;
    this.inboxWanted.add(q);
    void this.publishInboxKey(q).catch(() => undefined);
  }

  /**
   * Publishes the inbox key of the current epoch (for example right after creating a webhook); once per epoch and
   * session. False without a local group (the webhook then waits until a member publishes).
   */
  async publishInboxKey(q: string): Promise<boolean> {
    const remote = this.forwarded<boolean>("publishInboxKey", [q]);
    if (remote) return remote;
    if (!this.client.hasGroup(q)) return false;
    const ds = this.ds(q);
    if (!ds.api.publishInboxKey) return false;
    const epoch = this.client.currentEpoch(q);
    if (this.inboxSent.get(q) === epoch) return true;
    const key = this.client.inboxKey(q, epoch);
    const body = { epoch, public_key: b64urlEncode(key.publicKey), signature: b64urlEncode(key.signature) };
    key.free();
    try {
      await ds.api.publishInboxKey(ds.id, body);
    } catch (e) {
      // A newer epoch is already published (another member was faster): nothing to do.
      if (apiCode(e) !== "inbox_key.stale") throw e;
    }
    this.inboxSent.set(q, epoch);
    return true;
  }

  private afterOwnCommit(q: string) {
    if (this.inboxWanted.has(q)) void this.publishInboxKey(q).catch(() => undefined);
  }

  /**
   * Commits a self update (fresh leaf key, new epoch). Voice joins do this so that every voice session
   * starts on a fresh frame key (ENCRYPTION.md §5a). `false` without a local group.
   */
  selfUpdate(q: string): Promise<boolean> {
    const remote = this.forwarded<boolean>("selfUpdate", [q]);
    if (remote) return remote;
    return this.run(async () => {
      if (!this.client.hasGroup(q)) return false;
      await this.catchUpInner(q);
      return this.commitInner(q, () => (this.client.hasGroup(q) ? this.client.selfUpdate(q) : null));
    });
  }

  /**
   * Voice frame key of the group's current epoch (ENCRYPTION.md §5a): 32 bytes of HKDF key material for
   * LiveKit's key provider. Never stored or sent anywhere. Null without a local group.
   */
  voiceKey(q: string): { epoch: number; key: Uint8Array } | null {
    if (!this.client.hasGroup(q)) return null;
    const epoch = this.client.currentEpoch(q);
    return { epoch, key: this.client.exportVoiceKey(q, epoch) };
  }

  /** `mls.remove_needed`: removes the listed leaves that are still in the group (callers check rights). */
  removeLeaves(q: string, identities: string[]): Promise<boolean> {
    const remote = this.forwarded<boolean>("removeLeaves", [q, identities]);
    if (remote) return remote;
    return this.run(async () => {
      if (!this.client.hasGroup(q)) return false;
      await this.catchUpInner(q);
      try {
        return await this.commitInner(q, () => {
          if (!this.client.hasGroup(q)) return null;
          const present = new Set(this.rosterIdentities(q));
          const targets = identities.filter((i) => present.has(i) && i !== this.client.identity);
          return targets.length ? this.client.removeMembers(q, targets) : null;
        });
      } catch (e) {
        // 403 mls.forbidden: the node still considers the leaves entitled (e.g. re-attested after a reset).
        if (apiCode(e) === "mls.forbidden") return false;
        throw e;
      }
    });
  }

  /**
   * DMs and group DMs (§4.2): adds every attested device of the members (addresses, of any node) that is
   * not in the group yet, via KeyPackages claimed through the hosting node and a Welcome. Devices are
   * the ones attested on the members' home nodes. Returns the other members without any device.
   */
  addMissingDevices(q: string, members: string[]): Promise<string[]> {
    const remote = this.forwarded<string[]>("addMissingDevices", [q, members]);
    if (remote) return remote;
    return this.run(async () => {
      const waiting: string[] = [];
      if (!this.client.hasGroup(q)) return waiting;
      const ds = this.ds(q);
      const own = this.client.identity;
      const candidates: { identity: string; keyPackage: Uint8Array }[] = [];
      const roster = new Set(this.rosterIdentities(q));
      for (const address of members) {
        try {
          const devices = await this.verifiedDevices(address);
          if (!devices || devices.size === 0) {
            if (address !== this.deps.address) waiting.push(address);
            continue;
          }
          const missing = [...devices.keys()].map((d) => `${address}/${d}`).filter((i) => i !== own && !roster.has(i));
          if (!missing.length) continue;
          const claimed = await ds.api.claim(address);
          for (const kp of claimed.key_packages) {
            const identity = `${address}/${kp.device_id}`;
            if (missing.includes(identity)) candidates.push({ identity, keyPackage: b64urlDecode(kp.key_package) });
          }
        } catch {
          /* unknown user or lookup failed: try again next time */
        }
      }
      if (candidates.length) {
        const added = await this.commitInner(q, () => {
          const present = new Set(this.rosterIdentities(q));
          const kps = candidates.filter((c) => !present.has(c.identity)).map((c) => c.keyPackage);
          return kps.length ? this.client.addMembers(q, kps) : null;
        });
        if (added) this.deps.onEvent?.({ type: "added", conversationId: q, addresses: [...new Set(candidates.map((c) => splitIdentity(c.identity).address))] });
      }
      return waiting;
    });
  }

  /**
   * Creates up to `count` KeyPackages (base64url, at most {@link MAX_KEY_PACKAGES}) in this device's client state and
   * persists it. `ensureDevice` tops up through it while a manager is open (its `keyPackages` option), so that the
   * private keys end up in the state that is written from now on (the owning tab's).
   */
  createKeyPackages(count: number): Promise<string[]> {
    const remote = this.forwarded<string[]>("createKeyPackages", [count]);
    if (remote) return remote;
    return this.run(async () => {
      const n = Math.max(0, Math.min(MAX_KEY_PACKAGES, Math.floor(count)));
      const out = Array.from({ length: n }, () => b64urlEncode(this.client.createKeyPackage()));
      if (n) await this.persist();
      return out;
    });
  }

  /** Leaf identities of the local group (empty without one). */
  roster(q: string): string[] {
    return this.client.hasGroup(q) ? this.rosterIdentities(q) : [];
  }

  /** This device's identity `<address>/<device id>`. */
  get identity(): string {
    return this.client.identity;
  }

  private rosterIdentities(q: string): string[] {
    return this.client.roster(q).map((e) => {
      const id = e.identity;
      e.free();
      return id;
    });
  }

  // ---- Content --------------------------------------------------------------------------------

  private rotationDue(conversationId: string): boolean {
    const c = this.deps.meta.convs[conversationId];
    return !c || !!c.rotate || this.now() - c.rotatedAt > ROTATE_AFTER_MS;
  }

  /**
   * Encrypts a content object for the current epoch (§5.2). Rotates the content key first when a
   * self update is due (weekly, or after a removal committed by someone else, §4.2).
   */
  encrypt(conversationId: string, content: Record<string, unknown>): Promise<{ content: string; epoch: number }> {
    // The node cannot see encrypted embeds: the sender checks them (APPLICATIONS.md §6.4).
    try {
      assertEmbeds(content);
    } catch (e) {
      return Promise.reject(e);
    }
    const remote = this.forwarded<{ content: string; epoch: number }>("encrypt", [conversationId, content]);
    if (remote) return remote;
    return this.run(async () => {
      const q = conversationId;
      // Senders use the current epoch (§5.2): pick up commits whose events may still be on the way.
      await this.catchUpInner(conversationId).catch(() => undefined);
      if (!this.client.hasGroup(q)) throw new MlsError("not_joined");
      if (this.rotationDue(conversationId)) {
        try {
          await this.commitInner(conversationId, () => (this.client.hasGroup(q) ? this.client.selfUpdate(q) : null));
        } catch {
          /* rotation is best effort; the message still goes out under the current key */
        }
        if (!this.client.hasGroup(q)) throw new MlsError("not_joined");
      }
      const ciphertext = this.client.encryptContent(q, JSON.stringify(content));
      return { content: ciphertext, epoch: this.client.currentEpoch(q) };
    });
  }

  /**
   * Decrypts and verifies an encrypted envelope; the result is cached for the session (not persisted). Content of
   * another purpose in the same format (a thread title, a history share) is `invalid` here: the node could otherwise
   * serve it as a message of its author, since format and AAD are the same (§5.2, §7b).
   */
  decrypt(conversationId: string, m: EncryptedEnvelope): Promise<Decrypted> {
    return this.decryptEnvelope(conversationId, m, "message");
  }

  private async decryptEnvelope(conversationId: string, m: EncryptedEnvelope, purpose: "message" | "title"): Promise<Decrypted> {
    const sealed = m.webhook ? sealedContent(m.content) : null;
    if (sealed) return purpose === "message" ? this.decryptSealed(conversationId, m, sealed) : { ok: false, reason: "invalid" };
    if (typeof m.content !== "string" || !m.device_id) return { ok: false, reason: "invalid" };
    const cacheKey = `${purpose}|${conversationId}|${m.id}|${m.content}`;
    const cached = this.decrypted.get(cacheKey);
    if (cached) return cached;
    const sentAt = m.created_at ? Date.parse(m.created_at) : NaN;
    let result = await this.decryptUncached(conversationId, m.id, m.author, m.device_id, m.epoch ?? null, m.content, Number.isFinite(sentAt) ? sentAt : null);
    if (result.ok && (purpose === "title") !== (result.content.type === THREAD_TITLE_TYPE)) result = { ok: false, reason: "invalid" };
    if (result.ok && NOT_CONTENT_TYPES.has(String(result.content.type))) result = { ok: false, reason: "invalid" };
    if (!result.ok && result.reason === "invalid") this.forgetNonce(conversationId, m.content, m.id);
    // Missing keys may arrive later (catch-up, backup): only final results are cached.
    if (result.ok || result.reason !== "missing_key") this.decrypted.set(cacheKey, result);
    return result;
  }

  /**
   * A sealed webhook message (APPLICATIONS.md §6.1a): opened with the inbox key of its epoch, derived from the
   * epoch's content key (current state, history backup or history share), then checked like a webhook payload.
   */
  private async decryptSealed(q: string, m: EncryptedEnvelope, s: SealedContent): Promise<Decrypted> {
    const cacheKey = `${q}|${m.id}|${s.sealed}`;
    const cached = this.decrypted.get(cacheKey);
    if (cached) return cached;
    if (m.device_id || m.epoch !== s.epoch) return { ok: false, reason: "invalid" };
    let bytes: Uint8Array;
    try {
      bytes = b64urlDecode(s.sealed);
    } catch {
      return { ok: false, reason: "invalid" };
    }
    for (let round = 0; round < 3; round++) {
      let result: Decrypted;
      try {
        const payload = webhookPayload(this.client.openSealed(q, s.epoch, bytes));
        result = payload ? { ok: true, content: payload.content, sealedBy: s.sealedBy, ...(payload.username ? { webhookName: payload.username } : {}) } : { ok: false, reason: "invalid" };
      } catch (e) {
        if (cryptoCode(e) === "unknown_epoch" && (await this.fetchMissingKey(q, s.epoch, round))) continue;
        result = { ok: false, reason: cryptoCode(e) === "unknown_epoch" ? "missing_key" : "invalid" };
      }
      if (result.ok || result.reason !== "missing_key") this.decrypted.set(cacheKey, result);
      return result;
    }
    return { ok: false, reason: "missing_key" };
  }

  /**
   * After `unknown_epoch`: catch up when the epoch is newer than the local one (first round), else restore the
   * history backup once per conversation and session. False when the key stays missing.
   */
  private async fetchMissingKey(q: string, epoch: number, round: number): Promise<boolean> {
    const local = this.epoch(q);
    if (round === 0 && local !== null && epoch > local) {
      await this.catchUp(q).catch(() => undefined);
      return true;
    }
    if (this.backupTried.has(q)) return false;
    this.backupTried.add(q);
    await (this.forwarded<void>("restoreBackup", [q]) ?? this.run(() => this.restoreOne(q))).catch(() => undefined);
    return true;
  }

  /**
   * Encrypts a thread title for an encrypted channel (PROTOCOL.md §7e): content format 1 of
   * `{ "type": "thread.title", "body" }` under the current epoch, sent as `title` with `title_epoch`.
   */
  async encryptThreadTitle(conversationId: string, title: string): Promise<{ title: string; title_epoch: number }> {
    const body = title.trim();
    if (!body || Array.from(body).length > THREAD_TITLE_MAX) throw new RangeError(`thread title: 1 to ${THREAD_TITLE_MAX} characters`);
    const { content, epoch } = await this.encrypt(conversationId, { type: "thread.title", body });
    return { title: content, title_epoch: epoch };
  }

  /**
   * Decrypts and verifies the title of a thread in an encrypted channel with its author and device. Anything that is
   * not a `thread.title` object with a body of 1–100 characters is `invalid` (the node cannot pass off message
   * content as a title: the type differs, and the same ciphertext seen twice is a replay).
   */
  async decryptThreadTitle(
    conversationId: string,
    t: { id: string; title: string; title_epoch?: number | null; title_author: string; title_device_id?: string | null; created_at?: string | null },
  ): Promise<{ ok: true; title: string } | { ok: false; reason: DecryptFailure }> {
    const r = await this.decryptEnvelope(conversationId, { id: `thread-title:${t.id}`, author: t.title_author, device_id: t.title_device_id ?? null, epoch: t.title_epoch ?? null, content: t.title, created_at: t.created_at ?? null }, "title");
    if (!r.ok) return r;
    const body = r.content.body;
    if (r.content.type !== "thread.title" || typeof body !== "string" || !body.trim() || Array.from(body).length > THREAD_TITLE_MAX) return { ok: false, reason: "invalid" };
    return { ok: true, title: body.trim() };
  }

  /** Synchronous lookup of an already decrypted message (pins panel, edits). */
  peek(conversationId: string, m: EncryptedEnvelope): Decrypted | undefined {
    const sealed = m.webhook ? sealedContent(m.content) : null;
    if (sealed) return this.decrypted.get(`${conversationId}|${m.id}|${sealed.sealed}`);
    return this.decrypted.get(`message|${conversationId}|${m.id}|${String(m.content)}`);
  }

  /**
   * Encrypts the content of an ephemeral event (PROTOCOL.md §6, whiteboard and cursors) exactly like a
   * message (§5.2), but under the local epoch without catching up or rotating first: ephemeral events
   * are frequent and short-lived, the node accepts any epoch it knows, and receivers catch up themselves.
   */
  encryptEphemeral(conversationId: string, content: Record<string, unknown>): Promise<string> {
    return this.run(async () => {
      if (!this.client.hasGroup(conversationId)) throw new MlsError("not_joined");
      return this.client.encryptContent(conversationId, JSON.stringify(content));
    });
  }

  /**
   * Decrypts and verifies the content of an ephemeral event sent by `author`/`deviceId`. Nothing is cached
   * (there may be dozens per second); a repeated `(epoch, nonce)` within the recent window is a replay.
   */
  async decryptEphemeral(conversationId: string, author: string, deviceId: string, content: unknown): Promise<Decrypted> {
    if (typeof content !== "string" || !deviceId) return { ok: false, reason: "invalid" };
    const header = contentHeader(content);
    if (!header) return { ok: false, reason: "invalid" };
    const replayKey = `${conversationId}|${header.epoch}|${header.nonce}`;
    if (this.ephemeralNonces.has(replayKey)) return { ok: false, reason: "replay" };
    let result = await this.decryptUncached(conversationId, `eph:${replayKey}`, author, deviceId, header.epoch, content);
    if (result.ok && (result.content.type === THREAD_TITLE_TYPE || NOT_CONTENT_TYPES.has(String(result.content.type)))) {
      this.nonces.delete(replayKey);
      return { ok: false, reason: "invalid" };
    }
    if (result.ok) {
      this.ephemeralNonces.add(replayKey);
      // A bounded window: the oldest nonces are forgotten first (Set keeps insertion order).
      if (this.ephemeralNonces.size > EPHEMERAL_REPLAY_WINDOW) {
        const oldest = this.ephemeralNonces.values().next().value;
        if (oldest !== undefined) this.ephemeralNonces.delete(oldest);
      }
      // decryptUncached remembers message nonces for good; ephemeral ones live only in the window above.
      this.nonces.delete(replayKey);
    }
    return result;
  }

  /** A ciphertext refused for its purpose does not count as seen: the genuine use of it is not a replay. */
  private forgetNonce(q: string, content: string, id: string) {
    const h = contentHeader(content);
    const key = h ? `${q}|${h.epoch}|${h.nonce}` : null;
    if (key && this.nonces.get(key) === id) this.nonces.delete(key);
  }

  private async decryptUncached(conversationId: string, id: string, author: string, deviceId: string, epoch: number | null, content: string, sentAt: number | null = null): Promise<Decrypted> {
    const header = contentHeader(content);
    // §5.2: the header epoch must equal the envelope epoch.
    if (!header || header.epoch !== epoch) return { ok: false, reason: "invalid" };
    const replayKey = `${conversationId}|${header.epoch}|${header.nonce}`;
    const q = conversationId;

    const attempt = async (): Promise<Decrypted> => {
      // §3.3: the author device must be attested under the pinned identity key; if it is in the
      // roster, its leaf key must be the attested key.
      let deviceKey = (await this.verifiedDevices(author))?.get(deviceId);
      if (!deviceKey) deviceKey = (await this.verifiedDevices(author, true))?.get(deviceId);
      // §5.2: a deleted device's history stays readable with its retired attestation, for what it sent before
      // its deletion (server time, with slack). Ephemeral events (no time) never come from retired devices.
      let retired = false;
      if (!deviceKey && sentAt !== null) {
        const r = this.retiredDevice(author, deviceId);
        if (r && sentAt <= r.deletedAt + RETIRED_SLACK_MS) {
          deviceKey = r.key;
          retired = true;
        }
      }
      if (!deviceKey) return { ok: false, reason: "unknown_device" };
      if (this.client.hasGroup(q)) {
        const leaf = this.client.roster(q).find((e) => e.identity === `${author}/${deviceId}`);
        if (leaf && !sameBytes(leaf.signatureKey, deviceKey)) return { ok: false, reason: "unknown_device" };
      }
      const json = this.client.decryptContent(q, author, deviceId, content, deviceKey);
      const parsed: unknown = JSON.parse(json);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { ok: false, reason: "invalid" };
      // Invalid embeds of another member are dropped, never shown (APPLICATIONS.md §6.4).
      const checked = withValidEmbeds(parsed as Record<string, unknown>);
      return retired ? { ok: true, content: checked, retired: true } : { ok: true, content: checked };
    };

    for (let round = 0; round < 3; round++) {
      try {
        const r = await attempt();
        if (!r.ok) return r;
        // §5.2: a second message with the same (epoch, nonce) is a replay.
        const seen = this.nonces.get(replayKey);
        if (seen && seen !== id) return { ok: false, reason: "replay" };
        this.nonces.set(replayKey, id);
        return r;
      } catch (e) {
        const code = cryptoCode(e);
        if (code === "bad_signature") return { ok: false, reason: "bad_signature" };
        if (code === "unknown_sender") return { ok: false, reason: "unknown_device" };
        if (code !== "unknown_epoch") return { ok: false, reason: "invalid" };
        if (!(await this.fetchMissingKey(conversationId, header.epoch, round))) return { ok: false, reason: "missing_key" };
      }
    }
    return { ok: false, reason: "missing_key" };
  }

  // ---- Plaintext signatures (FEDERATION.md §10.3) ----------------------------------------------

  /**
   * Signature of a plaintext message sent by this device: the covered envelope fields as they will be
   * stored (mentions normalized, attachments sorted by id) and the content object. Null if signing is
   * not possible (best effort until `content.signed1` is announced).
   */
  signPlaintext(conversationId: string, fields: Omit<SignedFields, "conversation" | "author" | "device_id">, content: Record<string, unknown>): string | null {
    try {
      const signed: SignedFields = { ...fields, conversation: conversationId, author: this.deps.address, device_id: this.deps.deviceId };
      return this.client.signPlaintext(JSON.stringify(signed), jcs(content));
    } catch {
      return null;
    }
  }

  /**
   * Checks the device signature of a plaintext message against the author's attested devices
   * (verified against the pinned identity key). Results are cached for the session.
   */
  async verifyPlaintext(conversationId: string, m: PlainEnvelope): Promise<PlainStatus> {
    if (!m.signature) return "unsigned";
    const cacheKey = `${conversationId}|${m.id}|${m.signature}`;
    const cached = this.plainChecked.get(cacheKey);
    if (cached) return cached;
    const fields = envelopeFields(conversationId, m);
    const nonce = signatureNonce(m.signature);
    if (!fields || !nonce || !m.content || typeof m.content !== "object" || Array.isArray(m.content)) return "invalid";
    let key: Uint8Array | undefined;
    try {
      key = (await this.verifiedDevices(m.author))?.get(fields.device_id) ?? (await this.verifiedDevices(m.author, true))?.get(fields.device_id);
    } catch {
      key = undefined;
    }
    // Unknown device key: may become known later (not cached).
    if (!key) return "unverifiable";
    let status: PlainStatus;
    try {
      status = verifyPlaintext(JSON.stringify(fields), jcs(m.content), m.signature, key) ? "valid" : "invalid";
    } catch {
      return "unverifiable";
    }
    if (status === "valid") {
      // A second message with the same nonce in a conversation is a replay (§10.3).
      const replayKey = `${conversationId}|${nonce}`;
      const seen = this.plainNonces.get(replayKey);
      if (seen && seen !== m.id) status = "replay";
      else this.plainNonces.set(replayKey, m.id);
    }
    this.plainChecked.set(cacheKey, status);
    return status;
  }

  // ---- Verified contacts (FEDERATION.md §10.1, §10.2) -------------------------------------------

  /** Verification state of a contact: compares the verified key with the currently pinned key. */
  verification(address: string): VerificationState {
    const v = this.verified[address];
    if (!v) return "unverified";
    const pinned = this.deps.pins[address]?.key;
    if (pinned === v.identity_public_key) return "verified";
    if (v.rotated_to && pinned === v.rotated_to) return "refresh";
    return "broken";
  }

  /** Verified, broken and to-be-refreshed contacts (for the UI store); a dismissed refresh notice is left out. */
  verificationStates(): Record<string, "verified" | "broken" | "refresh"> {
    const out: Record<string, "verified" | "broken" | "refresh"> = {};
    for (const address of Object.keys(this.verified)) {
      const state = this.verification(address);
      if (state === "refresh" && this.verified[address]?.refresh_dismissed) continue;
      if (state !== "unverified") out[address] = state;
    }
    return out;
  }

  /** Hides the "verification needs a refresh" notice of a contact (the safety number can be compared any time). */
  async dismissVerificationRefresh(address: string): Promise<void> {
    const v = this.verified[address];
    if (!v || this.verification(address) !== "refresh") return;
    v.refresh_dismissed = true;
    await this.deps.saveVerified?.(this.verified);
    this.deps.onEvent?.({ type: "verification", address });
  }

  verifiedContact(address: string): VerifiedContact | undefined {
    return this.verified[address];
  }

  /** The contact's pinned identity key (pinning it on first use); null if none is known. */
  private async contactKey(address: string): Promise<string | null> {
    if (address === this.deps.address) return null;
    if (!this.deps.pins[address]) await this.verifiedDevices(address).catch(() => null);
    return this.deps.pins[address]?.key ?? null;
  }

  /** Safety number (60 digits) and QR payload of this user and `address`; null without a pinned key. */
  async safetyNumber(address: string): Promise<{ number: string; payload: string } | null> {
    const contact = await this.contactKey(address);
    if (!contact) return null;
    const own = b64urlDecode(this.deps.ownIdentityKey());
    const theirs = b64urlDecode(contact);
    return { number: safetyNumber(this.deps.address, own, address, theirs), payload: verifyPayload(this.deps.address, own, address, theirs) };
  }

  /** Scanning rule (§10.1): the payload must name this user with the own key and the contact with the pin. */
  comparePayload(address: string, payload: string): boolean {
    const pin = this.deps.pins[address];
    if (!pin || address === this.deps.address) return false;
    try {
      return verifyPayloadMatches(payload, this.deps.address, b64urlDecode(this.deps.ownIdentityKey()), address, b64urlDecode(pin.key));
    } catch {
      return false;
    }
  }

  /** Marks the contact's currently pinned key as verified; also acknowledges a pending key change. */
  async markVerified(address: string, method: VerifiedContact["method"]): Promise<boolean> {
    const key = await this.contactKey(address);
    if (!key) return false;
    this.verified[address] = { address, identity_public_key: key, verified_at: new Date(this.now()).toISOString(), method };
    await this.deps.saveVerified?.(this.verified);
    await this.acknowledgeKeyChange(address);
    this.deps.onEvent?.({ type: "verification", address });
    return true;
  }

  async removeVerification(address: string): Promise<void> {
    if (!this.verified[address]) return;
    delete this.verified[address];
    await this.deps.saveVerified?.(this.verified);
    this.deps.onEvent?.({ type: "verification", address });
  }

  /** "I trust the new key": accepts a changed key without verification (the contact becomes unverified). */
  async acceptNewKey(address: string): Promise<void> {
    await this.removeVerification(address);
    await this.acknowledgeKeyChange(address);
  }

  // ---- Devices, pins, ghosts ------------------------------------------------------------------

  /**
   * Attested devices of `address` (device id → key), as published by the user's home node and verified
   * against the pinned identity key; null for malformed addresses. Pins on first use; a changed key is
   * re-pinned with `changed` set (the "security key changed" notice) and reported. Lookups are cached
   * for {@link KEY_TTL_MS} (devices added or removed elsewhere show up after that at the latest).
   */
  verifiedDevices(address: string, refresh = false): Promise<Map<string, Uint8Array> | null> {
    const cached = this.keyCache.get(address);
    // A refresh reuses a lookup that is still running or just finished (several misses at once).
    if (cached && (cached.pending || this.now() - cached.at < (refresh ? KEY_REFETCH_MS : KEY_TTL_MS))) return cached.devices;
    const entry = { at: this.now(), pending: true, devices: Promise.resolve<Map<string, Uint8Array> | null>(null) };
    entry.devices = this.loadDevices(address).then(
      (d) => {
        entry.pending = false;
        entry.at = this.now();
        return d;
      },
      (e: unknown) => {
        if (this.keyCache.get(address) === entry) this.keyCache.delete(address);
        throw e;
      },
    );
    this.keyCache.set(address, entry);
    return entry.devices;
  }

  private async loadDevices(address: string): Promise<Map<string, Uint8Array> | null> {
    if (address.indexOf("@") < 1) return null;
    // Always the user's home node (FEDERATION.md §3.5), whichever node hosts the conversation.
    const keys = await this.deps.api.keys(address);
    const out = new Map<string, Uint8Array>();
    if (keys.user !== address) return out;
    // Older nodes do not send `kind`: their accounts count as users.
    this.kinds.set(address, typeof keys.kind === "string" ? keys.kind : "user");
    if (!keys.identity_public_key) return out;
    const published = keys.identity_public_key;
    let trusted = published;
    if (address === this.deps.address) {
      trusted = this.deps.ownIdentityKey();
    } else {
      const pin = this.deps.pins[address];
      if (!pin) {
        this.deps.pins[address] = { key: published };
        await this.deps.savePins(this.deps.pins);
      } else if (pin.key !== published && chainReaches(keys.continuity, pin.key, published)) {
        // Rotation with continuity (§9a): signed by the pinned key, pinned at once with a soft notice. An earlier,
        // unacknowledged change keeps its warning. A verified contact needs a fresh verification (not blocking).
        this.deps.pins[address] = pin.changed ? { key: published, changed: true, rotated: true } : { key: published, rotated: true };
        await this.deps.savePins(this.deps.pins);
        const v = this.verified[address];
        if (v && (v.identity_public_key === pin.key || v.rotated_to === pin.key)) {
          v.rotated_to = published;
          delete v.refresh_dismissed;
          await this.deps.saveVerified?.(this.verified);
        }
        this.deps.onEvent?.({ type: "key_rotated", address });
      } else if (pin.key !== published) {
        this.deps.pins[address] = { key: published, changed: true };
        await this.deps.savePins(this.deps.pins);
        this.deps.onEvent?.({ type: "key_changed", address });
      }
    }
    if (published !== trusted) return out;
    const identityKey = b64urlDecode(trusted);
    // Keys before the current one on the valid chain: retired devices attested under them stay verifiable (§3.3).
    const previous = keys.continuity?.length ? chainKeys(keys.continuity, trusted) : null;
    for (const d of keys.devices) {
      try {
        const pk = b64urlDecode(d.device_public_key);
        if (verifyDeviceAttestation(address, d.device_id, pk, b64urlDecode(d.identity_signature), identityKey)) out.set(d.device_id, pk);
      } catch {
        /* malformed entry: not verified */
      }
    }
    // Retired devices (§2.3): verified under the same pinned key; only used for history (§5.2).
    const retired = new Map<string, { key: Uint8Array; deletedAt: number }>();
    for (const d of keys.retired ?? []) {
      try {
        const pk = b64urlDecode(d.device_public_key);
        const deletedAt = Date.parse(d.deleted_at);
        if (out.has(d.device_id) || !Number.isFinite(deletedAt)) continue;
        const under = d.attested_identity_key && previous?.has(d.attested_identity_key) ? b64urlDecode(d.attested_identity_key) : identityKey;
        if (verifyDeviceAttestation(address, d.device_id, pk, b64urlDecode(d.identity_signature), under)) retired.set(d.device_id, { key: pk, deletedAt });
      } catch {
        /* malformed entry: not verified */
      }
    }
    this.retiredKeys.set(address, retired);
    return out;
  }

  /**
   * The verified retired attestation of `address`/`deviceId` from the last device lookup (call
   * {@link verifiedDevices} first), or undefined.
   */
  retiredDevice(address: string, deviceId: string): { key: Uint8Array; deletedAt: number } | undefined {
    return this.retiredKeys.get(address)?.get(deviceId);
  }

  /** Leaves of the local group with their signature keys (empty without one). */
  rosterEntries(q: string): { identity: string; key: Uint8Array }[] {
    if (!this.client.hasGroup(q)) return [];
    return this.client.roster(q).map((e) => {
      const r = { identity: e.identity, key: e.signatureKey };
      e.free();
      return r;
    });
  }

  /**
   * Drops the cached devices of a user (devices changed, a device re-attested as retired); the next lookup asks the
   * node again, and failed results of that user's messages are tried again.
   */
  forgetDevices(address: string): void {
    this.keyCache.delete(address);
    for (const [k, v] of [...this.decrypted]) if (!v.ok) this.decrypted.delete(k);
  }

  /** `identity.changed` of another user: drop cached devices so the next lookup re-pins (with notice). */
  identityChanged(address: string): void {
    this.keyCache.delete(address);
    for (const [k, v] of [...this.decrypted]) if (!v.ok) this.decrypted.delete(k);
    for (const [k, v] of [...this.plainChecked]) if (v !== "valid") this.plainChecked.delete(k);
  }

  /** Users whose identity key changed and whose notice is not acknowledged yet. */
  changedKeys(): string[] {
    return Object.entries(this.deps.pins)
      .filter(([, p]) => p.changed)
      .map(([a]) => a);
  }

  /** Users whose key was rotated with continuity and whose soft notice is not dismissed yet (and nothing worse). */
  rotatedKeys(): string[] {
    return Object.entries(this.deps.pins)
      .filter(([, p]) => p.rotated && !p.changed)
      .map(([a]) => a);
  }

  /** Acknowledges the warning of a changed key and dismisses the notice of a rotated one. */
  async acknowledgeKeyChange(address: string): Promise<void> {
    const pin = this.deps.pins[address];
    if (!pin?.changed && !pin?.rotated) return;
    this.deps.pins[address] = { key: pin.key };
    await this.deps.savePins(this.deps.pins);
  }

  /**
   * `kind` of `address` as its home node published it with its keys (`user`, `bot`, …), or undefined before the
   * first lookup ({@link verifiedDevices}).
   */
  kindOf(address: string): string | undefined {
    return this.kinds.get(address);
  }

  /**
   * Ghost member check (§4.6): every leaf's user must be in `members` (addresses), every leaf must
   * carry an attested key under the pinned identity key, and no identity may appear twice. With `noBots`
   * (the conversation's effective "no bots" flag) a leaf of a bot is a ghost as well, whatever the member
   * list says: `kind` comes from the bot's home node, so a lying room node cannot disguise it (APPLICATIONS.md §3.5).
   */
  async ghostCheck(q: string, members: Iterable<string>, opts: GhostCheckOptions = {}): Promise<GhostViolation[]> {
    if (!this.client.hasGroup(q)) return [];
    const entries = this.client.roster(q).map((e) => {
      const r = { identity: e.identity, key: e.signatureKey };
      e.free();
      return r;
    });
    const allowed = new Set(members);
    const seen = new Set<string>();
    const refreshed = new Set<string>();
    const out: GhostViolation[] = [];
    for (const e of entries) {
      if (seen.has(e.identity)) {
        out.push({ identity: e.identity, reason: "duplicate" });
        continue;
      }
      seen.add(e.identity);
      const { address, deviceId } = splitIdentity(e.identity);
      if (!allowed.has(address)) {
        out.push({ identity: e.identity, reason: "not_member" });
        continue;
      }
      let key: Uint8Array | undefined;
      try {
        if (opts.fresh && !refreshed.has(address)) {
          // Before acting on a violation: look the user's devices up again.
          refreshed.add(address);
          if (!this.keyCache.get(address)?.pending) this.keyCache.delete(address);
        }
        key = (await this.verifiedDevices(address))?.get(deviceId) ?? (await this.verifiedDevices(address, true))?.get(deviceId);
      } catch {
        key = undefined;
      }
      if (opts.noBots && isBotKind(this.kinds.get(address))) {
        out.push({ identity: e.identity, reason: "bot" });
        continue;
      }
      if (!key || !sameBytes(key, e.key)) out.push({ identity: e.identity, reason: "unattested" });
    }
    return out;
  }

  // ---- Backup ---------------------------------------------------------------------------------

  private markDirty(conversationId: string) {
    if (this.disposed) return;
    this.dirty.add(conversationId);
    this.savePending();
    if (this.backupTimer) clearTimeout(this.backupTimer);
    this.backupTimer = setTimeout(() => {
      this.backupTimer = null;
      void this.flushBackups().catch(() => undefined);
    }, this.deps.backupDelayMs ?? 1000);
  }

  private savePending() {
    const meta = this.deps.meta;
    meta.pendingBackups = [...this.dirty];
    void this.deps.saveMeta(meta);
  }

  /** Whether epoch keys of some conversation still wait for their backup upload (e.g. after a restart). */
  hasPendingBackups(): boolean {
    return this.dirty.size > 0 || !!this.deps.meta.pendingBackups?.length;
  }

  /** Uploads the backups of conversations with new epoch keys (merge with the stored blob, If-Match). */
  flushBackups(): Promise<void> {
    const remote = this.forwarded<void>("flushBackups", []);
    if (remote) return remote;
    return this.run(async () => {
      for (const c of this.deps.meta.pendingBackups ?? []) this.dirty.add(c);
      for (const c of [...this.dirty]) {
        this.dirty.delete(c);
        try {
          await this.backupOne(c);
        } catch {
          this.dirty.add(c); // retried with the next change or start
        }
      }
      this.savePending();
    });
  }

  /** Backups live on the home node under the hosting node's domain and the conversation ULID (§7). */
  private async backupOne(q: string): Promise<void> {
    const { domain, id } = splitQualified(q);
    const key = this.deps.backupKey();
    try {
      for (let attempt = 0; attempt < MAX_TRIES; attempt++) {
        const remote = await this.deps.api.backupGet(domain, id);
        if (remote) {
          try {
            this.client.importBackup(q, key, remote.blob); // keys are never overwritten
          } catch {
            /* unreadable (older identity): replaced by ours */
          }
        }
        const blob = this.client.exportBackup(q, key);
        try {
          await this.deps.api.backupPut(domain, id, blob, remote?.etag ?? null);
          await this.persist();
          return;
        } catch (e) {
          if (apiCode(e) !== "backup.etag_mismatch") throw e;
        }
      }
    } finally {
      key.fill(0);
    }
  }

  private async restoreOne(q: string): Promise<void> {
    const { domain, id } = splitQualified(q);
    const remote = await this.deps.api.backupGet(domain, id);
    if (!remote) return;
    const key = this.deps.backupKey();
    try {
      this.client.importBackup(q, key, remote.blob);
      await this.persist();
    } finally {
      key.fill(0);
    }
  }

  /** New device (§8 step 3): imports every backup of the account once. */
  restoreBackups(): Promise<number> {
    const remote = this.forwarded<number>("restoreBackups", []);
    if (remote) return remote;
    return this.run(async () => {
      if (this.deps.meta.restored) return 0;
      const { items } = await this.deps.api.backupList();
      const key = this.deps.backupKey();
      let n = 0;
      try {
        for (const item of items) {
          const slash = item.conversation.indexOf("/");
          const domain = item.conversation.slice(0, slash);
          const ulid = item.conversation.slice(slash + 1);
          try {
            const remote = await this.deps.api.backupGet(domain, ulid);
            if (remote) n += this.client.importBackup(item.conversation, key, remote.blob);
          } catch {
            /* one unreadable backup does not stop the others */
          }
        }
      } finally {
        key.fill(0);
      }
      await this.persist();
      this.deps.meta.restored = true;
      await this.deps.saveMeta(this.deps.meta);
      return n;
    });
  }

  // ---- History keys for new members (ENCRYPTION.md §7b) ------------------------------------------

  /** Epochs whose content key this device holds, ascending. */
  knownEpochs(q: string): number[] {
    return [...this.client.knownEpochs(q)].sort((a, b) => a - b);
  }

  /** Copies of the content keys of `epochs` this device holds; the caller zeroes them after use. */
  exportEpochKeys(q: string, epochs: number[]): [number, Uint8Array][] {
    const known = new Set(this.client.knownEpochs(q));
    return epochs.filter((e) => known.has(e)).map((e) => [e, this.client.exportEpochKey(q, e)]);
  }

  /**
   * Encrypts a history share payload (canonical JSON) like message content under the group's current
   * epoch, after catching up, without rotating: only current members can read it.
   */
  encryptHistory(q: string, json: string): Promise<{ content: string; epoch: number }> {
    const remote = this.forwarded<{ content: string; epoch: number }>("encryptHistory", [q, json]);
    if (remote) return remote;
    return this.run(async () => {
      await this.catchUpInner(q).catch(() => undefined);
      if (!this.client.hasGroup(q)) throw new MlsError("not_joined");
      return { content: this.client.encryptContent(q, json), epoch: this.client.currentEpoch(q) };
    });
  }

  /**
   * Decrypts a history share sent by `author`/`deviceId` and verifies the device signature against the
   * author's attested device (pinned identity key). Nothing is cached (shares never enter the message cache).
   */
  async decryptHistory(q: string, shareId: string, author: string, deviceId: string, content: string): Promise<Decrypted> {
    const header = contentHeader(content);
    if (!header) return { ok: false, reason: "invalid" };
    return this.decryptUncached(q, `history:${shareId}`, author, deviceId, header.epoch, content);
  }

  /**
   * Stores accepted history keys (validated by the caller) in the client state, exactly like own epoch keys:
   * persisted in the encrypted key store and included in the history backup. Keys never overwrite known
   * ones. Returns the number of new keys.
   */
  importHistoryKeys(q: string, keys: [number, Uint8Array][]): Promise<number> {
    const remote = this.forwarded<number>("importHistoryKeys", [q, keys]);
    if (remote) return remote;
    return this.run(async () => {
      const known = new Set(this.client.knownEpochs(q));
      let n = 0;
      for (const [epoch, key] of keys) {
        if (known.has(epoch)) continue;
        this.client.importEpochKey(q, epoch, key);
        known.add(epoch);
        n++;
      }
      if (n === 0) return 0;
      await this.persist();
      // Messages that failed with a missing key are decrypted again.
      for (const [k, v] of [...this.decrypted]) if (!v.ok && [`${q}|`, `message|${q}|`, `title|${q}|`].some((p) => k.startsWith(p))) this.decrypted.delete(k);
      this.markDirty(q);
      this.deps.onEvent?.({ type: "epoch", conversationId: q });
      return n;
    });
  }

  /** Stops timers and frees the client (sign-out, identity change). */
  dispose(): void {
    this.disposed = true;
    this.deps.tabs?.close();
    if (this.backupTimer) clearTimeout(this.backupTimer);
    this.decrypted.clear();
    this.plainChecked.clear();
    this.ephemeralNonces.clear();
    void this.queue.then(() => this.client.free());
  }
}

function commitRequest(out: CommitOutput): CommitRequest {
  const welcome = out.welcome;
  return { epoch: out.epoch, commit: b64urlEncode(out.commit), group_info: b64urlEncode(out.groupInfo), welcome: welcome ? b64urlEncode(welcome) : null };
}
