// SPDX-License-Identifier: MPL-2.0
// In-memory nodes for the session manager tests: delivery services that follow the node's rules for
// epochs, the handshake log, Welcomes and backups, keys and KeyPackages of each node's own users, the
// claim proxy for users of other nodes (FEDERATION.md §3.5, §6).
import { verifyContinuity, verifyDeviceAttestation, verifyDeviceShareKey, type MasterSecret } from "@tavrn/crypto";
import { TavrnApiError, b64urlDecode, b64urlEncode, type CommitRequest, type TavrnApi, type UserKeys } from "@tavrn/sdk";
import type { MlsApi, MlsNodeApi } from "../src/mls";

export function problem(status: number, code: string, meta?: unknown) {
  return new TavrnApiError({ type: "x", title: code, status, detail: "", code, meta } as never);
}

export const domainOf = (address: string) => address.slice(address.lastIndexOf("@") + 1);

/** The node's check of a published share key (ENCRYPTION.md §3.1). */
function checkShare(deviceId: string, devicePk: string, spk: string, ssig: string): { spk: string; ssig: string } {
  if (!verifyDeviceShareKey(deviceId, b64urlDecode(devicePk), b64urlDecode(spk), b64urlDecode(ssig))) throw problem(400, "e2ee.share_key_invalid");
  return { spk, ssig };
}

export interface UserRecord {
  identity: string;
  /** Device keys with their attestation and, once published, the share key and its device signature (§3.1). */
  devices: Map<string, { pk: string; sig: string; spk?: string; ssig?: string }>;
  kps: Map<string, string[]>;
  /** Deleted devices with their attestation (ENCRYPTION.md §2.3); `under` = the key it was attested under. */
  retired?: Map<string, { pk: string; sig: string; deletedAt: string; under?: string }>;
  /** Continuity chain (ENCRYPTION.md §9a), oldest first, and the wrapped current key. */
  continuity?: { old_key: string; new_key: string; at: string; sig_old: string; sig_new: string }[];
  blob?: string;
  /** `kind` of the keys document (ENCRYPTION.md §2.3); `user` when absent. */
  kind?: string;
}

/**
 * In-memory node: delivery service (§4.4) for the conversations it hosts, keys and KeyPackages of its
 * own users (§3), the claim proxy for users of other nodes (FEDERATION.md §3.5), backups with ETags (§7).
 */
export class FakeNode {
  users = new Map<string, UserRecord>();
  groups = new Map<string, { epoch: number; groupInfo: string; log: Map<number, string> }>();
  /** Welcomes by device identity (`address/device`). */
  welcomes = new Map<string, { id: string; conversation_id: string; epoch: number; welcome: string; created_at: string }[]>();
  backups = new Map<string, { blob: Uint8Array; etag: string }>();
  /** Device identities whose KeyPackages a session claimed (they get the Welcome of its next commit). */
  claimed = new Map<string, string[]>();
  /** Claims forwarded to other nodes (address list). */
  proxied: string[] = [];
  /** Requests served by the delivery service (for "which node was asked" checks). */
  dsCalls = 0;
  failNextPut = false;
  /** The next this many handshake log requests fail like a lost connection. */
  failLog = 0;
  /** Handshake log requests served (round trips of catch-ups). */
  logCalls = 0;
  counter = 0;
  /** Secret storage entries (method → wrapped) per username. */
  secrets = new Map<string, Map<string, string>>();
  /** Published inbox keys of write-only webhooks per conversation, and every publication (ENCRYPTION.md §5b). */
  inboxKeys = new Map<string, { epoch: number; public_key: string }>();
  inboxPublications: { conversation: string; epoch: number; by: string }[] = [];

  constructor(
    readonly domain: string,
    private readonly net: Network,
  ) {}

  addUser(username: string, master: MasterSecret) {
    this.users.set(username, { identity: b64urlEncode(master.identityPublicKey()), devices: new Map(), kps: new Map() });
  }

  /**
   * Account routes of one of the node's users (`keys` and `secretStorage`, as the account flows use
   * them): the identity key is set once, device keys must be attested under it, KeyPackages are counted.
   */
  accountApi(username: string): Pick<TavrnApi, "keys" | "secretStorage"> {
    const address = `${username}@${this.domain}`;
    const user = () => this.users.get(username);
    const entries = this.secrets.get(username) ?? new Map<string, string>();
    this.secrets.set(username, entries);
    const api = {
      keys: {
        get: async (u: string) => (this.users.has(u) ? this.keysOf(`${u}@${this.domain}`) : { user: `${u}@${this.domain}`, identity_public_key: null, identity_reset_at: null, devices: [] }),
        // The node's checks of a rotation (ENCRYPTION.md §9a), without the clock and the rate limit.
        rotateIdentity: async (req: { new_identity_public_key: string; continuity: NonNullable<UserRecord["continuity"]>[number]; identity_blob: string; attestations: { device_id: string; identity_signature: string }[] }) => {
          const u = user()!;
          const c = req.continuity;
          if (c.old_key !== u.identity || c.new_key !== req.new_identity_public_key || !verifyContinuity(JSON.stringify(c))) throw problem(400, "e2ee.continuity_invalid");
          for (const [id, d] of u.devices) {
            const a = req.attestations.find((x) => x.device_id === id);
            if (!a || !verifyDeviceAttestation(address, id, b64urlDecode(d.pk), b64urlDecode(a.identity_signature), b64urlDecode(c.new_key))) throw problem(400, "e2ee.rotation_incomplete");
          }
          for (const a of req.attestations) u.devices.get(a.device_id)!.sig = a.identity_signature;
          u.identity = c.new_key;
          u.continuity = [...(u.continuity ?? []), c];
          u.blob = req.identity_blob;
          return { identity_public_key: c.new_key, identity_generation: u.continuity.length };
        },
        identityBlob: async () => {
          const u = user();
          if (!u?.blob) throw problem(404, "e2ee.identity_blob_not_found");
          return { identity_blob: u.blob, identity_generation: u.continuity?.length ?? 0, identity_public_key: u.identity };
        },
        putIdentity: async ({ identity_public_key }: { identity_public_key: string }) => {
          if (user()) throw problem(409, "e2ee.identity_exists");
          this.users.set(username, { identity: identity_public_key, devices: new Map(), kps: new Map() });
        },
        putDeviceKey: async (deviceId: string, req: { device_public_key: string; identity_signature: string; share_public_key?: string; share_key_signature?: string }) => {
          const u = user();
          if (!u || !verifyDeviceAttestation(address, deviceId, b64urlDecode(req.device_public_key), b64urlDecode(req.identity_signature), b64urlDecode(u.identity))) throw problem(400, "e2ee.attestation_invalid");
          if (u.devices.has(deviceId)) throw problem(409, "e2ee.device_key_exists");
          const share = req.share_public_key && req.share_key_signature ? checkShare(deviceId, req.device_public_key, req.share_public_key, req.share_key_signature) : {};
          u.devices.set(deviceId, { pk: req.device_public_key, sig: req.identity_signature, ...share });
        },
        // ENCRYPTION.md §3.1: once per device, checked against the device key; the same key again is fine.
        putShareKey: async (deviceId: string, req: { share_public_key: string; share_key_signature: string }) => {
          this.shareKeyPuts++;
          const d = user()?.devices.get(deviceId);
          if (!d) throw problem(403, "e2ee.device_not_attested");
          const share = checkShare(deviceId, d.pk, req.share_public_key, req.share_key_signature);
          if (d.spk && d.spk !== share.spk) throw problem(409, "e2ee.share_key_exists");
          Object.assign(d, share);
        },
        countKeyPackages: async (deviceId: string) => ({ count: user()?.kps.get(deviceId)?.length ?? 0 }),
        uploadKeyPackages: async (deviceId: string, req: { key_packages: string[] }) => {
          const list = user()!.kps.get(deviceId) ?? [];
          list.push(...req.key_packages);
          user()!.kps.set(deviceId, list);
          return { count: list.length };
        },
      },
      secretStorage: {
        list: async () => ({ items: [...entries].map(([method, wrapped]) => ({ method, wrapped, params: {}, updated_at: "" })) }),
        putRecovery: async (req: { wrapped: string }) => void entries.set("recovery", req.wrapped),
        putPasskey: async (id: string, req: { wrapped: string }) => void entries.set(`passkey:${id}`, req.wrapped),
      },
    };
    return api as unknown as Pick<TavrnApi, "keys" | "secretStorage">;
  }

  /** Calls of `PUT …/share-key`. */
  shareKeyPuts = 0;

  /** The node's own users: one KeyPackage per device (single use). */
  claimLocal(address: string): { device_id: string; key_package: string }[] {
    const user = domainOf(address) === this.domain ? this.users.get(address.slice(0, address.lastIndexOf("@"))) : undefined;
    if (!user) throw problem(404, "user.not_found");
    const out: { device_id: string; key_package: string }[] = [];
    for (const [d, list] of user.kps) {
      const kp = list.shift();
      if (kp) out.push({ device_id: d, key_package: kp });
    }
    return out;
  }

  keysOf(address: string): UserKeys {
    const username = address.slice(0, address.lastIndexOf("@"));
    const user = domainOf(address) === this.domain ? this.users.get(username) : undefined;
    if (!user) throw problem(404, "user.not_found");
    return {
      user: `${username}@${this.domain}`,
      identity_public_key: user.identity,
      identity_reset_at: null,
      devices: [...user.devices].map(([device_id, d]) => ({ device_id, device_public_key: d.pk, identity_signature: d.sig, created_at: "", share_public_key: d.spk ?? null, share_key_signature: d.ssig ?? null })),
      retired: [...(user.retired ?? new Map())].map(([device_id, d]) => ({ device_id, device_public_key: d.pk, identity_signature: d.sig, attested_identity_key: d.under ?? user.identity, deleted_at: d.deletedAt })),
      continuity: user.continuity ?? [],
      identity_generation: user.continuity?.length ?? 0,
      kind: user.kind ?? "user",
    };
  }

  /** The delivery service as seen by one device session (local or federated). */
  ds(address: string, deviceId: string): MlsNodeApi {
    const self = `${address}/${deviceId}`;
    const group = (c: string) => {
      this.dsCalls++;
      const g = this.groups.get(c);
      if (!g) throw problem(404, "mls.no_group");
      return g;
    };
    return {
      groupInfo: async (c) => ({ epoch: group(c).epoch, group_info: group(c).groupInfo }),
      createGroup: async (c, gi) => {
        this.dsCalls++;
        if (this.groups.has(c)) throw problem(409, "mls.group_exists");
        this.groups.set(c, { epoch: 0, groupInfo: gi, log: new Map() });
        return { epoch: 0 };
      },
      postCommit: async (c, req: CommitRequest) => {
        const g = group(c);
        if (req.epoch !== g.epoch) throw problem(409, "mls.epoch_conflict", { epoch: g.epoch });
        g.log.set(g.epoch, req.commit);
        g.epoch += 1;
        g.groupInfo = req.group_info;
        if (req.welcome) {
          for (const d of this.claimed.get(self) ?? []) {
            const list = this.welcomes.get(d) ?? [];
            list.push({ id: `w${++this.counter}`, conversation_id: c, epoch: g.epoch, welcome: req.welcome, created_at: "" });
            this.welcomes.set(d, list);
          }
        }
        this.claimed.delete(self);
        return { epoch: g.epoch };
      },
      log: async (c, since) => {
        this.logCalls++;
        if (this.failLog > 0) {
          this.failLog--;
          throw new TypeError("Failed to fetch");
        }
        const g = group(c);
        const items = [...g.log.entries()].filter(([e]) => e >= since).sort(([x], [y]) => x - y).map(([epoch, commit]) => ({ epoch, commit }));
        return { items, next: null };
      },
      welcomes: async () => ({ items: [...(this.welcomes.get(self) ?? [])] }),
      deleteWelcome: async (id) => {
        this.welcomes.set(self, (this.welcomes.get(self) ?? []).filter((w) => w.id !== id));
      },
      claim: async (target) => {
        let out: { device_id: string; key_package: string }[];
        if (domainOf(target) === this.domain) {
          out = this.claimLocal(target);
        } else {
          // Claim proxy: the user's home node answers (S2S claim).
          this.proxied.push(target);
          out = this.net.node(domainOf(target)).claimLocal(target);
        }
        this.claimed.set(self, [...(this.claimed.get(self) ?? []), ...out.map((k) => `${target}/${k.device_id}`)]);
        return { key_packages: out };
      },
      // Newer epochs only; the same key again is fine (the node also checks the device signature).
      publishInboxKey: async (c, req) => {
        const current = this.inboxKeys.get(c);
        if (req.epoch > group(c).epoch) throw problem(400, "inbox_key.invalid");
        this.inboxPublications.push({ conversation: c, epoch: req.epoch, by: self });
        if (current && (current.epoch > req.epoch || (current.epoch === req.epoch && current.public_key !== req.public_key))) throw problem(409, "inbox_key.stale", { epoch: current.epoch });
        this.inboxKeys.set(c, { epoch: req.epoch, public_key: req.public_key });
        return { ...req, algorithm: "x25519-xsalsa20poly1305-sealedbox" };
      },
    };
  }
}

export class Network {
  nodes = new Map<string, FakeNode>();
  /** Domains asked for keys, per address. */
  keyLookups: string[] = [];

  node(domain: string): FakeNode {
    let n = this.nodes.get(domain);
    if (!n) {
      n = new FakeNode(domain, this);
      this.nodes.set(domain, n);
    }
    return n;
  }

  /** The API of one device: delivery service of any node, keys from home nodes, backups on its own home. */
  api(address: string, deviceId: string): MlsApi {
    const home = this.node(domainOf(address));
    return {
      node: (domain) => this.node(domain).ds(address, deviceId),
      keys: async (target) => {
        this.keyLookups.push(`${target}→${domainOf(target)}`);
        return this.node(domainOf(target)).keysOf(target);
      },
      backupList: async () => ({
        items: [...home.backups.entries()].filter(([k]) => k.startsWith(`${address}|`)).map(([k, v]) => ({ conversation: k.split("|")[1]!, size: v.blob.length, etag: v.etag, updated_at: "" })),
      }),
      backupGet: async (domain, ulid) => home.backups.get(`${address}|${domain}/${ulid}`) ?? null,
      backupPut: async (domain, ulid, blob, etag) => {
        const key = `${address}|${domain}/${ulid}`;
        const current = home.backups.get(key);
        if (home.failNextPut || (current ? current.etag !== etag : etag !== null)) {
          home.failNextPut = false;
          throw problem(412, "backup.etag_mismatch");
        }
        home.backups.set(key, { blob: blob.slice(), etag: `"${++home.counter}"` });
      },
    };
  }
}
