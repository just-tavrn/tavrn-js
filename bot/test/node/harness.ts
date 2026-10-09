// SPDX-License-Identifier: Apache-2.0
/**
 * In-process test nodes for the bot runtime's integration tests (APPLICATIONS.md §11: "SDK tests run Vitest against
 * an in-process node started by the test harness"): starts the `tavrn-node` binary named by `TAVRN_NODE_BIN` with
 * `--dev`, its own SQLite database and data directory in a temporary directory, on a free port, optionally federated
 * with other test nodes through `TAVRN_FEDERATION_DEV_PEERS`. Users are registered over the API with TOTP and get
 * end-to-end encryption through `@tavrn/e2ee` with an in-memory key store.
 *
 * The tests in this directory are opt-in: `vitest.config.ts` leaves them out unless `TAVRN_NODE_BIN` is set (a debug
 * build of tavrn-node, or the binary copied out of the node's container image).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHmac } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RecoveryKey } from "@tavrn/crypto";
import { MemoryKeyStore, ensureCrypto, mlsApiOf, openMlsManager, qualify, setupAccount, type MlsManager } from "@tavrn/e2ee";
import { TavrnApi, type RoomDetail, type UserPrivate } from "@tavrn/sdk";

export function nodeBinary(): string {
  const bin = process.env.TAVRN_NODE_BIN;
  if (!bin) throw new Error("TAVRN_NODE_BIN is not set: point it at a tavrn-node binary to run the integration tests");
  if (!existsSync(bin)) throw new Error(`TAVRN_NODE_BIN=${bin} does not exist (build tavrn-node or copy it out of the node image)`);
  return bin;
}

export async function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolvePort(port));
    });
  });
}

export interface TestNode {
  domain: string;
  port: number;
  /** `http://127.0.0.1:<port>` */
  base: string;
  /** Public API client (no session). */
  api: TavrnApi;
  stop(): Promise<void>;
}

export interface NodeSpec {
  domain: string;
  port?: number;
  /** Other test nodes (domain → port) this node federates with. */
  peers?: Record<string, number>;
  env?: Record<string, string>;
}

/** Starts one node and waits for `/healthz`. */
export async function startNode(spec: NodeSpec): Promise<TestNode> {
  const port = spec.port ?? (await freePort());
  const dir = await mkdtemp(join(tmpdir(), `tavrn-bot-node-${spec.domain}-`));
  const base = `http://127.0.0.1:${port}`;
  const peers = Object.entries(spec.peers ?? {})
    .map(([d, p]) => `${d}=http://127.0.0.1:${p}`)
    .join(",");
  const child: ChildProcess = spawn(nodeBinary(), ["--dev"], {
    cwd: dir,
    stdio: ["ignore", "ignore", "pipe"],
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? dir,
      TAVRN_DOMAIN: spec.domain,
      TAVRN_LISTEN: `127.0.0.1:${port}`,
      TAVRN_PUBLIC_URL: base,
      // The relying party id (the domain) must match the web origin: like the e2e nodes, a web client "under" the domain.
      TAVRN_WEBAUTHN_ORIGIN: `http://${spec.domain}:${port}`,
      TAVRN_DATABASE_URL: `sqlite://${join(dir, "node.db")}?mode=rwc`,
      TAVRN_DATA_DIR: join(dir, "data"),
      TAVRN_VOICE_ENABLED: "false",
      TAVRN_LOG_LEVEL: "warn",
      TAVRN_FEDERATION_ALLOW_PRIVATE: "true",
      TAVRN_FEDERATION_RATE_LOGINS: "1000",
      ...(peers ? { TAVRN_FEDERATION_DEV_PEERS: peers } : {}),
      ...spec.env,
    },
  });
  let stderr = "";
  child.stderr?.on("data", (d: Buffer) => {
    stderr = (stderr + d.toString()).slice(-4000);
  });
  let exited = false;
  child.on("exit", () => {
    exited = true;
  });
  const deadline = Date.now() + 60_000;
  for (;;) {
    if (exited) throw new Error(`node ${spec.domain} exited during start:\n${stderr}`);
    try {
      if ((await fetch(`${base}/healthz`)).ok) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) {
      child.kill("SIGKILL");
      throw new Error(`node ${spec.domain} did not start:\n${stderr}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return {
    domain: spec.domain,
    port,
    base,
    api: new TavrnApi({ baseUrl: base }),
    stop: async () => {
      if (!exited) {
        const gone = new Promise((r) => child.once("exit", r));
        child.kill("SIGTERM");
        await Promise.race([gone, new Promise((r) => setTimeout(r, 5000))]);
        if (!exited) child.kill("SIGKILL");
      }
      await rm(dir, { recursive: true, force: true });
    },
  };
}

/** Two federated nodes `a.test` and `b.test` (FEDERATION.md §13: development peers over plain HTTP). */
export async function startFederation(): Promise<{ a: TestNode; b: TestNode }> {
  const pa = await freePort();
  const pb = await freePort();
  const [a, b] = await Promise.all([startNode({ domain: "a.test", port: pa, peers: { "b.test": pb } }), startNode({ domain: "b.test", port: pb, peers: { "a.test": pa } })]);
  return { a, b };
}

// ---- Users -------------------------------------------------------------------------------------

function base32Decode(s: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

function totp(secret: string, step = Math.floor(Date.now() / 30_000)): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  return ((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}

let counter = 0;
export function unique(prefix: string): string {
  counter += 1;
  return `${prefix}${Date.now().toString(36).slice(-5)}${counter}`.toLowerCase();
}

export interface TestUser {
  node: TestNode;
  username: string;
  address: string;
  user: UserPrivate;
  token: string;
  deviceId: string;
  /** API client with the user's session on their home node. */
  api: TavrnApi;
}

/** Registers a user with password and TOTP (the mandatory second factor) over the API. */
export async function registerUser(node: TestNode, prefix = "user"): Promise<TestUser> {
  const username = unique(prefix);
  const pre = await node.api.auth.register({ username, password: `passwort-${username}-xyz`, device_name: "vitest", date_of_birth: "1990-01-01" });
  const preApi = node.api.withToken(pre.preauth_token!);
  const { secret } = await preApi.auth.totpEnroll();
  const confirmed = (await preApi.auth.totpConfirm(totp(secret))) as unknown as { session: { access_token: string; device_id: string; user: UserPrivate } };
  const s = confirmed.session;
  return {
    node,
    username,
    address: `${username}@${node.domain}`,
    user: s.user,
    token: s.access_token,
    deviceId: s.device_id,
    api: new TavrnApi({ baseUrl: node.base, getToken: () => s.access_token }),
  };
}

export interface CryptoUser extends TestUser {
  mls: MlsManager;
}

/**
 * Sets up end-to-end encryption for a user (identity, recovery entry, device attestation, KeyPackages) and opens the
 * session manager. `nodes` are the other nodes the user talks to: their conversations go there with the user's
 * federated session (`sessions`), keys always come from the address's home node.
 */
export async function withCrypto(u: TestUser, nodes: TestNode[] = []): Promise<CryptoUser> {
  await ensureCrypto();
  const store = new MemoryKeyStore();
  const recovery = RecoveryKey.generate();
  await setupAccount({ api: u.api, username: u.username, address: u.address, deviceId: u.deviceId, store }, recovery);
  recovery.free();
  const byDomain = new Map<string, TestNode>([[u.node.domain, u.node], ...nodes.map((n) => [n.domain, n] as const)]);
  const mls = await openMlsManager(store, {
    api: mlsApiOf({
      home: { backups: u.api.backups },
      node: (domain) => {
        if (domain === u.node.domain) return u.api;
        throw new Error(`no session of ${u.address} on ${domain}`);
      },
      keys: (address) => {
        const at = address.lastIndexOf("@");
        const home = byDomain.get(address.slice(at + 1));
        if (!home) throw new Error(`unknown node of ${address}`);
        return home.api.keys.get(address.slice(0, at));
      },
    }),
    address: u.address,
    deviceId: u.deviceId,
    homeDomain: u.node.domain,
    backupDelayMs: 60_000,
  });
  if (!mls) throw new Error("no MLS client after setupAccount");
  return { ...u, mls };
}

// ---- Rooms, applications -------------------------------------------------------------------------

/**
 * A room of `owner` whose default text channel stays encrypted (the user's device creates its group). New rooms keep
 * bots out of encrypted channels (`bots_in_encrypted_channels = per_channel`), so the channel allows bots unless
 * `botsAllowed` is false.
 */
export async function encryptedRoom(owner: CryptoUser, name = "Bot-Raum", opts: { botsAllowed?: boolean } = {}): Promise<{ room: RoomDetail; channelId: string; q: string }> {
  const room = await owner.api.rooms.create({ name });
  const channel = room.channels.find((c) => c.kind === "text")!;
  if (opts.botsAllowed !== false) await owner.api.channels.update(room.id, channel.id, { bots_allowed: true });
  const q = qualify(owner.node.domain, channel.id);
  await owner.mls.ensureJoined(q, { canCreate: true });
  return { room, channelId: channel.id, q };
}

export interface TestApp {
  id: string;
  ref: string;
  botAddress: string;
  botUsername: string;
  tokenId: string;
  secret: string;
}

/** An application of `owner` with one token (all scopes unless narrowed). */
export async function createApp(owner: TestUser, opts: { public?: boolean; expiresInDays?: number; name?: string } = {}): Promise<TestApp> {
  const app = await owner.api.applications.create({ name: opts.name ?? "Echo Wetter", username: unique("echobot"), description: "test bot", public: opts.public ?? false, requested_permissions: "3" } as never);
  const created = await owner.api.applications.createToken(app.id, { name: "main", ...(opts.expiresInDays ? { expires_in_days: opts.expiresInDays } : {}) } as never);
  return { id: app.id, ref: app.ref, botAddress: app.bot.address, botUsername: app.bot.username, tokenId: created.token.id, secret: created.secret };
}

/** Installs an application in a room (the caller manages the room). */
export async function install(installer: TestUser, roomId: string, appRef: string): Promise<void> {
  await installer.api.applications.install(roomId, { application: appRef, permissions: "3", create_role: true } as never);
}

/** Waits until `check` returns a truthy value (polling). */
export async function until<T>(check: () => T | Promise<T>, what: string, ms = 20_000): Promise<NonNullable<T>> {
  const deadline = Date.now() + ms;
  let last: unknown;
  for (;;) {
    try {
      const v = await check();
      if (v) return v as NonNullable<T>;
    } catch (e) {
      last = e;
    }
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}${last ? `: ${String(last)}` : ""}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}
