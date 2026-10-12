// SPDX-License-Identifier: MPL-2.0
// The account flows on the shared KeyStores (the web client runs the same flows on its IndexedDB store,
// see src/crypto/e2ee.test.ts in tavrn-web).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, MasterSecret, RecoveryKey, wrapMasterSecret } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import {
  E2eeError,
  MemoryKeyStore,
  deviceLoginProof,
  ensureCrypto,
  ensureDevice,
  forgetIdentityKeepDevice,
  loadClient,
  localDeviceLost,
  localIdentityKey,
  localStatus,
  saveClient,
  setupAccount,
  unlockWithRecoveryKey,
  wipeLocal,
  type E2eeContext,
  type KeyStore,
} from "../src/index";
import { FileKeyStore } from "../src/node";
import { Network, problem } from "./fake-node";

const DOMAIN = "t.local";
const DEV_A = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
const DEV_B = "01J9ZK3G5M8Q2W4E6R8T0Y2VB1";

const root = mkdtempSync(join(tmpdir(), "tavrn-e2ee-account-"));
let n = 0;

beforeAll(() => ensureCrypto());
afterAll(() => rmSync(root, { recursive: true, force: true }));

const kinds: [string, () => KeyStore][] = [
  ["memory", () => new MemoryKeyStore()],
  ["file", () => new FileKeyStore(join(root, `a${++n}`))],
];

describe.each(kinds)("account flows (%s store)", (_kind, makeStore) => {
  function account(store = makeStore()) {
    const net = new Network();
    const node = net.node(DOMAIN);
    const username = `user${++n}`;
    const ctx: E2eeContext = { api: node.accountApi(username), username, address: `${username}@${DOMAIN}`, deviceId: DEV_A, store, clientName: "test" };
    return { node, ctx, user: () => node.users.get(username)!, entries: () => node.secrets.get(username)! };
  }

  it("sets up an account and tops up KeyPackages idempotently", async () => {
    const { ctx, user } = account();
    await setupAccount(ctx, RecoveryKey.generate());
    expect(await localStatus(ctx.store, ctx.address, DEV_A)).toBe("unlocked");
    expect(localIdentityKey(ctx.store)).toBe(user().identity);
    const client = (await loadClient(ctx.store))!;
    expect(b64urlEncode(client.devicePublicKey)).toBe(user().devices.get(DEV_A)!.pk);
    client.free();
    expect(user().kps.get(DEV_A)).toHaveLength(20);
    user().kps.get(DEV_A)!.splice(0, 17);
    await ensureDevice(ctx);
    expect(user().kps.get(DEV_A)).toHaveLength(20);
  });

  it("refuses a second setup when this device holds the account's master secret or the node has a recovery entry", async () => {
    const { ctx, user, node } = account();
    await setupAccount(ctx, RecoveryKey.generate());
    const identity = user().identity;
    // A lying node reports "no identity key": the locked device is not replaced, it unlocks instead.
    ctx.store.lock();
    await expect(setupAccount(ctx, RecoveryKey.generate())).rejects.toMatchObject({ name: "E2eeError", code: "already_set_up" });
    expect(await ctx.store.status(ctx.address)).toBe("locked");
    expect(user().identity).toBe(identity);
    // Another device without local data: the recovery entry on the node tells that the account is set up.
    const other: E2eeContext = { ...ctx, deviceId: DEV_B, store: makeStore(), api: node.accountApi(ctx.username) };
    await expect(setupAccount(other, RecoveryKey.generate())).rejects.toMatchObject({ code: "already_set_up" });
  });

  it("publishes the device's share key with the device key, and once later for a device attested without one", async () => {
    const { ctx, user, node } = account();
    await setupAccount(ctx, RecoveryKey.generate());
    const client = (await loadClient(ctx.store))!;
    const share = client.shareKey();
    // Published together with the device key; the node checked the signature (ENCRYPTION.md §3.1).
    expect(user().devices.get(DEV_A)!.spk).toBe(b64urlEncode(share.publicKey));
    expect(user().devices.get(DEV_A)!.ssig).toBe(b64urlEncode(share.signature));
    expect(node.shareKeyPuts).toBe(0);
    // A device attested before share keys existed: the next ensureDevice publishes it once.
    delete user().devices.get(DEV_A)!.spk;
    delete user().devices.get(DEV_A)!.ssig;
    await ensureDevice(ctx);
    expect(user().devices.get(DEV_A)!.spk).toBe(b64urlEncode(share.publicKey));
    await ensureDevice(ctx);
    expect(node.shareKeyPuts).toBe(1);
    share.free();
    client.free();
  });

  it("proves the stored device for a login and reports a replaced device instead of dropping it silently", async () => {
    const { ctx } = account();
    await setupAccount(ctx, RecoveryKey.generate());
    let asked = 0;
    const proof = await deviceLoginProof(ctx.store, ctx.address, async () => {
      asked++;
      return "nonce-1";
    });
    expect(proof).toMatchObject({ id: DEV_A, nonce: "nonce-1" });
    expect(b64urlDecode(proof!.proof)).toHaveLength(64);
    const other = await deviceLoginProof(ctx.store, ctx.address, async () => "nonce-2");
    expect(other!.proof).not.toBe(proof!.proof);
    expect(asked).toBe(1);
    // No device of that account in the store: nothing to prove, and no nonce is fetched.
    expect(await deviceLoginProof(ctx.store, `someone@${DOMAIN}`, async () => { asked++; return "n"; })).toBeNull();
    expect(asked).toBe(1);

    // The session got another device after all: the old one is reported, then the local data goes.
    const stale: string[] = [];
    expect(await localStatus(ctx.store, ctx.address, DEV_B, { onStaleDevice: (id) => void stale.push(id) })).toBe("none");
    expect(stale).toEqual([DEV_A]);
    expect(await ctx.store.deviceIdOf(ctx.address)).toBeNull();
  });

  it("unlocks a locked store with the recovery key and keeps the device", async () => {
    const { ctx, user } = account();
    const recovery = RecoveryKey.generate();
    const words = recovery.toWords();
    await setupAccount(ctx, recovery);
    const deviceKey = user().devices.get(DEV_A)!.pk;
    ctx.store.lock();
    expect(localIdentityKey(ctx.store)).toBeNull();
    await expect(ensureDevice(ctx)).rejects.toThrow();
    await expect(unlockWithRecoveryKey(ctx, RecoveryKey.generate().toWords())).rejects.toMatchObject({ code: "recovery_key_wrong" });
    await unlockWithRecoveryKey(ctx, words);
    expect(ctx.store.isUnlocked(ctx.address)).toBe(true);
    expect(user().devices.get(DEV_A)!.pk).toBe(deviceKey);
    // The local MLS client (device key) was kept, not replaced.
    const client = (await loadClient(ctx.store))!;
    expect(b64urlEncode(client.devicePublicKey)).toBe(deviceKey);
    client.free();
  });

  it("refuses an unwrapped master secret that does not match the published identity key", async () => {
    const { ctx, user } = account();
    const recovery = RecoveryKey.generate();
    const words = recovery.toWords();
    await setupAccount(ctx, recovery);
    await wipeLocal(ctx.store, ctx.address);
    user().identity = b64urlEncode(MasterSecret.generate().identityPublicKey());
    const err = await unlockWithRecoveryKey({ ...ctx, deviceId: DEV_B }, words).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(E2eeError);
    expect((err as E2eeError).code).toBe("identity_mismatch");
    expect(ctx.store.isUnlocked()).toBe(false);
  });

  it("an identity reset elsewhere: the device key is carried over to the new master secret", async () => {
    const { ctx, user, entries } = account();
    await setupAccount(ctx, RecoveryKey.generate());
    const deviceKey = user().devices.get(DEV_A)!.pk;
    const fresh = MasterSecret.generate();
    const recovery = RecoveryKey.generate();
    user().identity = b64urlEncode(fresh.identityPublicKey());
    user().devices.clear();
    entries().set("recovery", b64urlEncode(wrapMasterSecret(fresh, recovery.wrappingKey(), ctx.address, "recovery")));
    await forgetIdentityKeepDevice(ctx.store, ctx.address);
    expect(await localStatus(ctx.store, ctx.address, DEV_A)).toBe("none");
    await unlockWithRecoveryKey(ctx, recovery.toWords());
    expect(localIdentityKey(ctx.store)).toBe(user().identity);
    expect(user().devices.get(DEV_A)!.pk).toBe(deviceKey);
  });
  // tavrn-web#83: the local key store was lost while the session lives on (an app process killed before its storage
  // reached the disk). The device's key is gone; a second key for the same device id would sign commits and messages
  // the node and every member refuse (ENCRYPTION.md §3.1: a new key means a new device).
  it("a device whose local keys were lost gets no second key: device_key_lost, nothing stored", async () => {
    const { ctx, user } = account();
    const recovery = RecoveryKey.generate();
    await setupAccount(ctx, recovery);
    const attested = { ...user().devices.get(DEV_A)! };
    const packages = [...user().kps.get(DEV_A)!];
    await wipeLocal(ctx.store, ctx.address);
    expect(await localStatus(ctx.store, ctx.address, DEV_A)).toBe("none");
    expect(await localDeviceLost(ctx)).toBe(true);
    await expect(unlockWithRecoveryKey(ctx, recovery.toWords())).rejects.toMatchObject({ name: "E2eeError", code: "device_key_lost" });
    // The master secret is the account's (unlocked), but no MLS client: no session manager opens with a foreign key.
    expect(ctx.store.isUnlocked(ctx.address)).toBe(true);
    expect(await loadClient(ctx.store)).toBeNull();
    expect(await localDeviceLost(ctx)).toBe(true);
    await expect(ensureDevice(ctx)).rejects.toMatchObject({ code: "device_key_lost" });
    expect(await loadClient(ctx.store)).toBeNull();
    expect(user().devices.get(DEV_A)).toEqual(attested);
    expect(user().kps.get(DEV_A)).toEqual(packages);
    // Signed in anew (a new device), the same recovery key works.
    await wipeLocal(ctx.store, ctx.address);
    const next: E2eeContext = { ...ctx, deviceId: DEV_B };
    expect(await localDeviceLost(next)).toBe(false);
    await unlockWithRecoveryKey(next, recovery.toWords());
    const client = (await loadClient(next.store))!;
    expect(b64urlEncode(client.devicePublicKey)).toBe(user().devices.get(DEV_B)!.pk);
    client.free();
  });

  it("drops a stored MLS client whose key is not the device's attested key (left by earlier versions)", async () => {
    const { ctx, user } = account();
    await setupAccount(ctx, RecoveryKey.generate());
    expect(await localDeviceLost(ctx)).toBe(false);
    const foreign = Client.create(ctx.address, DEV_A);
    await saveClient(ctx.store, foreign);
    foreign.free();
    expect(await localDeviceLost(ctx)).toBe(true);
    await expect(ensureDevice(ctx)).rejects.toMatchObject({ code: "device_key_lost" });
    expect(await loadClient(ctx.store)).toBeNull();
    expect(user().devices.get(DEV_A)).toBeDefined();
  });

  it("a device not attested under the current identity key whose key is gone is lost too", async () => {
    const { ctx, user, node } = account();
    await setupAccount(ctx, RecoveryKey.generate());
    // The node keeps the key of a device that is not listed (attested under an earlier identity key, §9).
    const hidden = user().devices.get(DEV_A)!;
    const keys = node.accountApi(ctx.username).keys;
    const api = { ...ctx.api, keys: { ...keys, get: async (u: string) => ({ ...(await keys.get(u)), devices: [] }), putDeviceKey: async () => Promise.reject(problem(409, "e2ee.share_key_exists")) } };
    const foreign = Client.create(ctx.address, DEV_A);
    await saveClient(ctx.store, foreign);
    foreign.free();
    await expect(ensureDevice({ ...ctx, api: api as never })).rejects.toMatchObject({ code: "device_key_lost" });
    expect(user().devices.get(DEV_A)).toBe(hidden);
  });
});
