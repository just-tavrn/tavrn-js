// SPDX-License-Identifier: MPL-2.0
// The account flows on the shared KeyStores (the web client runs the same flows on its IndexedDB store,
// see src/crypto/e2ee.test.ts in tavrn-web).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MasterSecret, RecoveryKey, wrapMasterSecret } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import {
  E2eeError,
  MemoryKeyStore,
  deviceLoginProof,
  ensureCrypto,
  ensureDevice,
  forgetIdentityKeepDevice,
  loadClient,
  localIdentityKey,
  localStatus,
  setupAccount,
  unlockWithRecoveryKey,
  wipeLocal,
  type E2eeContext,
  type KeyStore,
} from "../src/index";
import { FileKeyStore } from "../src/node";
import { Network } from "./fake-node";

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
});
