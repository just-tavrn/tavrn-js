// SPDX-License-Identifier: MPL-2.0
// Identity key rotation with continuity (ENCRYPTION.md §9a): chain checks against the published test vectors,
// the rotation itself, other devices following it (unlock and start) and the refusals.
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { IdentityKey, MasterSecret, RecoveryKey, signContinuity, unwrapIdentityKey, verifyContinuity, wrapIdentityKey } from "@tavrn/crypto";
import { b64urlDecode, b64urlEncode } from "@tavrn/sdk";
import {
  E2eeError,
  IDENTITY_SEED,
  MemoryKeyStore,
  chainKeys,
  chainReaches,
  ensureCrypto,
  ensureDevice,
  localStatus,
  openMlsManager,
  ownIdentityPublicKey,
  reloadOwnIdentity,
  rotateIdentity,
  setupAccount,
  syncIdentity,
  unlockWithRecoveryKey,
  type ContinuityStatement,
  type E2eeContext,
} from "../src/index";
import { Network } from "./fake-node";

const DOMAIN = "t.local";
const DEV_A = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
const DEV_B = "01J9ZK3G5M8Q2W4E6R8T0Y2VB1";
const AT = "2026-10-06T12:00:00Z";

beforeAll(() => ensureCrypto());

const pk = (k: IdentityKey) => b64urlEncode(k.publicKey());
const sign = (a: IdentityKey, b: IdentityKey, at = AT) => JSON.parse(signContinuity(a, b, at)) as ContinuityStatement;

describe("continuity chains", () => {
  it("verify the published test vectors", () => {
    const v = JSON.parse(readFileSync(new URL("../../protocol/testvectors/encryption.json", import.meta.url), "utf8"));
    const r = v.identity_rotation;
    expect(verifyContinuity(JSON.stringify(r.continuity))).toBe(true);
    expect(r.continuity.old_key).toBe(v.keys.identity_public_key);
    const master = MasterSecret.fromBytes(b64urlDecode(r.master_secret));
    const key = unwrapIdentityKey(master, b64urlDecode(r.identity_blob), r.user_address);
    expect(pk(key)).toBe(r.rotated_public_key);
    expect(chainReaches([r.continuity], v.keys.identity_public_key, r.rotated_public_key)).toBe(true);
    // The message layout: context string, then RFC 8785 JSON.
    expect(new TextDecoder().decode(b64urlDecode(r.continuity_message))).toBe(
      `tavrn identity continuity v1{"at":"${r.continuity.at}","new_key":"${r.continuity.new_key}","old_key":"${r.continuity.old_key}"}`,
    );
    key.free();
    master.free();
  });

  it("are followed forward only and break at an invalid or missing link", () => {
    const [k0, k1, k2, k3] = [IdentityKey.generate(), IdentityKey.generate(), IdentityKey.generate(), IdentityKey.generate()];
    const chain = [sign(k0, k1), sign(k1, k2), sign(k2, k3)];
    expect(chainReaches(chain, pk(k0), pk(k3))).toBe(true);
    expect(chainReaches(chain, pk(k2), pk(k3))).toBe(true);
    expect(chainReaches(chain, pk(k3), pk(k0))).toBe(false);
    expect(chainReaches([], pk(k0), pk(k1))).toBe(false);
    expect(chainReaches(null, pk(k0), pk(k0))).toBe(true);
    expect(chainReaches([chain[0]!, chain[2]!], pk(k0), pk(k3))).toBe(false);
    const forged = { ...chain[1]!, sig_old: sign(IdentityKey.generate(), k2).sig_old };
    expect(chainReaches([chain[0]!, forged, chain[2]!], pk(k0), pk(k3))).toBe(false);
    expect([...chainKeys(chain, pk(k3))].sort()).toEqual([pk(k0), pk(k1), pk(k2), pk(k3)].sort());
    expect([...chainKeys([chain[0]!, forged, chain[2]!], pk(k3))].sort()).toEqual([pk(k2), pk(k3)].sort());
  });
});

function account() {
  const net = new Network();
  const node = net.node(DOMAIN);
  const username = "alice";
  const ctx = (store: MemoryKeyStore, deviceId: string): E2eeContext => ({ api: node.accountApi(username), username, address: `${username}@${DOMAIN}`, deviceId, store, clientName: "test" });
  return { node, net, ctx, user: () => node.users.get(username)!, entries: () => node.secrets.get(username)! };
}

describe("rotation (account flows)", () => {
  it("rotates on one device; the other device follows on its next start and on unlock", async () => {
    const { ctx, user, net } = account();
    const recovery = RecoveryKey.generate();
    const words = recovery.toWords();
    const a = ctx(new MemoryKeyStore(), DEV_A);
    await setupAccount(a, recovery);
    // The second device unlocks with the recovery key (generation 0).
    const b = ctx(new MemoryKeyStore(), DEV_B);
    await unlockWithRecoveryKey(b, words);
    const k0 = user().identity;
    expect(Object.keys(Object.fromEntries(user().devices))).toEqual([DEV_A, DEV_B]);

    // B's session manager is open while A rotates.
    const mls = (await openMlsManager(b.store, { api: net.api(b.address, DEV_B), address: b.address, deviceId: DEV_B, homeDomain: DOMAIN }))!;
    expect((await mls.verifiedDevices(b.address))!.size).toBe(2);
    const res = await rotateIdentity({ api: a.api, username: a.username, address: a.address, store: a.store, now: () => Date.parse(AT) });
    expect(res.identity_generation).toBe(1);
    const k1 = user().identity;
    expect(k1).not.toBe(k0);
    expect(await ownIdentityPublicKey(a.store)).toBe(k1);
    expect(chainReaches(user().continuity, k0, k1)).toBe(true);
    expect(user().continuity![0]!.at).toBe(AT);

    // Device B still holds the old key; its next start takes the new one from the blob and keeps working.
    expect(await ownIdentityPublicKey(b.store)).toBe(k0);
    await ensureDevice(b);
    expect(await ownIdentityPublicKey(b.store)).toBe(k1);
    expect(await syncIdentity(b.api, b.store, b.username, b.address)).toBe("current");
    // The open session manager verifies own devices against the rotated key once told so.
    mls.forgetDevices(b.address);
    expect((await mls.verifiedDevices(b.address))!.size).toBe(0);
    await reloadOwnIdentity(mls);
    expect([...(await mls.verifiedDevices(b.address))!.keys()].sort()).toEqual([DEV_A, DEV_B]);
    mls.dispose();

    // A new browser unlocks with the recovery key: derived key → chain → blob.
    const c = ctx(new MemoryKeyStore(), "01J9ZK3G5M8Q2W4E6R8T0Y2VC1");
    await unlockWithRecoveryKey(c, words);
    expect(await localStatus(c.store, c.address, c.deviceId)).toBe("unlocked");
    expect(await ownIdentityPublicKey(c.store)).toBe(k1);
    expect(user().devices.has(c.deviceId)).toBe(true);
  });

  it("refuses an unlock whose chain or blob does not lead to the published key", async () => {
    const { ctx, user } = account();
    const recovery = RecoveryKey.generate();
    const words = recovery.toWords();
    const a = ctx(new MemoryKeyStore(), DEV_A);
    await setupAccount(a, recovery);
    const master = MasterSecret.fromBytes(a.store.masterSecret());
    const k0 = IdentityKey.fromMaster(master);
    // A node publishes a foreign key with a chain signed by a key that is not the derived one.
    const mallory = IdentityKey.generate();
    const foreign = IdentityKey.generate();
    user().identity = pk(foreign);
    user().continuity = [sign(mallory, foreign)];
    user().blob = b64urlEncode(wrapIdentityKey(master, foreign, a.address));
    await expect(unlockWithRecoveryKey(ctx(new MemoryKeyStore(), DEV_B), words)).rejects.toEqual(new E2eeError("identity_mismatch"));
    // A valid chain but a blob holding another key.
    const k1 = IdentityKey.generate();
    user().identity = pk(k1);
    user().continuity = [sign(k0, k1)];
    user().blob = b64urlEncode(wrapIdentityKey(master, foreign, a.address));
    await expect(unlockWithRecoveryKey(ctx(new MemoryKeyStore(), DEV_B), words)).rejects.toEqual(new E2eeError("identity_mismatch"));
    // ... or no blob at all.
    user().blob = undefined;
    await expect(unlockWithRecoveryKey(ctx(new MemoryKeyStore(), DEV_B), words)).rejects.toEqual(new E2eeError("identity_mismatch"));
    // The running device refuses to follow as well.
    await expect(syncIdentity(a.api, a.store, a.username, a.address)).rejects.toEqual(new E2eeError("identity_mismatch"));
    expect(await a.store.getSecret(IDENTITY_SEED)).toBeNull();
    [k0, k1, mallory, foreign, master].forEach((x) => x.free());
  });

  it("never follows the published key back to an older generation (rollback by the node)", async () => {
    const { ctx, user } = account();
    const a = ctx(new MemoryKeyStore(), DEV_A);
    await setupAccount(a, RecoveryKey.generate());
    const k0 = user().identity;
    await rotateIdentity({ api: a.api, username: a.username, address: a.address, store: a.store, now: () => Date.parse(AT) });
    const firstChain = [...user().continuity!];
    const firstBlob = user().blob;
    const k1 = user().identity;
    await rotateIdentity({ api: a.api, username: a.username, address: a.address, store: a.store, now: () => Date.parse(AT) + 1000 });
    const k2 = user().identity;
    expect(await ownIdentityPublicKey(a.store)).toBe(k2);
    // The node (or whoever stole generation 1, the reason for the second rotation) serves the state of generation 1
    // again: a valid chain from the derived key and the old blob. The device must not go back to k1.
    user().identity = k1;
    user().continuity = firstChain;
    user().blob = firstBlob;
    await expect(syncIdentity(a.api, a.store, a.username, a.address)).rejects.toEqual(new E2eeError("identity_mismatch"));
    expect(await ownIdentityPublicKey(a.store)).toBe(k2);
    // ... nor back to the derived generation 0 with an empty chain.
    user().identity = k0;
    user().continuity = [];
    user().blob = undefined;
    await expect(syncIdentity(a.api, a.store, a.username, a.address)).rejects.toEqual(new E2eeError("identity_mismatch"));
    expect(await ownIdentityPublicKey(a.store)).toBe(k2);
  });

  it("does not roll a locked device back to an older generation when it unlocks", async () => {
    const { ctx, user } = account();
    const recovery = RecoveryKey.generate();
    const words = recovery.toWords();
    const a = ctx(new MemoryKeyStore(), DEV_A);
    await setupAccount(a, recovery);
    await rotateIdentity({ api: a.api, username: a.username, address: a.address, store: a.store, now: () => Date.parse(AT) });
    const firstChain = [...user().continuity!];
    const firstBlob = user().blob;
    const k1 = user().identity;
    await rotateIdentity({ api: a.api, username: a.username, address: a.address, store: a.store, now: () => Date.parse(AT) + 1000 });
    const k2 = user().identity;
    const [fullChain, fullBlob] = [[...user().continuity!], user().blob];
    // Lock on close: the next start unlocks with the recovery key while the node serves generation 1 again.
    a.store.lock();
    user().identity = k1;
    user().continuity = firstChain;
    user().blob = firstBlob;
    await expect(unlockWithRecoveryKey(a, words)).rejects.toEqual(new E2eeError("identity_mismatch"));
    // The node serves the current state again: the device unlocks and is still on k2.
    user().identity = k2;
    user().continuity = fullChain;
    user().blob = fullBlob;
    a.store.lock();
    await unlockWithRecoveryKey(a, words);
    expect(await ownIdentityPublicKey(a.store)).toBe(k2);
  });

  it("stops when a listed device does not verify under the current key", async () => {
    const { ctx, user } = account();
    const a = ctx(new MemoryKeyStore(), DEV_A);
    await setupAccount(a, RecoveryKey.generate());
    // A device the node lists but this account never attested (the document and the local state disagree).
    const stranger = MasterSecret.generate();
    const key = IdentityKey.generate().publicKey();
    user().devices.set(DEV_B, { pk: b64urlEncode(key), sig: b64urlEncode(stranger.attestDevice(a.address, DEV_B, key)) });
    const before = user().identity;
    await expect(rotateIdentity({ api: a.api, username: a.username, address: a.address, store: a.store })).rejects.toEqual(new E2eeError("rotation_devices"));
    expect(user().identity).toBe(before);
    expect(await a.store.getSecret(IDENTITY_SEED)).toBeNull();
    stranger.free();
  });
});
