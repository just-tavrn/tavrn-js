// SPDX-License-Identifier: MPL-2.0
/**
 * A {@link KeyStore} that keeps everything in process memory (tests, one-shot tools). Nothing is written
 * anywhere; the data is gone with the object. Like the file store it keeps no local key: after `lock()`
 * it opens only with the master secret.
 */
import { LocalKeyMismatchError, type CryptoStatus, type KeyStore } from "../keystore";

interface Account {
  deviceId: string;
  master: Uint8Array;
  secrets: Map<string, Uint8Array>;
}

export class MemoryKeyStore implements KeyStore {
  private readonly accounts = new Map<string, Account>();
  private current: string | null = null;

  async status(account: string): Promise<CryptoStatus> {
    if (this.current === account) return "unlocked";
    return this.accounts.has(account) ? "locked" : "none";
  }

  async deviceIdOf(account: string): Promise<string | null> {
    return this.accounts.get(account)?.deviceId ?? null;
  }

  async resume(account: string): Promise<boolean> {
    return this.isUnlocked(account);
  }

  async saveMaster(account: string, deviceId: string, master: Uint8Array): Promise<void> {
    await this.wipe(account);
    this.accounts.set(account, { deviceId, master: master.slice(), secrets: new Map() });
    this.current = account;
  }

  async unlockWithMaster(account: string, master: Uint8Array): Promise<void> {
    const rec = this.accounts.get(account);
    if (!rec) throw new Error("no local data for this account");
    if (rec.master.length !== master.length || !rec.master.every((v, i) => v === master[i])) throw new LocalKeyMismatchError();
    this.current = account;
  }

  isUnlocked(account?: string): boolean {
    return this.current !== null && (account === undefined || this.current === account);
  }

  lock(): void {
    this.current = null;
  }

  async wipe(account: string): Promise<void> {
    if (this.current === account) this.lock();
    const rec = this.accounts.get(account);
    if (!rec) return;
    rec.master.fill(0);
    for (const v of rec.secrets.values()) v.fill(0);
    this.accounts.delete(account);
  }

  account(): string | null {
    return this.current;
  }

  private open(): Account {
    const rec = this.current ? this.accounts.get(this.current) : undefined;
    if (!rec) throw new Error("crypto store is locked");
    return rec;
  }

  deviceId(): string {
    return this.open().deviceId;
  }

  masterSecret(): Uint8Array {
    return this.open().master.slice();
  }

  async putSecret(name: string, value: Uint8Array): Promise<void> {
    const rec = this.open();
    rec.secrets.get(name)?.fill(0);
    rec.secrets.set(name, value.slice());
  }

  async getSecret(name: string): Promise<Uint8Array | null> {
    return this.open().secrets.get(name)?.slice() ?? null;
  }

  async deleteSecret(name: string): Promise<void> {
    const rec = this.open();
    rec.secrets.get(name)?.fill(0);
    rec.secrets.delete(name);
  }
}
