// SPDX-License-Identifier: Apache-2.0
/**
 * KeyPackage claims for the devices of DM members (ENCRYPTION.md §3.2, §4.2). A claim returns and deletes one
 * KeyPackage of every attested device of the user, also of the devices already in the group; the protocol has no
 * claim per device. A device that has no KeyPackage left (offline and drained) stays missing after the claim, so
 * without a guard every later send would claim again and burn the KeyPackages of the user's other devices and the
 * claim budget. The guard claims only while a missing device is due: after a claim that left it missing it waits
 * (1 minute, doubling up to 30 minutes) until it tries that device again, or until the user's devices change.
 */

/** The session manager calls the guard needs (`MlsManager`). */
export interface ClaimTarget {
  roster(q: string): string[];
  verifiedDevices(address: string): Promise<Map<string, Uint8Array> | null>;
  addMissingDevices(q: string, members: string[]): Promise<string[]>;
}

export interface ClaimGuardOptions {
  /** First wait after a claim that left a device missing (default 60 s). */
  baseMs?: number;
  /** Longest wait (default 30 minutes). */
  maxMs?: number;
  now?: () => number;
}

/** At most this many devices are remembered (the oldest entries are dropped). */
const MAX_ENTRIES = 10_000;

export class ClaimGuard {
  /** `address/device` → when it may be claimed again and the current wait. */
  private readonly waits = new Map<string, { until: number; delay: number }>();

  constructor(private readonly opts: ClaimGuardOptions = {}) {}

  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  /** Whether the device `identity` (`address/device`) may be claimed now. */
  due(identity: string): boolean {
    const w = this.waits.get(identity);
    return !w || w.until <= this.now();
  }

  /** The user's devices changed (`devices.changed`): every device of `address` is due again. */
  forget(address: string): void {
    const prefix = `${address}/`;
    for (const k of [...this.waits.keys()]) if (k.startsWith(prefix)) this.waits.delete(k);
  }

  private failed(identity: string): void {
    const base = this.opts.baseMs ?? 60_000;
    const max = this.opts.maxMs ?? 30 * 60_000;
    const prev = this.waits.get(identity);
    const delay = prev ? Math.min(max, prev.delay * 2) : base;
    this.waits.delete(identity);
    this.waits.set(identity, { until: this.now() + delay, delay });
    if (this.waits.size > MAX_ENTRIES) this.waits.delete(this.waits.keys().next().value!);
  }

  /**
   * Adds the members' missing devices to the group of `q` (`addMissingDevices`), but passes only the members with a
   * missing device that is due; `own` is the bot's own device identity. Errors of the lookup are left to the
   * session manager (it retries on the next send).
   */
  async addMissing(mls: ClaimTarget, q: string, members: string[], own: string): Promise<void> {
    const present = new Set(mls.roster(q));
    const targets: string[] = [];
    const missing: string[] = [];
    for (const address of members) {
      const devices = await mls.verifiedDevices(address).catch(() => null);
      if (!devices) continue;
      const gone = [...devices.keys()].map((d) => `${address}/${d}`).filter((i) => i !== own && !present.has(i));
      if (!gone.some((i) => this.due(i))) continue;
      targets.push(address);
      missing.push(...gone);
    }
    if (!targets.length) return;
    await mls.addMissingDevices(q, targets);
    const after = new Set(mls.roster(q));
    for (const i of missing) {
      if (after.has(i)) this.waits.delete(i);
      else this.failed(i);
    }
  }
}
