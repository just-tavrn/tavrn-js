// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import { TavrnApiError, createRefresher, type LockManagerLike, type TokenPair } from "../src";

const pair = (n: number): TokenPair => ({ access_token: `a${n}`, refresh_token: `r${n}`, expires_in: 3600, device_id: "D" });
const apiError = (status: number) => new TavrnApiError({ type: "about:blank", title: "x", status, detail: "", code: status === 0 ? "network.error" : "auth.refresh_invalid" });

/** In-memory Web Locks: callbacks of one name run one after another. */
function fakeLocks(): LockManagerLike {
  const tails = new Map<string, Promise<unknown>>();
  return {
    request<T>(name: string, cb: () => Promise<T>): Promise<T> {
      const prev = tails.get(name) ?? Promise.resolve();
      const next = prev.then(cb, cb);
      tails.set(name, next.catch(() => undefined));
      return next;
    },
  };
}

/** Two "tabs" sharing a storage, each with its own memory and refresher. */
function tabs(call: (refresh: string) => Promise<TokenPair>, locks: LockManagerLike | null) {
  const storage = { access: "a0" as string | null, refresh: "r0" as string | null };
  const make = () => {
    const mem = { access: storage.access, refresh: storage.refresh };
    const onInvalid = vi.fn(() => {
      mem.access = mem.refresh = null;
      storage.access = storage.refresh = null;
    });
    const refresh = createRefresher({
      lockName: "tavrn-refresh:x",
      locks,
      current: () => mem.refresh,
      shared: () => ({ ...storage }),
      adopt: (t) => Object.assign(mem, t),
      call,
      store: (p) => {
        mem.access = storage.access = p.access_token;
        mem.refresh = storage.refresh = p.refresh_token;
      },
      onInvalid,
      sleep: async () => undefined,
    });
    return { mem, refresh, onInvalid };
  };
  return { storage, a: make(), b: make() };
}

describe("createRefresher", () => {
  it("runs one refresh for parallel callers", async () => {
    const call = vi.fn(async () => pair(1));
    const { a } = tabs(call, null);
    const results = await Promise.all([a.refresh(), a.refresh(), a.refresh()]);
    expect(results).toEqual(["a1", "a1", "a1"]);
    expect(call).toHaveBeenCalledTimes(1);
    expect(call).toHaveBeenCalledWith("r0");
    // The next expiry refreshes again with the rotated token.
    call.mockResolvedValueOnce(pair(2));
    expect(await a.refresh()).toBe("a2");
    expect(call).toHaveBeenLastCalledWith("r1");
  });

  it("lets a second tab adopt the tokens the first one rotated (lock + shared storage)", async () => {
    let n = 0;
    const call = vi.fn(async () => pair(++n));
    const { a, b, storage } = tabs(call, fakeLocks());
    const [ra, rb] = await Promise.all([a.refresh(), b.refresh()]);
    expect(call).toHaveBeenCalledTimes(1);
    expect([ra, rb]).toEqual(["a1", "a1"]);
    expect(b.mem).toEqual({ access: "a1", refresh: "r1" });
    expect(storage.refresh).toBe("r1");
    expect(a.onInvalid).not.toHaveBeenCalled();
    expect(b.onInvalid).not.toHaveBeenCalled();
  });

  it("adopts tokens rotated elsewhere when the node refuses the stale token (no locks)", async () => {
    const { a, b, storage } = tabs(async () => pair(1), null);
    await a.refresh();
    // Tab b still holds r0; the node would refuse it after the grace.
    const refuse = vi.fn(async () => {
      throw apiError(401);
    });
    const late = createRefresher({ lockName: "x", locks: null, current: () => b.mem.refresh, shared: () => ({ ...storage }), adopt: (t) => Object.assign(b.mem, t), call: refuse, store: () => undefined, onInvalid: b.onInvalid });
    expect(await late()).toBe("a1");
    expect(refuse).not.toHaveBeenCalled();
    expect(b.onInvalid).not.toHaveBeenCalled();
  });

  it("logs out only on a definitive answer to the refresh itself", async () => {
    const { a } = tabs(async () => {
      throw apiError(401);
    }, fakeLocks());
    expect(await a.refresh()).toBeNull();
    expect(a.onInvalid).toHaveBeenCalledTimes(1);
  });

  it("keeps the session on network errors and server errors, after retries", async () => {
    const call = vi.fn(async (): Promise<TokenPair> => {
      throw apiError(0);
    });
    const { a } = tabs(call, null);
    await expect(a.refresh()).rejects.toBeInstanceOf(TavrnApiError);
    expect(call).toHaveBeenCalledTimes(3);
    expect(a.onInvalid).not.toHaveBeenCalled();
    expect(a.mem.refresh).toBe("r0");
    // A 503 that recovers on the second attempt.
    call.mockRejectedValueOnce(apiError(503)).mockResolvedValueOnce(pair(5));
    expect(await a.refresh()).toBe("a5");
  });

  it("follows a sign-out in another tab", async () => {
    const call = vi.fn(async () => pair(1));
    const { a, storage } = tabs(call, null);
    storage.access = storage.refresh = null;
    expect(await a.refresh()).toBeNull();
    expect(call).not.toHaveBeenCalled();
    expect(a.onInvalid).toHaveBeenCalled();
  });

  it("uses navigator.locks when present", async () => {
    const request = vi.fn((_: string, cb: () => Promise<unknown>) => cb());
    vi.stubGlobal("navigator", { locks: { request } });
    try {
      const refresh = createRefresher({ lockName: "tavrn-refresh:n", current: () => "r0", call: async () => pair(1), store: () => undefined, onInvalid: () => undefined });
      expect(await refresh()).toBe("a1");
      expect(request).toHaveBeenCalledWith("tavrn-refresh:n", expect.any(Function));
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
