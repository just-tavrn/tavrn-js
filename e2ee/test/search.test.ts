// SPDX-License-Identifier: MPL-2.0
import { beforeAll, describe, expect, it } from "vitest";
import {
  MARK_END,
  MARK_START,
  MemoryKeyStore,
  MemorySearchBackend,
  SearchIndex,
  SearchLockedError,
  deriveSearchKeys,
  ensureCrypto,
  open,
  searchKeysFromStore,
  seal,
  tokenKey,
  type IndexedMessage,
  type SearchKeys,
} from "../src";

const DAY = 86_400_000;
const NOW = Date.UTC(2026, 9, 6, 12);
const CONV = "n.example/01J9ZK3G5M8Q2W4E6R8T0Y2VC1";
const CONV2 = "n.example/01J9ZK3G5M8Q2W4E6R8T0Y2VC2";

let keys: SearchKeys;
let otherKeys: SearchKeys;

beforeAll(async () => {
  keys = await deriveSearchKeys(new Uint8Array(32).fill(7));
  otherKeys = await deriveSearchKeys(new Uint8Array(32).fill(8));
});

/** A ULID-like, time-ordered id. */
function ulid(ts: number, n: number): string {
  return `01${ts.toString(36).toUpperCase().padStart(10, "0")}${n.toString(36).toUpperCase().padStart(14, "0")}`;
}

let seq = 0;
function msg(text: string, opts: Partial<IndexedMessage> = {}): IndexedMessage {
  const ts = opts.ts ?? NOW - 1000 + seq;
  return { conversation: CONV, id: ulid(ts, seq++), ts, author: "alice@t.local", text, files: [], ...opts };
}

async function fresh(opts: { now?: () => number; maxBytes?: number; windowDays?: number } = {}) {
  const backend = new MemorySearchBackend();
  const index = await SearchIndex.open(backend, keys, { now: () => NOW, ...opts });
  return { backend, index };
}

describe("keys", () => {
  it("token keys are deterministic per key, differ for another key and per conversation, hex-32", async () => {
    const a = await tokenKey(keys, "tok", CONV, "p:hel");
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(await tokenKey(keys, "tok", CONV, "p:hel")).toBe(a);
    expect(await tokenKey(otherKeys, "tok", CONV, "p:hel")).not.toBe(a);
    expect(await tokenKey(keys, "tok", CONV2, "p:hel")).not.toBe(a);
    // Parts are separated: ("ab", "c") ≠ ("a", "bc").
    expect(await tokenKey(keys, "ab", "c")).not.toBe(await tokenKey(keys, "a", "bc"));
  });

  it("seal/open round trip, bound to the aad and the key", async () => {
    const sealed = await seal(keys, "docs\u0000k", { hello: "world" });
    expect(await open(keys, "docs\u0000k", sealed)).toEqual({ hello: "world" });
    await expect(open(keys, "docs\u0000other", sealed)).rejects.toThrow();
    await expect(open(otherKeys, "docs\u0000k", sealed)).rejects.toThrow();
    expect(new TextDecoder().decode(sealed)).not.toContain("world");
    // Fresh iv each time.
    const again = await seal(keys, "docs\u0000k", { hello: "world" });
    expect(Buffer.from(again).equals(Buffer.from(sealed))).toBe(false);
  });

  it("derived keys are not extractable", () => {
    expect(keys.mac.extractable).toBe(false);
    expect(keys.enc.extractable).toBe(false);
  });

  describe("searchKeysFromStore", () => {
    beforeAll(() => ensureCrypto());

    it("refuses a locked store", async () => {
      await expect(searchKeysFromStore(new MemoryKeyStore())).rejects.toBeInstanceOf(SearchLockedError);
      await expect(searchKeysFromStore(new MemoryKeyStore())).rejects.toMatchObject({ name: "search_locked" });
    });

    it("derives the same keys for the same master secret and device, others for another device", async () => {
      const master = new Uint8Array(32).fill(3);
      const store = new MemoryKeyStore();
      await store.saveMaster("alice@t.local", "01J9ZK3G5M8Q2W4E6R8T0Y2VC1", master);
      const k1 = await searchKeysFromStore(store);
      const k2 = await searchKeysFromStore(store);
      expect(await tokenKey(k1, "x")).toBe(await tokenKey(k2, "x"));
      const store2 = new MemoryKeyStore();
      await store2.saveMaster("alice@t.local", "01J9ZK3G5M8Q2W4E6R8T0Y2VC9", master);
      expect(await tokenKey(await searchKeysFromStore(store2), "x")).not.toBe(await tokenKey(k1, "x"));
      store.lock();
      await expect(searchKeysFromStore(store)).rejects.toBeInstanceOf(SearchLockedError);
    });
  });
});

describe("SearchIndex", () => {
  it("prefix search, AND, short exact terms, newest first, snippets", async () => {
    const { index } = await fresh();
    await index.add([
      msg("Hello there"),
      msg("hello world"),
      msg("the world is big"),
      msg("ab and abc"),
      msg("abc only"),
    ]);
    const hel = await index.search("hel");
    expect(hel.map((h) => h.snippet)).toEqual([`${MARK_START}hello${MARK_END} world`, `${MARK_START}Hello${MARK_END} there`]);
    expect(hel[0]!.ts).toBeGreaterThan(hel[1]!.ts);
    expect((await index.search("hello world")).map((h) => h.snippet)).toEqual([
      `${MARK_START}hello${MARK_END} ${MARK_START}world${MARK_END}`,
    ]);
    expect(await index.search("ab")).toHaveLength(1);
    expect(await index.search("abc")).toHaveLength(2);
    expect(await index.search("he")).toEqual([]);
    expect(await index.search("")).toEqual([]);
    expect(await index.search('" ( ) * OR NEAR( : \\ \'')).toEqual([]);
    const [hit] = await index.search("big");
    expect(hit).toMatchObject({ conversation: CONV, author: "alice@t.local", files: [] });
    expect(hit!.room).toBeUndefined();
    await index.add([msg("roomy channel text", { room: "ROOM1" })]);
    expect((await index.search("roomy"))[0]!.room).toBe("ROOM1");
    expect((await index.search("roomy"))[0]!.thread).toBeUndefined();
    // Thread messages keep their thread (PROTOCOL.md §7e), sealed like the room.
    await index.add([msg("threaded reply text", { room: "ROOM1", thread: "THREAD1" })]);
    expect((await index.search("threaded"))[0]).toMatchObject({ room: "ROOM1", thread: "THREAD1" });
  });

  it("finds file names, filters by author, date, files, conversation and limit", async () => {
    const { index } = await fresh();
    await index.add([
      msg("see attachment", { files: ["report-2026.pdf"], ts: NOW - 5 * DAY }),
      msg("report follows", { author: "bob@t.local", ts: NOW - 3 * DAY }),
      msg("another report", { conversation: CONV2, ts: NOW - DAY }),
    ]);
    expect(await index.search("report")).toHaveLength(3);
    const withFile = await index.search("report", { hasFile: true });
    expect(withFile).toHaveLength(1);
    expect(withFile[0]!.files).toEqual(["report-2026.pdf"]);
    expect(await index.search("report", { hasFile: false })).toHaveLength(2);
    expect((await index.search("report", { author: "bob@t.local" })).map((h) => h.author)).toEqual(["bob@t.local"]);
    expect(await index.search("report", { after: NOW - 4 * DAY })).toHaveLength(2);
    expect(await index.search("report", { before: NOW - 4 * DAY })).toHaveLength(1);
    expect(await index.search("report", { conversations: [CONV2] })).toHaveLength(1);
    expect(await index.search("report", { conversations: ["unknown"] })).toEqual([]);
    expect(await index.search("report", { limit: 2 })).toHaveLength(2);
    expect(await index.search("pdf")).toHaveLength(1);
    // Empty query with filters: newest messages matching them; without filters: nothing.
    expect((await index.search("", { hasFile: true })).map((h) => h.files)).toEqual([["report-2026.pdf"]]);
    expect((await index.search("", { author: "alice@t.local" })).length).toBe(2);
    expect(await index.search("")).toEqual([]);
  });

  it("caps the results at MAX_RESULTS", async () => {
    const { index } = await fresh();
    await index.add(Array.from({ length: 70 }, (_, i) => msg(`common word ${i}`)));
    expect(await index.search("common")).toHaveLength(50);
    expect(await index.search("common", { limit: 500 })).toHaveLength(50);
  });

  it("THE DUMP TEST: nothing in the backend is plaintext", async () => {
    const { backend, index } = await fresh();
    const messages = [
      msg("Das zebrastreifen geheimnis bleibt unter uns", { files: ["steuererklaerung.pdf"], room: "01J9ZK3G5M8Q2W4E6R8T0Y2ROO" }),
      msg("Noch ein geheimnis über den Zebrastreifen"),
      msg("Rechnung fuer die kanzlei hinterlegt", { conversation: CONV2 }),
    ];
    await index.add(messages);
    await index.flush();
    await index.search("zebra");
    await index.search("geheimnis");
    await index.search("steuer");
    await index.setSync(CONV, { cursor: messages[0]!.id, done: true });
    const dump = backend.dump();
    expect(dump.length).toBeGreaterThan(10);
    const haystacks: string[] = [];
    for (const { store, key, value } of dump) {
      expect(key).toMatch(/^[0-9a-f]{32}$/);
      haystacks.push(store + key);
      haystacks.push(new TextDecoder().decode(value));
      haystacks.push(Buffer.from(value).toString("latin1"));
      haystacks.push(Buffer.from(value).toString("utf16le"));
    }
    const all = haystacks.join("\n").toLowerCase();
    const secrets = ["zebrastreifen", "geheimnis", "rechnung", "kanzlei", "hinterlegt", "steuererklaerung"];
    const forbidden = [
      "steuererklaerung.pdf",
      "alice@t.local",
      "alice",
      CONV.toLowerCase(),
      "n.example",
      "01j9zk3g5m8q2w4e6r8t0y2vc",
      "01j9zk3g5m8q2w4e6r8t0y2roo",
      ...messages.map((m) => m.id.toLowerCase()),
    ];
    for (const w of secrets) {
      for (let k = 4; k <= Math.min(8, w.length); k++) forbidden.push(w.slice(0, k));
      // 3-character prefixes are too short to rule out in random bytes; check the forms they would leak in.
      forbidden.push(`p:${w.slice(0, 3)}`, `"${w.slice(0, 3)}`);
    }
    for (const f of forbidden) expect(all.includes(f), `found ${JSON.stringify(f)} at rest`).toBe(false);
  });

  it("wrong keys find nothing, do not throw, and drop the unreadable data", async () => {
    const { backend, index } = await fresh();
    await index.add([msg("geheimnis eins"), msg("geheimnis zwei")]);
    await index.flush();
    expect(await index.search("geheimnis")).toHaveLength(2);
    const other = await SearchIndex.open(backend, otherKeys, { now: () => NOW });
    expect(await other.search("geheimnis")).toEqual([]);
    expect(await other.coverage()).toEqual([]);
    expect(await other.stats()).toEqual({ bytes: 0, conversations: 0, messages: 0, complete: 0 });
    expect(backend.dump()).toEqual([]);
    // The index keeps working under the new key.
    await other.add([msg("geheimnis drei")]);
    expect(await other.search("geheimnis")).toHaveLength(1);
  });

  it("survives reopening (state is persisted)", async () => {
    const { backend, index } = await fresh();
    await index.add([msg("persistent text", { files: ["a.txt"] })]);
    await index.setComplete(CONV, true);
    await index.flush();
    const again = await SearchIndex.open(backend, keys, { now: () => NOW });
    expect(await again.search("persist")).toHaveLength(1);
    const [cov] = await again.coverage(CONV);
    expect(cov).toMatchObject({ count: 1, complete: true });
  });

  it("edits replace, remove() and removeConversation() delete", async () => {
    const { backend, index } = await fresh();
    const m = msg("original wording", { files: ["old.txt"] });
    await index.add([m, msg("other message"), msg("conv two text", { conversation: CONV2 })]);
    await index.flush();
    await index.add([{ ...m, text: "edited phrasing", files: [] }]);
    expect(await index.search("original")).toEqual([]);
    expect(await index.search("old")).toEqual([]);
    const [edited] = await index.search("edited");
    expect(edited?.id).toBe(m.id);
    expect((await index.coverage(CONV))[0]!.count).toBe(2);

    const before = backend.dump().filter((r) => r.store === "postings").length;
    await index.remove(CONV, [m.id]);
    expect(await index.search("edited")).toEqual([]);
    expect(await index.search("phrasing")).toEqual([]);
    expect((await index.coverage(CONV))[0]!.count).toBe(1);
    // The postings that only held this message are gone.
    expect(backend.dump().filter((r) => r.store === "postings").length).toBeLessThan(before);

    // Removing a buffered (unflushed) message also works.
    const buffered = msg("buffered words");
    await index.add([buffered]);
    await index.remove(CONV, [buffered.id]);
    expect(await index.search("buffered")).toEqual([]);

    await index.removeConversation(CONV);
    expect(await index.search("other")).toEqual([]);
    expect((await index.coverage()).map((c) => c.conversation)).toEqual([CONV2]);
    expect(await index.search("conv")).toHaveLength(1);
    await index.removeConversation(CONV2);
    expect(await index.stats()).toEqual({ bytes: 0, conversations: 0, messages: 0, complete: 0 });
    // Only the (empty) conversation list is left.
    const left = backend.dump();
    expect(left).toHaveLength(1);
    expect(left[0]!.store).toBe("meta");
  });

  it("budget: the window skips and evicts old messages of non-complete conversations", async () => {
    let now = NOW;
    const { index } = await fresh({ now: () => now });
    await index.setComplete(CONV2, true);
    await index.add([
      msg("ancient history", { ts: NOW - 91 * DAY }),
      msg("ancient history", { ts: NOW - 91 * DAY, conversation: CONV2 }),
      msg("recent history", { ts: NOW - 10 * DAY }),
      msg("middle history", { ts: NOW - 50 * DAY }),
    ]);
    expect((await index.search("ancient")).map((h) => h.conversation)).toEqual([CONV2]);
    expect(await index.enforceBudget()).toBe(0);
    now = NOW + 45 * DAY;
    expect(await index.enforceBudget()).toBe(1);
    expect(await index.search("middle")).toEqual([]);
    expect(await index.search("recent")).toHaveLength(1);
    expect(await index.search("ancient")).toHaveLength(1);
    const [cov] = await index.coverage(CONV);
    expect(cov).toMatchObject({ count: 1, oldest: NOW - 10 * DAY, newest: NOW - 10 * DAY });
    // Turning "complete" off applies the window at the next enforceBudget().
    await index.setComplete(CONV2, false);
    expect((await index.search("ancient")).length).toBe(1);
    expect(await index.enforceBudget()).toBe(1);
    expect(await index.search("ancient")).toEqual([]);
  });

  it("budget: the byte cap evicts oldest first across non-complete conversations", async () => {
    const { index } = await fresh();
    const text = (i: number) => `message number ${i} with some padding text to have a few bytes`;
    const one = msg(text(0), { ts: NOW - 30 * DAY });
    await index.add([one]);
    await index.flush();
    const perMessage = (await index.stats()).bytes;
    await index.remove(CONV, [one.id]);

    const capped = await fresh({ maxBytes: Math.floor(perMessage * 4.5) });
    const msgs = [
      msg(text(1), { ts: NOW - 30 * DAY }),
      msg(text(2), { ts: NOW - 20 * DAY, conversation: CONV2 }),
      msg(text(3), { ts: NOW - 10 * DAY }),
      msg(text(4), { ts: NOW - 5 * DAY, conversation: CONV2 }),
      msg(text(5), { ts: NOW - 2 * DAY }),
      msg(text(6), { ts: NOW - DAY, conversation: CONV2 }),
    ];
    await capped.index.add(msgs);
    // A complete conversation is not counted and not evicted.
    const keep = msg(text(7), { ts: NOW - 60 * DAY, conversation: "n.example/complete" });
    await capped.index.setComplete("n.example/complete", true);
    await capped.index.add([keep]);
    expect(await capped.index.enforceBudget()).toBe(2);
    const left = (await capped.index.search("message")).map((h) => h.id);
    expect(left).toEqual([msgs[5]!.id, msgs[4]!.id, msgs[3]!.id, msgs[2]!.id, keep.id]);
    const covs = await capped.index.coverage();
    const open = covs.filter((c) => !c.complete).reduce((n, c) => n + c.bytes, 0);
    expect(open).toBeLessThanOrEqual(Math.floor(perMessage * 4.5));
    expect(covs.find((c) => c.conversation === CONV2)?.oldest).toBe(NOW - 5 * DAY);
  });

  it("coverage and stats reflect counts, bounds, the complete flag and the sync bookkeeping; clear() empties", async () => {
    const { backend, index } = await fresh();
    expect(await index.coverage(CONV)).toEqual([
      { conversation: CONV, count: 0, bytes: 0, oldest: null, newest: null, complete: false, sync: { done: false, cursor: null, reachedStart: false } },
    ]);
    await index.add([msg("one", { ts: NOW - 3 * DAY }), msg("two", { ts: NOW - DAY }), msg("three", { ts: NOW - 2 * DAY })]);
    await index.setSync(CONV, { cursor: "c1" });
    await index.setSync(CONV, { reachedStart: true });
    await index.setComplete(CONV2, true);
    const [cov] = await index.coverage(CONV);
    expect(cov).toMatchObject({
      conversation: CONV,
      count: 3,
      oldest: NOW - 3 * DAY,
      newest: NOW - DAY,
      complete: false,
      sync: { done: false, cursor: "c1", reachedStart: true },
    });
    expect(cov!.bytes).toBeGreaterThan(0);
    const stats = await index.stats();
    expect(stats).toMatchObject({ conversations: 2, messages: 3, complete: 1 });
    expect(stats.bytes).toBe(cov!.bytes);
    await index.clear();
    expect(backend.dump()).toEqual([]);
    expect(await index.coverage()).toEqual([]);
    expect(await index.search("one")).toEqual([]);
  });

  it("flushes automatically at 200 buffered messages", async () => {
    const { backend, index } = await fresh();
    await index.add(Array.from({ length: 199 }, (_, i) => msg(`text ${i}`)));
    expect(backend.dump()).toEqual([]);
    await index.add([msg("the 200th")]);
    expect(backend.dump().length).toBeGreaterThan(0);
  });

  it("refuses everything after lock()", async () => {
    const { index } = await fresh();
    await index.add([msg("locked away")]);
    index.lock();
    await expect(index.add([msg("x")])).rejects.toBeInstanceOf(SearchLockedError);
    await expect(index.search("locked")).rejects.toBeInstanceOf(SearchLockedError);
    await expect(index.flush()).rejects.toBeInstanceOf(SearchLockedError);
    await expect(index.coverage()).rejects.toBeInstanceOf(SearchLockedError);
    await expect(index.enforceBudget()).rejects.toBeInstanceOf(SearchLockedError);
  });

  it("serializes concurrent calls", async () => {
    const { index } = await fresh();
    const ops = Array.from({ length: 20 }, (_, i) => index.add([msg(`parallel ${i}`)]));
    const found = index.search("parallel");
    await Promise.all(ops);
    expect(await found).toHaveLength(20);
  });
});

describe("performance", () => {
  const words =
    "der die das und ist nicht ein eine wir haben morgen heute treffen projekt bericht rechnung kunde server " +
    "update release fehler behoben getestet bitte danke schön können sollten werden noch schon wieder meeting " +
    "the and is not we have tomorrow today meeting project report invoice customer deploy build pipeline review " +
    "merge request branch feature ticket priority deadline budget quarterly numbers sales marketing design " +
    "verschlüsselung schlüssel nachricht kanal gruppe benutzer passwort sicherheit straße müller größe " +
    "datenbank migration backup wiederherstellung konfiguration dokumentation besprechung zusammenfassung";
  const vocab = words.split(" ");

  it("indexes 2000 messages of ~20 words at ≤ 2 ms per message", async () => {
    let seed = 42;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    const messages: IndexedMessage[] = Array.from({ length: 2000 }, (_, i) => {
      const n = 15 + Math.floor(rnd() * 11);
      const text = Array.from({ length: n }, () => vocab[Math.floor(rnd() * vocab.length)]).join(" ") + ` #${i}.`;
      const ts = NOW - (2000 - i) * 60_000;
      return { conversation: `n.example/conv${i % 4}`, id: ulid(ts, i), ts, author: `user${i % 7}@t.local`, text, files: i % 50 === 0 ? [`file-${i}.pdf`] : [] };
    });
    const { index } = await fresh();
    const start = performance.now();
    for (let i = 0; i < messages.length; i += 100) await index.add(messages.slice(i, i + 100));
    await index.flush();
    const ms = performance.now() - start;
    console.info(`search index: ${(ms / 2000).toFixed(3)} ms per message (${ms.toFixed(0)} ms for 2000)`);
    expect(ms / 2000).toBeLessThan(2);
    expect((await index.stats()).messages).toBe(2000);
    const t0 = performance.now();
    const hits = await index.search("verschlüss");
    console.info(`search index: query took ${(performance.now() - t0).toFixed(1)} ms, ${hits.length} hits`);
    expect(hits.length).toBe(50);
  });
});

describe("entries of encrypted files channels (SEARCH.md §3.6)", () => {
  const FILES = "n.example/01J9ZK3G5M8Q2W4E6R8T0Y2VF0";
  const entry = (name: string, folder: string, category: string, opts: Partial<IndexedMessage> = {}): IndexedMessage =>
    msg(`${name}\n${folder}`, {
      conversation: FILES,
      room: "R1",
      file: { kind: "file", name, folder, mime: category === "images" ? "image/png" : "application/pdf", category, size: 1234, thumbnail: category === "images", parent: "P1" },
      ...opts,
    });

  it("finds entries by name and folder, returns the file part and filters by category, uploader and date", async () => {
    const { index, backend } = await fresh();
    const photo = entry("Holiday beach.png", "Trips/2026", "images", { author: "bob@t.local", ts: NOW - 5 * DAY });
    const plan = entry("Quarterly plan.pdf", "Board", "documents");
    await index.add([photo, plan, msg("the beach was great")]);
    const hits = await index.search("beach", { kind: "files" });
    expect(hits.map((h) => h.id)).toEqual([photo.id]);
    expect(hits[0]!.file).toEqual(photo.file);
    expect(hits[0]!.room).toBe("R1");
    expect((await index.search("trips")).map((h) => h.id)).toEqual([photo.id]);
    expect((await index.search("beach", { kind: "messages" })).map((h) => h.file)).toEqual([undefined]);
    expect((await index.search("", { category: "documents" })).map((h) => h.id)).toEqual([plan.id]);
    expect((await index.search("", { author: "bob@t.local", kind: "files" })).map((h) => h.id)).toEqual([photo.id]);
    expect((await index.search("", { after: NOW - DAY, kind: "files" })).map((h) => h.id)).toEqual([plan.id]);
    // Removing a deleted entry; nothing readable in the backend.
    await index.remove(FILES, [photo.id]);
    expect(await index.search("beach", { kind: "files" })).toEqual([]);
    await index.flush();
    for (const s of ["docs", "postings", "meta"] as const) {
      for (const k of await backend.keys(s)) {
        const text = new TextDecoder().decode((await backend.get(s, k))!);
        expect(text).not.toMatch(/Quarterly|Board|documents|pdf/);
      }
    }
  });
});
