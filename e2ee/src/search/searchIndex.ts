// SPDX-License-Identifier: MPL-2.0
/**
 * The local encrypted search index of encrypted channels and DMs (design note 4.4 "Search"). Messages are
 * indexed on the device after decryption; the server never sees a query.
 *
 * Storage layout (every value sealed with AES-GCM under `aad = store + NUL + key`, every key an HMAC
 * token key, never an id or a word):
 * - `docs` / `tokenKey("doc", conversation, id)` → `{ c, m, t, a, x, f, k }` (conversation, message id,
 *   time, author, text, file names, the lookup keys of the message);
 * - `postings` / `tokenKey("tok", conversation, lookupKey)` → sorted message ids. Postings are per
 *   conversation, so equal words in different conversations are not linkable;
 * - `meta` / `tokenKey("conv", conversation)` → counts, bounds, the "complete" flag, the sync
 *   bookkeeping and the message ids per UTC day (oldest-first eviction); `meta` / `tokenKey("list")` →
 *   all conversations.
 *
 * Byte accounting (budget, stats) is an approximation: the sealed doc length plus 32 bytes per posting
 * entry of the doc. Records that the index cannot open (data sealed under another local key after an
 * identity reset, or damaged data) are dropped when the index is opened.
 *
 * Search returns the newest hits first and ANDs all terms. Posting ids are processed newest id first,
 * which relies on message ids being ULIDs (time-ordered within a conversation). An empty query (or one
 * without words) returns the newest messages matching the filters when at least one of `author`,
 * `after`, `before` or `hasFile` is given, and nothing otherwise.
 */
import type { SearchBackend, SearchStore, SearchWrite } from "./backend";
import { SearchLockedError, open as openSealed, seal, tokenKey, type SearchKeys } from "./keys";
import { MAX_INDEXED_CHARS, cutText, indexKeys, matches, queryTerms, snippet, type QueryTerm } from "./tokenize";

export const DEFAULT_WINDOW_DAYS = 90;
export const DEFAULT_MAX_BYTES = 200 * 1024 * 1024;
export const MAX_RESULTS = 50;
/** Buffered messages that trigger an automatic flush. */
export const FLUSH_AT = 200;
/** Accounted bytes per posting entry. */
export const POSTING_ENTRY_BYTES = 32;
/** Cached token keys at most. */
const TOKEN_CACHE = 50_000;
/** Docs read per round on the search path. */
const DOC_CHUNK = 128;
const DAY_MS = 86_400_000;

/**
 * An entry of an encrypted files channel (SEARCH.md §3.6), indexed as a doc of the channel's conversation with the
 * entry id as its id, the upload date as its time and the uploader as its author. Never thumbnail bytes.
 */
export interface IndexedFile {
  kind: "file" | "folder";
  name: string;
  /** Folder path, "A/B" (empty at the top level). */
  folder: string;
  /** Empty for folders. */
  mime: string;
  /** Upload category (PROTOCOL.md §7a); empty for folders. */
  category: string;
  /** Plaintext bytes. */
  size: number;
  /** The entry has a thumbnail (the client fetches it from its preview cache or the node). */
  thumbnail: boolean;
  /** Parent folder id (null at the top level). */
  parent: string | null;
}

export interface IndexedMessage {
  /** Qualified conversation id "<node>/<ulid>" (opaque here). */
  conversation: string;
  /** Message id (ULID). */
  id: string;
  /** created_at in ms. */
  ts: number;
  /** Author address. */
  author: string;
  /** Decrypted body (plus embed titles etc., the caller decides); cut to MAX_INDEXED_CHARS. */
  text: string;
  /** Attachment file names (never contents). */
  files: string[];
  /** Room of a room channel (the client needs it to open the message); absent for DMs. Stored sealed. */
  room?: string;
  /** The thread of a thread message (PROTOCOL.md §7e; the client opens it there). Stored sealed. */
  thread?: string;
  /** Entries of encrypted files channels instead of messages. Stored sealed. */
  file?: IndexedFile;
}

export interface SearchFilter {
  /** Restrict to these conversations (default: all indexed). */
  conversations?: string[];
  /** Exact author address. */
  author?: string;
  /** ms, after < ts. */
  after?: number;
  /** ms, ts < before. */
  before?: number;
  hasFile?: boolean;
  /** Only messages or only entries of files channels (default both). */
  kind?: "messages" | "files";
  /** Entries of files channels of this upload category. */
  category?: string;
  /** Default and maximum MAX_RESULTS. */
  limit?: number;
}

export interface LocalHit {
  conversation: string;
  id: string;
  ts: number;
  author: string;
  /** Plain text with MARK_START/MARK_END around the matches. */
  snippet: string;
  files: string[];
  /** The room of a room channel, as given to `add`. */
  room?: string;
  /** The thread, as given to `add`. */
  thread?: string;
  /** The entry of a files channel, as given to `add`. */
  file?: IndexedFile;
}

export interface SyncState {
  done: boolean;
  cursor: string | null;
  reachedStart: boolean;
}

export interface Coverage {
  conversation: string;
  count: number;
  bytes: number;
  /** ms of the oldest indexed message. */
  oldest: number | null;
  /** ms of the newest indexed message. */
  newest: number | null;
  /** "Keep the full history on this device" (no window, no byte cap). */
  complete: boolean;
  /** Background sync bookkeeping, opaque to the index. */
  sync: SyncState;
}

export interface BudgetOptions {
  windowDays?: number;
  maxBytes?: number;
  now?: () => number;
}

interface DocRecord {
  c: string;
  m: string;
  t: number;
  a: string;
  x: string;
  f: string[];
  /** Room id (room channels). */
  r?: string;
  /** Thread id (thread messages). */
  h?: string;
  /** Entry of a files channel. */
  e?: IndexedFile;
  /** Lookup keys of the message (its posting token keys are derived from them). */
  k: string[];
}

interface MetaRecord {
  c: string;
  count: number;
  bytes: number;
  oldest: number | null;
  newest: number | null;
  complete: boolean;
  sync: SyncState;
  days: Record<string, string[]>;
}

interface ConvState {
  meta: MetaRecord;
  /** Message id → UTC day (derived from `meta.days`). */
  ids: Map<string, string>;
}

interface LoadedDoc {
  doc: DocRecord;
  /** Accounted bytes. */
  bytes: number;
}

/** Changes collected by one operation and written in one backend batch. */
interface Batch {
  /** Posting token key → ids to add / remove (read-modify-write at commit). */
  postings: Map<string, { add: Set<string>; del: Set<string> }>;
  writes: SearchWrite[];
  /** Docs to delete (conversation, message id). */
  deleteDocs: [string, string][];
  dirty: Set<string>;
  /** Conversations whose meta record is deleted. */
  dropped: Set<string>;
  list: boolean;
  /** Conversations whose oldest/newest must be recomputed. */
  bounds: Set<string>;
  /** ts of docs written in this batch (conversation → id → ts). */
  fresh: Map<string, Map<string, number>>;
}

const dayOf = (ts: number): string => new Date(ts).toISOString().slice(0, 10);
const aad = (store: SearchStore, key: string): string => `${store}\u0000${key}`;
const defaultSync = (): SyncState => ({ done: false, cursor: null, reachedStart: false });
const docBytes = (sealedLen: number, keys: number): number => sealedLen + POSTING_ENTRY_BYTES * keys;

function newBatch(): Batch {
  return { postings: new Map(), writes: [], deleteDocs: [], dirty: new Set(), dropped: new Set(), list: false, bounds: new Set(), fresh: new Map() };
}

function cleanMessage(m: IndexedMessage): IndexedMessage {
  if (typeof m.conversation !== "string" || typeof m.id !== "string" || !Number.isFinite(m.ts)) {
    throw new TypeError("invalid indexed message");
  }
  return {
    conversation: m.conversation,
    id: m.id,
    ts: m.ts,
    author: String(m.author ?? ""),
    text: cutText(String(m.text ?? ""), MAX_INDEXED_CHARS),
    files: Array.isArray(m.files) ? m.files.map(String) : [],
    ...(typeof m.room === "string" && m.room ? { room: m.room } : {}),
    ...(typeof m.thread === "string" && m.thread ? { thread: m.thread } : {}),
    ...(m.file && typeof m.file === "object" ? { file: cleanFile(m.file) } : {}),
  };
}

function cleanFile(f: IndexedFile): IndexedFile {
  return {
    kind: f.kind === "folder" ? "folder" : "file",
    name: String(f.name ?? ""),
    folder: String(f.folder ?? ""),
    mime: String(f.mime ?? ""),
    category: String(f.category ?? ""),
    size: Number.isFinite(f.size) ? f.size : 0,
    thumbnail: f.thumbnail === true,
    parent: typeof f.parent === "string" ? f.parent : null,
  };
}

export class SearchIndex {
  private keys: SearchKeys | null;
  private readonly tokens = new Map<string, string>();
  private convs = new Map<string, ConvState>();
  private pending = new Map<string, Map<string, IndexedMessage>>();
  private queue: Promise<unknown> = Promise.resolve();
  private readonly windowDays: number;
  private readonly maxBytes: number;
  private readonly now: () => number;

  private constructor(
    private readonly backend: SearchBackend,
    keys: SearchKeys,
    opts: BudgetOptions,
  ) {
    this.keys = keys;
    this.windowDays = opts.windowDays ?? DEFAULT_WINDOW_DAYS;
    this.maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
    this.now = opts.now ?? Date.now;
  }

  static async open(backend: SearchBackend, keys: SearchKeys, opts: BudgetOptions = {}): Promise<SearchIndex> {
    const idx = new SearchIndex(backend, keys, opts);
    await idx.load();
    return idx;
  }

  /**
   * Upsert: an id already indexed is replaced (edits). Messages older than the window of a non-complete
   * conversation are skipped. Buffered in memory; flushed automatically when the buffer holds ≥ 200
   * messages and by flush().
   */
  add(messages: IndexedMessage[]): Promise<void> {
    return this.run(async () => {
      const cutoff = this.now() - this.windowDays * DAY_MS;
      for (const raw of messages) {
        const m = cleanMessage(raw);
        if (!this.convs.get(m.conversation)?.meta.complete && m.ts < cutoff) continue;
        let p = this.pending.get(m.conversation);
        if (!p) this.pending.set(m.conversation, (p = new Map()));
        p.delete(m.id); // keep the newest version last
        p.set(m.id, m);
      }
      if (this.pendingCount() >= FLUSH_AT) await this.flushPending();
    });
  }

  /** Deletes messages (their docs and their posting entries). */
  remove(conversation: string, ids: string[]): Promise<void> {
    return this.run(async () => {
      const p = this.pending.get(conversation);
      for (const id of ids) p?.delete(id);
      await this.flushPending();
      const st = this.convs.get(conversation);
      if (!st) return;
      const known = [...new Set(ids)].filter((id) => st.ids.has(id));
      if (known.length === 0) return;
      const b = newBatch();
      const docs = await this.readDocs(conversation, known);
      for (const id of known) this.dropDoc(b, st, id, docs.get(id));
      await this.commit(b);
    });
  }

  /** Deletes a conversation with all its messages, postings and its meta record. */
  removeConversation(conversation: string): Promise<void> {
    return this.run(async () => {
      this.pending.delete(conversation);
      await this.flushPending();
      const st = this.convs.get(conversation);
      if (!st) return;
      const b = newBatch();
      const lookups = new Set<string>();
      const ids = [...st.ids.keys()];
      for (let i = 0; i < ids.length; i += 512) {
        const chunk = ids.slice(i, i + 512);
        const docs = await this.readDocs(conversation, chunk);
        for (const d of docs.values()) for (const l of d.doc.k) lookups.add(l);
        const docKeys = await Promise.all(chunk.map((id) => this.docKey(conversation, id)));
        for (const key of docKeys) b.writes.push({ store: "docs", key, value: null });
      }
      // Postings are per conversation: delete them outright instead of a read-modify-write.
      const toks = await Promise.all([...lookups].map((l) => this.tok(conversation, l)));
      for (const key of toks) b.writes.push({ store: "postings", key, value: null });
      this.convs.delete(conversation);
      b.dropped.add(conversation);
      b.list = true;
      await this.commit(b);
    });
  }

  flush(): Promise<void> {
    return this.run(() => this.flushPending());
  }

  /** Newest hits first; all terms must match. See the module comment for the empty query. */
  search(query: string, filter: SearchFilter = {}): Promise<LocalHit[]> {
    return this.run(async () => {
      await this.flushPending();
      const terms = queryTerms(query);
      const limit = Math.max(1, Math.min(MAX_RESULTS, Math.floor(filter.limit ?? MAX_RESULTS)));
      const scope = filter.conversations ? [...new Set(filter.conversations)].filter((c) => this.convs.has(c)) : [...this.convs.keys()];
      const hasFilter =
        filter.author !== undefined || filter.after !== undefined || filter.before !== undefined || filter.hasFile !== undefined || filter.kind !== undefined || filter.category !== undefined;
      if (terms.length === 0 && !hasFilter) return [];
      const hits: DocRecord[] = [];
      for (const c of scope) {
        hits.push(...(terms.length ? await this.searchConversation(c, terms, filter, limit) : await this.scanConversation(c, filter, limit)));
      }
      hits.sort((a, b) => b.t - a.t || (a.m < b.m ? 1 : a.m > b.m ? -1 : 0));
      return hits.slice(0, limit).map((d) => ({
        conversation: d.c,
        id: d.m,
        ts: d.t,
        author: d.a,
        snippet: snippet(d.x, terms),
        files: d.f,
        ...(d.r ? { room: d.r } : {}),
        ...(d.h ? { thread: d.h } : {}),
        ...(d.e ? { file: d.e } : {}),
      }));
    });
  }

  /** Flushes first. Unknown conversation → one empty entry. */
  coverage(conversation?: string): Promise<Coverage[]> {
    return this.run(async () => {
      await this.flushPending();
      if (conversation !== undefined) {
        const st = this.convs.get(conversation);
        return [
          st
            ? this.coverageOf(st.meta)
            : { conversation, count: 0, bytes: 0, oldest: null, newest: null, complete: false, sync: defaultSync() },
        ];
      }
      return [...this.convs.values()].map((st) => this.coverageOf(st.meta));
    });
  }

  /** Off → the budget applies at the next enforceBudget(). */
  setComplete(conversation: string, on: boolean): Promise<void> {
    return this.run(async () => {
      const b = newBatch();
      const st = this.conv(b, conversation);
      st.meta.complete = on;
      b.dirty.add(conversation);
      await this.commit(b);
    });
  }

  setSync(conversation: string, sync: Partial<SyncState>): Promise<void> {
    return this.run(async () => {
      const b = newBatch();
      const st = this.conv(b, conversation);
      const s = st.meta.sync;
      if (sync.done !== undefined) s.done = sync.done;
      if (sync.cursor !== undefined) s.cursor = sync.cursor;
      if (sync.reachedStart !== undefined) s.reachedStart = sync.reachedStart;
      b.dirty.add(conversation);
      await this.commit(b);
    });
  }

  /**
   * Window (non-complete conversations: drop messages older than now - windowDays) and byte cap over
   * non-complete conversations (drop oldest first across them until their total bytes ≤ maxBytes).
   * Returns the number of evicted messages.
   */
  enforceBudget(): Promise<number> {
    return this.run(async () => {
      await this.flushPending();
      const b = newBatch();
      let evicted = 0;
      const cutoff = this.now() - this.windowDays * DAY_MS;
      const cutoffDay = dayOf(cutoff);
      const open = () => [...this.convs.values()].filter((st) => !st.meta.complete);
      for (const st of open()) {
        const c = st.meta.c;
        for (const day of Object.keys(st.meta.days).sort()) {
          if (day > cutoffDay) break;
          const ids = [...(st.meta.days[day] ?? [])];
          const docs = await this.readDocs(c, ids);
          for (const id of ids) {
            const d = docs.get(id);
            if (day < cutoffDay || !d || d.doc.t < cutoff) {
              this.dropDoc(b, st, id, d);
              evicted++;
            }
          }
        }
      }
      let total = open().reduce((n, st) => n + st.meta.bytes, 0);
      while (total > this.maxBytes) {
        const candidates = open().filter((st) => st.meta.count > 0);
        let oldestDay: string | null = null;
        for (const st of candidates) {
          for (const day of Object.keys(st.meta.days)) if (oldestDay === null || day < oldestDay) oldestDay = day;
        }
        if (oldestDay === null) break;
        const victims: { st: ConvState; id: string; d: LoadedDoc | undefined; t: number }[] = [];
        for (const st of candidates) {
          const ids = st.meta.days[oldestDay];
          if (!ids?.length) continue;
          const docs = await this.readDocs(st.meta.c, [...ids]);
          for (const id of ids) {
            const d = docs.get(id);
            victims.push({ st, id, d, t: d?.doc.t ?? -Infinity });
          }
        }
        victims.sort((x, y) => x.t - y.t);
        for (const v of victims) {
          if (total <= this.maxBytes) break;
          const before = v.st.meta.bytes;
          this.dropDoc(b, v.st, v.id, v.d);
          total -= before - v.st.meta.bytes;
          evicted++;
        }
      }
      await this.commit(b);
      return evicted;
    });
  }

  /** Accounted bytes (see the module comment), conversations, messages, complete conversations. Flushes first. */
  stats(): Promise<{ bytes: number; conversations: number; messages: number; complete: number }> {
    return this.run(async () => {
      await this.flushPending();
      let bytes = 0;
      let messages = 0;
      let complete = 0;
      for (const st of this.convs.values()) {
        bytes += st.meta.bytes;
        messages += st.meta.count;
        if (st.meta.complete) complete++;
      }
      return { bytes, conversations: this.convs.size, messages, complete };
    });
  }

  /** Deletes everything in the backend (and the unflushed buffer). */
  clear(): Promise<void> {
    return this.run(async () => {
      this.pending.clear();
      this.convs.clear();
      await this.backend.clear();
    });
  }

  /** Forgets the keys, the caches and the unflushed buffer (lock); every later call throws SearchLockedError. */
  lock(): void {
    this.keys = null;
    this.tokens.clear();
    this.pending.clear();
    this.convs.clear();
  }

  // ---- internals ------------------------------------------------------------------------------------

  /** Serializes the public operations (one at a time) and refuses them once locked. */
  private run<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.queue.then(() => {
      this.k();
      return fn();
    });
    this.queue = p.catch(() => undefined);
    return p;
  }

  private k(): SearchKeys {
    if (!this.keys) throw new SearchLockedError();
    return this.keys;
  }

  private pendingCount(): number {
    let n = 0;
    for (const p of this.pending.values()) n += p.size;
    return n;
  }

  /** Posting token key of a lookup key in a conversation (cached; HMAC is the hot path). */
  private async tok(conversation: string, lookup: string): Promise<string> {
    const id = `${conversation}\u0000${lookup}`;
    const hit = this.tokens.get(id);
    if (hit !== undefined) return hit;
    const t = await tokenKey(this.k(), "tok", conversation, lookup);
    if (this.tokens.size >= TOKEN_CACHE) {
      const first = this.tokens.keys().next();
      if (!first.done) this.tokens.delete(first.value);
    }
    this.tokens.set(id, t);
    return t;
  }

  private docKey(conversation: string, id: string): Promise<string> {
    return tokenKey(this.k(), "doc", conversation, id);
  }

  private async load(): Promise<void> {
    const keys = this.k();
    this.convs.clear();
    const listKey = await tokenKey(keys, "list");
    const raw = await this.backend.get("meta", listKey);
    let list: string[] | null = null;
    if (raw) {
      try {
        list = await openSealed<string[]>(keys, aad("meta", listKey), raw);
      } catch {
        list = null;
      }
    }
    if (!list) {
      // Records sealed under another local key (identity reset) or damaged data: unusable, drop them.
      if (raw || (await this.backend.keys("meta")).length > 0) await this.backend.clear();
      return;
    }
    const metaKeys = await Promise.all(list.map((c) => tokenKey(keys, "conv", c)));
    const metas = await this.backend.getMany("meta", metaKeys);
    await Promise.all(
      list.map(async (c, i) => {
        const v = metas[i];
        if (!v) return;
        try {
          const meta = await openSealed<MetaRecord>(keys, aad("meta", metaKeys[i]!), v);
          if (meta.c !== c) return;
          const ids = new Map<string, string>();
          for (const [day, dayIds] of Object.entries(meta.days)) for (const id of dayIds) ids.set(id, day);
          this.convs.set(c, { meta, ids });
        } catch {
          // An unreadable meta record drops the conversation from the index.
        }
      }),
    );
  }

  private conv(b: Batch, conversation: string): ConvState {
    let st = this.convs.get(conversation);
    if (!st) {
      st = {
        meta: { c: conversation, count: 0, bytes: 0, oldest: null, newest: null, complete: false, sync: defaultSync(), days: {} },
        ids: new Map(),
      };
      this.convs.set(conversation, st);
      b.list = true;
      b.dirty.add(conversation);
    }
    return st;
  }

  private posting(b: Batch, key: string): { add: Set<string>; del: Set<string> } {
    let p = b.postings.get(key);
    if (!p) b.postings.set(key, (p = { add: new Set(), del: new Set() }));
    return p;
  }

  /** Reads and opens docs; unreadable or missing docs are left out. */
  private async readDocs(conversation: string, ids: string[]): Promise<Map<string, LoadedDoc>> {
    const out = new Map<string, LoadedDoc>();
    if (ids.length === 0) return out;
    const keys = this.k();
    const docKeys = await Promise.all(ids.map((id) => this.docKey(conversation, id)));
    const raws = await this.backend.getMany("docs", docKeys);
    await Promise.all(
      raws.map(async (raw, i) => {
        if (!raw) return;
        try {
          const doc = await openSealed<DocRecord>(keys, aad("docs", docKeys[i]!), raw);
          if (doc.c === conversation && doc.m === ids[i]) out.set(ids[i]!, { doc, bytes: docBytes(raw.length, doc.k.length) });
        } catch {
          // left out
        }
      }),
    );
    return out;
  }

  /** Removes a message from the meta state and queues the deletion of its doc and posting entries. */
  private dropDoc(b: Batch, st: ConvState, id: string, d: LoadedDoc | undefined, keepDoc = false): void {
    const c = st.meta.c;
    const day = st.ids.get(id);
    if (day === undefined) return;
    st.ids.delete(id);
    const dayIds = st.meta.days[day];
    if (dayIds) {
      const i = dayIds.indexOf(id);
      if (i >= 0) dayIds.splice(i, 1);
      if (dayIds.length === 0) delete st.meta.days[day];
    }
    st.meta.count = Math.max(0, st.meta.count - 1);
    b.dirty.add(c);
    // Oldest/newest only change when a boundary message goes (or its time is unknown).
    if (!d || st.meta.count === 0 || d.doc.t <= (st.meta.oldest ?? -Infinity) || d.doc.t >= (st.meta.newest ?? Infinity)) b.bounds.add(c);
    if (!d) return;
    st.meta.bytes = Math.max(0, st.meta.bytes - d.bytes);
    for (const l of d.doc.k) this.posting(b, `${c}\u0000${l}`).del.add(id);
    if (!keepDoc) b.deleteDocs.push([c, id]);
  }

  private async flushPending(): Promise<void> {
    if (this.pending.size === 0) return;
    const pending = this.pending;
    this.pending = new Map();
    const keys = this.k();
    const b = newBatch();
    for (const [c, msgs] of pending) {
      if (msgs.size === 0) continue;
      const st = this.conv(b, c);
      const list = [...msgs.values()];
      const old = await this.readDocs(c, list.filter((m) => st.ids.has(m.id)).map((m) => m.id));
      const prepared = await Promise.all(
        list.map(async (m) => {
          const lookups = indexKeys(m.files.length ? `${m.files.join("\n")}\n${m.text}` : m.text);
          const key = await this.docKey(c, m.id);
          const doc: DocRecord = { c, m: m.id, t: m.ts, a: m.author, x: m.text, f: m.files, k: lookups, ...(m.room ? { r: m.room } : {}), ...(m.thread ? { h: m.thread } : {}), ...(m.file ? { e: m.file } : {}) };
          const sealed = await seal(keys, aad("docs", key), doc);
          return { m, key, lookups, sealed };
        }),
      );
      let fresh = b.fresh.get(c);
      if (!fresh) b.fresh.set(c, (fresh = new Map()));
      for (const { m, key, lookups, sealed } of prepared) {
        const prev = old.get(m.id);
        let unchanged = new Set<string>();
        if (st.ids.has(m.id)) {
          if (prev) {
            const next = new Set(lookups);
            unchanged = new Set(prev.doc.k.filter((l) => next.has(l)));
            prev.doc.k = prev.doc.k.filter((l) => !next.has(l));
          }
          // The doc itself is overwritten below.
          this.dropDoc(b, st, m.id, prev, true);
        }
        b.writes.push({ store: "docs", key, value: sealed });
        for (const l of lookups) if (!unchanged.has(l)) this.posting(b, `${c}\u0000${l}`).add.add(m.id);
        const day = dayOf(m.ts);
        (st.meta.days[day] ??= []).push(m.id);
        st.ids.set(m.id, day);
        st.meta.count++;
        st.meta.bytes += docBytes(sealed.length, lookups.length);
        st.meta.oldest = st.meta.oldest === null ? m.ts : Math.min(st.meta.oldest, m.ts);
        st.meta.newest = st.meta.newest === null ? m.ts : Math.max(st.meta.newest, m.ts);
        fresh.set(m.id, m.ts);
        b.dirty.add(c);
      }
    }
    await this.commit(b);
  }

  /** Recomputes oldest/newest of a conversation from the docs of its first and last day. */
  private async fixBounds(b: Batch, st: ConvState): Promise<void> {
    const days = Object.keys(st.meta.days).sort();
    if (days.length === 0 || st.meta.count === 0) {
      st.meta.oldest = null;
      st.meta.newest = null;
      return;
    }
    const fresh = b.fresh.get(st.meta.c);
    const tsOf = async (day: string): Promise<number[]> => {
      const ids = st.meta.days[day] ?? [];
      const known = ids.filter((id) => fresh?.has(id)).map((id) => fresh!.get(id)!);
      const rest = ids.filter((id) => !fresh?.has(id));
      const docs = await this.readDocs(st.meta.c, rest);
      return [...known, ...[...docs.values()].map((d) => d.doc.t)];
    };
    const first = await tsOf(days[0]!);
    const last = days.length === 1 ? first : await tsOf(days[days.length - 1]!);
    st.meta.oldest = first.length ? Math.min(...first) : null;
    st.meta.newest = last.length ? Math.max(...last) : null;
  }

  /** Writes a batch: posting read-modify-write, docs, meta and list, in one backend write. */
  private async commit(b: Batch): Promise<void> {
    const keys = this.k();
    try {
      for (const c of b.bounds) {
        const st = this.convs.get(c);
        if (st) await this.fixBounds(b, st);
      }
      const deletes = await Promise.all(
        b.deleteDocs.map(async ([c, id]): Promise<SearchWrite> => ({ store: "docs", key: await this.docKey(c, id), value: null })),
      );
      // Postings: map "<conversation> NUL <lookup>" to token keys, then read, merge and reseal each once.
      const entries = [...b.postings.entries()].filter(([, p]) => p.add.size > 0 || p.del.size > 0);
      const toks = await Promise.all(
        entries.map(([id]) => {
          const i = id.indexOf("\u0000");
          return this.tok(id.slice(0, i), id.slice(i + 1));
        }),
      );
      const raws = await this.backend.getMany("postings", toks);
      const postingWrites = await Promise.all(
        entries.map(async ([, p], i): Promise<SearchWrite> => {
          const key = toks[i]!;
          const raw = raws[i];
          let ids: string[] = [];
          if (raw) {
            try {
              ids = await openSealed<string[]>(keys, aad("postings", key), raw);
            } catch {
              ids = [];
            }
          }
          const set = new Set(ids);
          for (const id of p.del) set.delete(id);
          for (const id of p.add) set.add(id);
          if (set.size === 0) return { store: "postings", key, value: null };
          const sorted = [...set].sort();
          return { store: "postings", key, value: await seal(keys, aad("postings", key), sorted) };
        }),
      );
      const metaWrites = await Promise.all([
        ...[...b.dirty].map(async (c): Promise<SearchWrite> => {
          const key = await tokenKey(keys, "conv", c);
          const st = this.convs.get(c);
          return { store: "meta", key, value: st ? await seal(keys, aad("meta", key), st.meta) : null };
        }),
        ...[...b.dropped].filter((c) => !b.dirty.has(c)).map(async (c): Promise<SearchWrite> => ({ store: "meta", key: await tokenKey(keys, "conv", c), value: null })),
      ]);
      if (b.list) {
        const key = await tokenKey(keys, "list");
        metaWrites.push({ store: "meta", key, value: await seal(keys, aad("meta", key), [...this.convs.keys()]) });
      }
      const all = [...b.writes, ...deletes, ...postingWrites, ...metaWrites];
      if (all.length) await this.backend.write(all);
    } catch (e) {
      // The in-memory state ran ahead of the stored one: reload it (the backend write is all or nothing).
      if (this.keys) await this.load().catch(() => undefined);
      throw e;
    }
  }

  private coverageOf(meta: MetaRecord): Coverage {
    return {
      conversation: meta.c,
      count: meta.count,
      bytes: meta.bytes,
      oldest: meta.oldest,
      newest: meta.newest,
      complete: meta.complete,
      sync: { ...meta.sync },
    };
  }

  private accept(d: DocRecord, f: SearchFilter): boolean {
    if (f.author !== undefined && d.a !== f.author) return false;
    if (f.after !== undefined && !(d.t > f.after)) return false;
    if (f.before !== undefined && !(d.t < f.before)) return false;
    if (f.hasFile !== undefined && f.hasFile !== d.f.length > 0) return false;
    if (f.kind === "files" && !d.e) return false;
    if (f.kind === "messages" && d.e) return false;
    if (f.category !== undefined && d.e?.category !== f.category) return false;
    return true;
  }

  private async searchConversation(c: string, terms: QueryTerm[], f: SearchFilter, limit: number): Promise<DocRecord[]> {
    const keys = this.k();
    const toks = await Promise.all(terms.map((t) => this.tok(c, t.key)));
    const raws = await this.backend.getMany("postings", toks);
    if (raws.some((r) => r === null)) return [];
    let lists: string[][];
    try {
      lists = await Promise.all(raws.map((r, i) => openSealed<string[]>(keys, aad("postings", toks[i]!), r!)));
    } catch {
      return [];
    }
    lists.sort((a, b) => a.length - b.length);
    let cand = lists[0] ?? [];
    for (const other of lists.slice(1)) {
      const s = new Set(other);
      cand = cand.filter((id) => s.has(id));
      if (cand.length === 0) return [];
    }
    // Newest ids first (ULIDs): stop once `limit` hits are found.
    cand.sort().reverse();
    const out: DocRecord[] = [];
    for (let i = 0; i < cand.length && out.length < limit; i += DOC_CHUNK) {
      const chunk = cand.slice(i, i + DOC_CHUNK);
      const docs = await this.readDocs(c, chunk);
      for (const id of chunk) {
        const d = docs.get(id)?.doc;
        if (!d || !this.accept(d, f)) continue;
        if (!matches(d.f.length ? `${d.x}\n${d.f.join("\n")}` : d.x, terms)) continue;
        out.push(d);
      }
    }
    return out;
  }

  /** Empty query: the newest messages of a conversation matching the filters (day by day, newest first). */
  private async scanConversation(c: string, f: SearchFilter, limit: number): Promise<DocRecord[]> {
    const st = this.convs.get(c);
    if (!st) return [];
    const out: DocRecord[] = [];
    const lastDay = f.before !== undefined ? dayOf(Math.max(0, f.before)) : null;
    const firstDay = f.after !== undefined ? dayOf(Math.max(0, f.after)) : null;
    for (const day of Object.keys(st.meta.days).sort().reverse()) {
      if (out.length >= limit) break;
      if (lastDay !== null && day > lastDay) continue;
      if (firstDay !== null && day < firstDay) break;
      const docs = await this.readDocs(c, [...(st.meta.days[day] ?? [])]);
      for (const { doc } of docs.values()) if (this.accept(doc, f)) out.push(doc);
    }
    return out;
  }
}
