// SPDX-License-Identifier: Apache-2.0
/**
 * The bot's view of the conversations on its nodes: the room channels it can view (from `GET /rooms/{id}`, kept
 * current by the channel events), its DMs, and a short memory of conversation ids that a reload did not find, so
 * that repeated sends to a wrong id do not reload every room each time. Reloads of a node are single flight and
 * fetch the rooms with bounded concurrency.
 */
import { qualify } from "@tavrn/e2ee";
import type { Channel, TavrnApi } from "@tavrn/sdk";
import type { BotLogger } from "./logger";

export interface ChannelInfo {
  node: string;
  roomId: string;
  id: string;
  kind: string;
  encrypted: boolean;
  noBots: boolean;
}

/** A DM or group DM: whether it is encrypted (always, on current nodes) and its members. */
export interface DirectInfo {
  encrypted: boolean;
  members: string[];
}

/** What the directory needs of a node link. */
export interface DirectoryLink {
  readonly domain: string;
  readonly api: Pick<TavrnApi, "rooms">;
}

export interface DirectoryOptions {
  logger: BotLogger;
  /** After a room's channels were (re)loaded: the bot's eager joins. */
  onRoomLoaded?: (link: DirectoryLink, channels: Channel[]) => Promise<void>;
  /** Rooms fetched at the same time during a reload (default 4). */
  concurrency?: number;
  /** How long an id a reload did not find is not looked up again (default 30 s). */
  unknownTtlMs?: number;
  now?: () => number;
}

/** At most this many unknown ids are remembered (the oldest are dropped). */
const MAX_UNKNOWN = 1000;

/** Runs `fn` over `items` with at most `limit` at a time. */
export async function eachLimited<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) await fn(items[next++]!);
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
}

export class ConversationDirectory {
  readonly channels = new Map<string, ChannelInfo>();
  readonly direct = new Map<string, DirectInfo>();
  private readonly unknown = new Map<string, number>();
  private readonly refreshing = new Map<string, Promise<void>>();

  constructor(private readonly opts: DirectoryOptions) {}

  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  remember(node: string, c: Channel): void {
    const q = qualify(node, c.id);
    this.channels.set(q, { node, roomId: c.room_id, id: c.id, kind: c.kind, encrypted: !!c.encrypted, noBots: !!c.no_bots_effective });
    this.unknown.delete(q);
  }

  rememberDirect(q: string, info: DirectInfo): void {
    this.direct.set(q, info);
    this.unknown.delete(q);
  }

  /** The room of a known channel, null for DMs and unknown ids. */
  roomOf(q: string): string | null {
    return this.channels.get(q)?.roomId ?? null;
  }

  /** Forgets the channels of a room (uninstall); true when the node still has channels the bot knows. */
  forgetRoom(node: string, roomId: string): boolean {
    for (const [q, c] of [...this.channels]) if (c.node === node && c.roomId === roomId) this.channels.delete(q);
    return [...this.channels.values()].some((c) => c.node === node);
  }

  /** Reads a room's channels (the ones the bot can view) and hands them to `onRoomLoaded`; failures are logged. */
  async loadRoom(link: DirectoryLink, roomId: string): Promise<void> {
    let channels: Channel[];
    try {
      channels = (await link.api.rooms.get(roomId)).channels;
    } catch (e) {
      this.opts.logger.warn("room could not be loaded", { node: link.domain, room: roomId, error: e });
      return;
    }
    for (const q of [...this.channels.keys()]) if (this.channels.get(q)?.roomId === roomId && q.startsWith(`${link.domain}/`)) this.channels.delete(q);
    for (const c of channels) this.remember(link.domain, c);
    await this.opts.onRoomLoaded?.(link, channels);
  }

  /**
   * Reloads every room of a node (single flight: a reload requested while one runs shares it). Rejects when the rooms
   * cannot be listed; single rooms that fail are logged and skipped.
   */
  refreshRooms(link: DirectoryLink): Promise<void> {
    let running = this.refreshing.get(link.domain);
    if (running) return running;
    running = (async () => {
      const rooms = await link.api.rooms.list();
      await eachLimited(rooms, this.opts.concurrency ?? 4, (room) => this.loadRoom(link, room.id));
    })().finally(() => this.refreshing.delete(link.domain));
    this.refreshing.set(link.domain, running);
    return running;
  }

  /**
   * A room channel by its qualified id: known, or after one reload of the node's rooms. An id the reload did not find
   * is answered from memory for a short while (no reload per call for a wrong id).
   */
  async find(link: DirectoryLink, q: string): Promise<ChannelInfo | undefined> {
    const known = this.channels.get(q);
    if (known) return known;
    const missingUntil = this.unknown.get(q);
    if (missingUntil !== undefined && missingUntil > this.now()) return undefined;
    await this.refreshRooms(link);
    const found = this.channels.get(q);
    if (!found) {
      this.unknown.delete(q);
      this.unknown.set(q, this.now() + (this.opts.unknownTtlMs ?? 30_000));
      if (this.unknown.size > MAX_UNKNOWN) this.unknown.delete(this.unknown.keys().next().value!);
    }
    return found;
  }
}
