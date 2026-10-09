// SPDX-License-Identifier: Apache-2.0
/**
 * Permissions, identical to the Rust implementation (server/src/permissions.rs).
 * Both must pass the test vectors in protocol/testvectors/permissions.json.
 * Permissions are 64-bit masks, hence BigInt; over the API they travel as decimal strings.
 */
export const Permission = {
  VIEW_CHANNEL: 1n << 0n,
  SEND_MESSAGES: 1n << 1n,
  MANAGE_MESSAGES: 1n << 2n,
  ATTACH_FILES: 1n << 3n,
  ADD_REACTIONS: 1n << 4n,
  MENTION_EVERYONE: 1n << 5n,
  CREATE_THREADS: 1n << 6n,
  MANAGE_CHANNELS: 1n << 7n,
  MANAGE_ROLES: 1n << 8n,
  MANAGE_ROOM: 1n << 9n,
  CREATE_INVITES: 1n << 10n,
  KICK_MEMBERS: 1n << 11n,
  BAN_MEMBERS: 1n << 12n,
  MODERATE_MEMBERS: 1n << 13n,
  PURGE: 1n << 14n,
  VIEW_AUDIT_LOG: 1n << 15n,
  CONNECT: 1n << 16n,
  SPEAK: 1n << 17n,
  STREAM: 1n << 18n,
  MUTE_MEMBERS: 1n << 19n,
  MOVE_MEMBERS: 1n << 20n,
  USE_SOUNDBOARD: 1n << 21n,
  MANAGE_EMOJIS: 1n << 22n,
  CHANGE_NICKNAME: 1n << 23n,
  MANAGE_NICKNAMES: 1n << 24n,
  PIN_MESSAGES: 1n << 25n,
  USE_CAMERA: 1n << 26n,
  USE_WHITEBOARD: 1n << 27n,
  MANAGE_WHITEBOARD: 1n << 28n,
  MANAGE_WEBHOOKS: 1n << 29n,
  PRIORITY_SPEAKER: 1n << 30n,
  USE_EXTERNAL_EMOJIS: 1n << 31n,
  USE_EXTERNAL_SOUNDS: 1n << 32n,
  MANAGE_FILES: 1n << 33n,
  READ_HISTORY: 1n << 34n,
  MANAGE_APPLICATIONS: 1n << 35n,
  MANAGE_THREADS: 1n << 36n,
  RESTORE_HISTORY: 1n << 37n,
  ADMINISTRATOR: 1n << 62n,
} as const;

export type PermissionName = keyof typeof Permission;

export const ALL_PERMISSIONS: bigint = Object.values(Permission).reduce((a, b) => a | b, 0n);

/**
 * Management-class permissions that can never be granted to `@everyone`, neither on the role nor as an
 * `allow` of a channel or category override (protocol/permissions.md, "Restricted for @everyone"). The
 * node refuses them with `role.everyone_restricted`; role editors grey them out for `@everyone`.
 */
export const EVERYONE_RESTRICTED: bigint = [
  Permission.ADMINISTRATOR,
  Permission.MANAGE_ROOM,
  Permission.MANAGE_ROLES,
  Permission.MANAGE_CHANNELS,
  Permission.VIEW_AUDIT_LOG,
  Permission.KICK_MEMBERS,
  Permission.BAN_MEMBERS,
  Permission.MODERATE_MEMBERS,
  Permission.MANAGE_EMOJIS,
  Permission.MANAGE_WHITEBOARD,
  Permission.MANAGE_WEBHOOKS,
  Permission.MANAGE_FILES,
  Permission.MOVE_MEMBERS,
  Permission.MUTE_MEMBERS,
  Permission.MANAGE_MESSAGES,
  Permission.MANAGE_NICKNAMES,
  Permission.MANAGE_APPLICATIONS,
  Permission.MANAGE_THREADS,
  Permission.RESTORE_HISTORY,
  Permission.PURGE,
].reduce((a, b) => a | b, 0n);

/**
 * Removed from the effective permissions in system channels (the welcome channel is read-only for everyone,
 * protocol/permissions.md "System channels").
 */
export const SYSTEM_CHANNEL_DENIED: bigint =
  Permission.SEND_MESSAGES | Permission.ATTACH_FILES | Permission.CREATE_THREADS | Permission.MENTION_EVERYONE | Permission.USE_WHITEBOARD | Permission.PIN_MESSAGES;

/**
 * Always granted in system channels: the welcome channel is the room's security log, no override can hide it or its
 * history (protocol/permissions.md "System channels", design note 4.13 item 12).
 */
export const SYSTEM_CHANNEL_FORCED: bigint = Permission.VIEW_CHANNEL | Permission.READ_HISTORY;

/** Permissions of every member in a DM or group DM (the node's `DIRECT_PERMS`). */
export const DIRECT_PERMISSIONS: bigint =
  Permission.VIEW_CHANNEL | Permission.SEND_MESSAGES | Permission.ATTACH_FILES | Permission.ADD_REACTIONS | Permission.PIN_MESSAGES | Permission.USE_WHITEBOARD;

/** Is this permission (a bit or its name) one that `@everyone` can never hold? */
export function isEveryoneRestricted(permission: bigint | PermissionName): boolean {
  const bit = typeof permission === "bigint" ? permission : Permission[permission];
  return (EVERYONE_RESTRICTED & bit) !== 0n;
}

/** For UIs: name, bit and English label in display order (the web client localizes by `name`). */
export const PERMISSION_LABELS: { name: PermissionName; label: string; group: string }[] = [
  { name: "VIEW_CHANNEL", label: "View channel", group: "General" },
  { name: "SEND_MESSAGES", label: "Send messages", group: "Text" },
  { name: "ATTACH_FILES", label: "Attach files", group: "Text" },
  { name: "ADD_REACTIONS", label: "Add reactions", group: "Text" },
  { name: "MENTION_EVERYONE", label: "Mention @everyone", group: "Text" },
  { name: "CREATE_THREADS", label: "Create threads", group: "Text" },
  { name: "PIN_MESSAGES", label: "Pin messages", group: "Text" },
  { name: "MANAGE_MESSAGES", label: "Manage messages", group: "Moderation" },
  { name: "MANAGE_THREADS", label: "Manage threads", group: "Moderation" },
  { name: "KICK_MEMBERS", label: "Remove members", group: "Moderation" },
  { name: "BAN_MEMBERS", label: "Ban members", group: "Moderation" },
  { name: "MODERATE_MEMBERS", label: "Moderate members (timeout)", group: "Moderation" },
  { name: "PURGE", label: "Bulk delete", group: "Moderation" },
  { name: "VIEW_AUDIT_LOG", label: "View audit log", group: "Moderation" },
  { name: "MANAGE_NICKNAMES", label: "Manage nicknames", group: "Moderation" },
  { name: "RESTORE_HISTORY", label: "Restore history after a key reset", group: "Moderation" },
  { name: "CONNECT", label: "Connect", group: "Voice" },
  { name: "SPEAK", label: "Speak", group: "Voice" },
  { name: "STREAM", label: "Share screen", group: "Voice" },
  { name: "USE_CAMERA", label: "Use camera", group: "Voice" },
  { name: "MUTE_MEMBERS", label: "Mute members", group: "Voice" },
  { name: "MOVE_MEMBERS", label: "Move members", group: "Voice" },
  { name: "USE_SOUNDBOARD", label: "Use soundboard", group: "Voice" },
  { name: "PRIORITY_SPEAKER", label: "Priority speaker", group: "Voice" },
  { name: "READ_HISTORY", label: "Read history from before joining", group: "Text" },
  { name: "USE_EXTERNAL_EMOJIS", label: "Use external emojis", group: "General" },
  { name: "USE_EXTERNAL_SOUNDS", label: "Use external sounds", group: "Voice" },
  { name: "USE_WHITEBOARD", label: "Use the whiteboard", group: "Voice" },
  { name: "MANAGE_WHITEBOARD", label: "Manage whiteboards", group: "Moderation" },
  { name: "CHANGE_NICKNAME", label: "Change own nickname", group: "General" },
  { name: "CREATE_INVITES", label: "Create invites", group: "General" },
  { name: "MANAGE_CHANNELS", label: "Manage channels", group: "Management" },
  { name: "MANAGE_ROLES", label: "Manage roles", group: "Management" },
  { name: "MANAGE_EMOJIS", label: "Manage emojis", group: "Management" },
  { name: "MANAGE_WEBHOOKS", label: "Manage webhooks", group: "Management" },
  { name: "MANAGE_FILES", label: "Manage files", group: "Management" },
  { name: "MANAGE_APPLICATIONS", label: "Manage applications", group: "Management" },
  { name: "MANAGE_ROOM", label: "Manage room", group: "Management" },
  { name: "ADMINISTRATOR", label: "Administrator", group: "Management" },
];

export function parsePermissions(s: string | bigint | undefined | null): bigint {
  if (typeof s === "bigint") return s;
  if (!s) return 0n;
  try {
    return BigInt(s);
  } catch {
    return 0n;
  }
}

export function hasPermission(perms: bigint, needed: bigint): boolean {
  return (perms & needed) === needed;
}

export interface OverrideInput {
  subject_type: "role" | "member";
  subject_id: string;
  allow: bigint | string | number;
  deny: bigint | string | number;
}

export interface PermissionInput {
  user_id: string;
  is_owner: boolean;
  everyone_role_id: string;
  everyone_permissions: bigint | string | number;
  member_roles: [string, bigint | string | number][];
  category_overrides: OverrideInput[];
  channel_overrides: OverrideInput[];
  sync_with_category: boolean;
  timed_out: boolean;
  /** Account kind; every kind except `user` gets the bot branch (APPLICATIONS.md §2.4). Default `user`. */
  kind?: string;
  /** Effective "no bots" flag of the channel (room ∨ category ∨ channel, APPLICATIONS.md §3.5). */
  no_bots?: boolean;
  /** Effective scopes of the bot's token; absent or null = all scopes. */
  scopes?: string[] | null;
  /** The channel is a system channel (welcome channel): {@link SYSTEM_CHANNEL_FORCED} added, {@link SYSTEM_CHANNEL_DENIED} removed. */
  system_channel?: boolean;
}

const big = (v: bigint | string | number): bigint => (typeof v === "bigint" ? v : BigInt(v));

/** Permission bits a bot keeps whatever the scopes of its token. */
export const BOT_ALWAYS: bigint = Permission.VIEW_CHANNEL | Permission.CHANGE_NICKNAME;

/** App token scopes and the permission bits each unlocks (APPLICATIONS.md §2.4), in canonical order. */
export const SCOPES: readonly (readonly [string, bigint])[] = [
  ["messages:read", Permission.READ_HISTORY],
  ["messages:write", Permission.SEND_MESSAGES | Permission.ATTACH_FILES | Permission.ADD_REACTIONS | Permission.MENTION_EVERYONE | Permission.CREATE_THREADS | Permission.PIN_MESSAGES | Permission.USE_EXTERNAL_EMOJIS],
  ["members:read", 0n],
  [
    "moderation",
    Permission.MANAGE_MESSAGES |
      Permission.KICK_MEMBERS |
      Permission.BAN_MEMBERS |
      Permission.MODERATE_MEMBERS |
      Permission.PURGE |
      Permission.VIEW_AUDIT_LOG |
      Permission.MANAGE_NICKNAMES |
      Permission.MUTE_MEMBERS |
      Permission.MOVE_MEMBERS |
      Permission.MANAGE_THREADS,
  ],
  ["rooms:manage", Permission.MANAGE_ROOM | Permission.MANAGE_CHANNELS | Permission.MANAGE_ROLES | Permission.CREATE_INVITES | Permission.MANAGE_EMOJIS | Permission.MANAGE_FILES | Permission.MANAGE_APPLICATIONS],
  ["voice", Permission.CONNECT | Permission.SPEAK | Permission.STREAM | Permission.USE_CAMERA | Permission.USE_SOUNDBOARD | Permission.USE_EXTERNAL_SOUNDS | Permission.PRIORITY_SPEAKER],
  ["whiteboard", Permission.USE_WHITEBOARD | Permission.MANAGE_WHITEBOARD],
  ["commands", 0n],
  ["webhooks:manage", Permission.MANAGE_WEBHOOKS],
  ["presence", 0n],
  ["dms", 0n],
] as const;

/** All scope names in canonical order. */
export const SCOPE_NAMES: string[] = SCOPES.map(([name]) => name);

/** `BOT_ALWAYS ∪ ⋃ bits(scope)`; unknown scope strings add nothing, `administrator` is never included. */
export function scopeMask(scopes: readonly string[]): bigint {
  let mask = BOT_ALWAYS;
  for (const s of scopes) {
    const entry = SCOPES.find(([name]) => name === s);
    if (entry) mask |= entry[1];
  }
  return mask;
}

/** Every kind except `user` is evaluated like a bot (fails closed for unknown kinds). */
export function isBotKind(kind: string | undefined | null): boolean {
  return (kind ?? "user") !== "user";
}

/** The bot branch: 0 in a "no bots" zone, otherwise capped by the scope mask (null scopes = all scopes). */
export function capBot(perms: bigint, kind: string | undefined | null, noBots: boolean, scopes: readonly string[] | null | undefined): bigint {
  if (!isBotKind(kind)) return perms;
  if (noBots) return 0n;
  return perms & scopeMask(scopes ?? SCOPE_NAMES);
}

/** Values of the room setting `bots_in_encrypted_channels` (APPLICATIONS.md §3.5). */
export const BOTS_IN_ENCRYPTED_CHANNELS = ["per_channel", "allowed"] as const;
export type BotsInEncryptedChannels = (typeof BOTS_IN_ENCRYPTED_CHANNELS)[number];

/** What the effective "no bots" flag of a channel depends on (APPLICATIONS.md §3.5). */
export interface NoBotsInput {
  room_no_bots?: boolean;
  category_no_bots?: boolean;
  channel_no_bots?: boolean;
  /** The channel is end-to-end encrypted. */
  encrypted?: boolean;
  /** The channel setting `bots_allowed`. */
  bots_allowed?: boolean;
  /** The room setting; anything but `allowed` counts as `per_channel` (fail closed). */
  bots_in_encrypted_channels?: string | null;
}

/**
 * The effective "no bots" flag of a channel, identical to `permissions::no_bots_effective` of the node (shared vectors
 * `protocol/testvectors/no_bots.json`): room ∨ category ∨ channel flag, and in a `per_channel` room every encrypted
 * channel without `bots_allowed`. Clients use it for the ghost rule (ENCRYPTION.md §4.6) together with the node's
 * `no_bots_effective`, so a node that reports a channel as open to bots cannot hide a bot leaf.
 */
export function noBotsEffective(input: NoBotsInput): boolean {
  return !!(input.room_no_bots || input.category_no_bots || input.channel_no_bots || (input.encrypted && !input.bots_allowed && input.bots_in_encrypted_channels !== "allowed"));
}

export function roomLevelPermissions(isOwner: boolean, everyone: bigint, memberRoles: [string, bigint][]): bigint {
  if (isOwner) return ALL_PERMISSIONS;
  const base = memberRoles.reduce((acc, [, p]) => acc | p, everyone);
  return hasPermission(base, Permission.ADMINISTRATOR) ? ALL_PERMISSIONS : base;
}

export function computePermissions(input: PermissionInput): bigint {
  let perms = computeMemberPermissions(input);
  if (input.system_channel) perms = (perms | SYSTEM_CHANNEL_FORCED) & ~SYSTEM_CHANNEL_DENIED;
  const capped = capBot(perms, input.kind, input.no_bots ?? false, input.scopes);
  return hasPermission(capped, Permission.VIEW_CHANNEL) ? capped : 0n;
}

function computeMemberPermissions(input: PermissionInput): bigint {
  if (input.is_owner) return ALL_PERMISSIONS;
  const memberRoles: [string, bigint][] = input.member_roles.map(([id, p]) => [id, big(p)]);
  const base = roomLevelPermissions(false, big(input.everyone_permissions), memberRoles);
  if (hasPermission(base, Permission.ADMINISTRATOR)) return ALL_PERMISSIONS;
  const overrides = input.sync_with_category ? input.category_overrides : input.channel_overrides;
  let perms = applyOverrides(base, overrides, input, memberRoles);
  // No override can hide a system channel: as if view_channel and read_history were never denied.
  if (input.system_channel) perms |= SYSTEM_CHANNEL_FORCED;
  if (!hasPermission(perms, Permission.VIEW_CHANNEL)) return 0n;
  if (input.timed_out) perms &= Permission.VIEW_CHANNEL | Permission.READ_HISTORY;
  return perms;
}

function applyOverrides(perms: bigint, overrides: OverrideInput[], input: PermissionInput, memberRoles: [string, bigint][]): bigint {
  const everyone = overrides.find((o) => o.subject_type === "role" && o.subject_id === input.everyone_role_id);
  if (everyone) perms = (perms & ~big(everyone.deny)) | big(everyone.allow);
  let allow = 0n;
  let deny = 0n;
  for (const o of overrides) {
    if (o.subject_type === "role" && memberRoles.some(([id]) => id === o.subject_id)) {
      allow |= big(o.allow);
      deny |= big(o.deny);
    }
  }
  perms = (perms & ~deny) | allow;
  const member = overrides.find((o) => o.subject_type === "member" && o.subject_id === input.user_id);
  if (member) perms = (perms & ~big(member.deny)) | big(member.allow);
  return perms;
}
