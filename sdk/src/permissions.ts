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
  /** Set or clear the status line of a voice channel (VOICE.md §2a), channel-scoped, grantable alone. */
  VOICE_STATUS: 1n << 38n,
  /**
   * Send polls (PROTOCOL.md §7g) together with SEND_MESSAGES. The node enforces it for plaintext polls and every
   * message with a close time; clients enforce it for encrypted polls. Channel-scoped, default of `@everyone`.
   */
  CREATE_POLLS: 1n << 39n,
  /**
   * Use the buttons, select menus and modals of applications' messages (APPLICATIONS.md §5.10). Channel-scoped,
   * default of `@everyone`, independent of SEND_MESSAGES; no app-token scope covers it (bots never click).
   */
  USE_COMPONENTS: 1n << 40n,
  WHISPER: 1n << 41n,
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
 * The bits an override (category or channel) may carry (protocol/permissions.md "Channel-scoped bits"). Room-level
 * bits are granted through roles only; the node refuses others with `permissions.not_channel_scoped`, and the
 * evaluation ignores them in overrides. Same value as `permissions::CHANNEL_SCOPED` of the node.
 */
export const CHANNEL_SCOPED: bigint = [
  Permission.VIEW_CHANNEL,
  Permission.SEND_MESSAGES,
  Permission.MANAGE_MESSAGES,
  Permission.ATTACH_FILES,
  Permission.ADD_REACTIONS,
  Permission.MENTION_EVERYONE,
  Permission.CREATE_THREADS,
  Permission.MANAGE_CHANNELS,
  Permission.MANAGE_ROLES,
  Permission.CONNECT,
  Permission.SPEAK,
  Permission.STREAM,
  Permission.MUTE_MEMBERS,
  Permission.MOVE_MEMBERS,
  Permission.USE_SOUNDBOARD,
  Permission.PIN_MESSAGES,
  Permission.USE_CAMERA,
  Permission.USE_WHITEBOARD,
  Permission.MANAGE_WHITEBOARD,
  Permission.MANAGE_WEBHOOKS,
  Permission.PRIORITY_SPEAKER,
  Permission.USE_EXTERNAL_EMOJIS,
  Permission.USE_EXTERNAL_SOUNDS,
  Permission.MANAGE_FILES,
  Permission.READ_HISTORY,
  Permission.MANAGE_THREADS,
  Permission.VOICE_STATUS,
  Permission.CREATE_POLLS,
  Permission.USE_COMPONENTS,
  Permission.WHISPER,
].reduce((a, b) => a | b, 0n);

/** Is this permission (a bit or its name) one that overrides may carry? */
export function isChannelScoped(permission: bigint | PermissionName): boolean {
  const bit = typeof permission === "bigint" ? permission : Permission[permission];
  return (CHANNEL_SCOPED & bit) === bit;
}

/** The channel-scoped bits in the groups and order of the override editors (clients localize `group`). */
export const CHANNEL_SCOPED_GROUPS: readonly { group: "general" | "text" | "voice" | "files" | "management"; permissions: readonly PermissionName[] }[] = [
  { group: "general", permissions: ["VIEW_CHANNEL", "READ_HISTORY", "ADD_REACTIONS", "USE_EXTERNAL_EMOJIS", "MENTION_EVERYONE"] },
  { group: "text", permissions: ["SEND_MESSAGES", "CREATE_THREADS", "CREATE_POLLS", "USE_COMPONENTS", "PIN_MESSAGES", "MANAGE_MESSAGES", "MANAGE_THREADS"] },
  { group: "voice", permissions: ["CONNECT", "SPEAK", "WHISPER", "STREAM", "USE_CAMERA", "USE_SOUNDBOARD", "USE_EXTERNAL_SOUNDS", "PRIORITY_SPEAKER", "VOICE_STATUS", "MUTE_MEMBERS", "MOVE_MEMBERS", "USE_WHITEBOARD", "MANAGE_WHITEBOARD"] },
  { group: "files", permissions: ["ATTACH_FILES", "MANAGE_FILES"] },
  { group: "management", permissions: ["MANAGE_CHANNELS", "MANAGE_ROLES", "MANAGE_WEBHOOKS"] },
];

/**
 * Removed from the effective permissions in system channels (the welcome channel is read-only for everyone,
 * protocol/permissions.md "System channels").
 */
export const SYSTEM_CHANNEL_DENIED: bigint =
  Permission.SEND_MESSAGES | Permission.ATTACH_FILES | Permission.CREATE_THREADS | Permission.MENTION_EVERYONE | Permission.USE_WHITEBOARD | Permission.PIN_MESSAGES | Permission.CREATE_POLLS;

/**
 * Always granted in system channels: the welcome channel is the room's security log, no override can hide it or its
 * history (protocol/permissions.md "System channels", design note 4.13 item 12).
 */
export const SYSTEM_CHANNEL_FORCED: bigint = Permission.VIEW_CHANNEL | Permission.READ_HISTORY;

/** Permissions of every member in a DM or group DM (the node's `DIRECT_PERMS`). */
export const DIRECT_PERMISSIONS: bigint =
  Permission.VIEW_CHANNEL | Permission.SEND_MESSAGES | Permission.ATTACH_FILES | Permission.ADD_REACTIONS | Permission.PIN_MESSAGES | Permission.USE_WHITEBOARD | Permission.CREATE_POLLS | Permission.USE_COMPONENTS;

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
  { name: "CREATE_POLLS", label: "Create polls", group: "Text" },
  { name: "USE_COMPONENTS", label: "Use buttons and menus of apps", group: "Text" },
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
  { name: "WHISPER", label: "Initiate whisper audio", group: "Voice" },
  { name: "VOICE_STATUS", label: "Set voice channel status", group: "Voice" },
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
  /** Overrides of the channel's category (empty without a category): the first layer on top of the roles. */
  category_overrides: OverrideInput[];
  /** The channel's own overrides: the second layer, on top of the category's. */
  channel_overrides: OverrideInput[];
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
  ["messages:write", Permission.SEND_MESSAGES | Permission.ATTACH_FILES | Permission.ADD_REACTIONS | Permission.MENTION_EVERYONE | Permission.CREATE_THREADS | Permission.PIN_MESSAGES | Permission.USE_EXTERNAL_EMOJIS | Permission.CREATE_POLLS],
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
  ["rooms:manage", Permission.MANAGE_ROOM | Permission.MANAGE_CHANNELS | Permission.MANAGE_ROLES | Permission.CREATE_INVITES | Permission.MANAGE_EMOJIS | Permission.MANAGE_FILES | Permission.MANAGE_APPLICATIONS | Permission.VOICE_STATUS],
  ["voice", Permission.CONNECT | Permission.SPEAK | Permission.STREAM | Permission.USE_CAMERA | Permission.USE_SOUNDBOARD | Permission.USE_EXTERNAL_SOUNDS | Permission.PRIORITY_SPEAKER | Permission.WHISPER],
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
  // Layered (protocol/permissions.md "Evaluation"): the category's overrides, then the channel's own on top.
  const category = applyOverrides(base, input.category_overrides, input.everyone_role_id, input.user_id, memberRoles);
  let perms = applyOverrides(category, input.channel_overrides, input.everyone_role_id, input.user_id, memberRoles);
  // No override can hide a system channel: as if view_channel and read_history were never denied.
  if (input.system_channel) perms |= SYSTEM_CHANNEL_FORCED;
  if (!hasPermission(perms, Permission.VIEW_CHANNEL)) return 0n;
  if (input.timed_out) perms &= Permission.VIEW_CHANNEL | Permission.READ_HISTORY;
  return perms;
}

/** One layer of overrides: `@everyone`, then all role overrides (denies, then allows), then the member's own. */
function applyOverrides(perms: bigint, overrides: OverrideInput[], everyoneRoleId: string, userId: string, memberRoles: [string, bigint][]): bigint {
  const apply = (p: bigint, allow: bigint, deny: bigint) => (p & ~(deny & CHANNEL_SCOPED)) | (allow & CHANNEL_SCOPED);
  const everyone = overrides.find((o) => o.subject_type === "role" && o.subject_id === everyoneRoleId);
  if (everyone) perms = apply(perms, big(everyone.allow), big(everyone.deny));
  let allow = 0n;
  let deny = 0n;
  for (const o of overrides) {
    if (o.subject_type === "role" && memberRoles.some(([id]) => id === o.subject_id)) {
      allow |= big(o.allow);
      deny |= big(o.deny);
    }
  }
  perms = apply(perms, allow, deny);
  const member = overrides.find((o) => o.subject_type === "member" && o.subject_id === userId);
  if (member) perms = apply(perms, big(member.allow), big(member.deny));
  return perms;
}

/**
 * Which layer decides a neutral bit in an override editor: `role` the role base, `category` the category's overrides
 * below the channel being edited, `everyone` the `@everyone` override of the edited layer, `roles` (member subjects)
 * the overrides of the member's roles in the edited layer.
 */
export type InheritedSource = "role" | "category" | "everyone" | "roles";

/** Whose value an override editor shows behind a neutral bit. */
export interface InheritedInput {
  everyone_role_id: string;
  everyone_permissions: bigint | string | number;
  /** The room's roles without `@everyone`: (role id, permissions). */
  roles: [string, bigint | string | number][];
  /** The override's subject: a role, or a member with the ids of their roles. */
  subject: { type: "role"; id: string } | { type: "member"; id: string; roles: string[] };
  /** `null` in the category editor (only the roles are below); in the channel editor the category's overrides. */
  category_overrides: OverrideInput[] | null;
  /** The overrides of the edited layer (the category or the channel); the subject's own override may be included, it is skipped. */
  layer_overrides: OverrideInput[];
}

/**
 * The value a bit has for an override's subject when the override leaves it neutral ("–"), and which layer decides
 * it (protocol/permissions.md "Evaluation"): the role base (`@everyone` plus the subject's role, or the member's
 * roles); in the channel editor the category's overrides on top; then, inside the edited layer, the `@everyone`
 * override (not for `@everyone` itself) and, for a member subject, the overrides of the member's roles. The subject's
 * own override is never applied. `source` names the last of these that allows or denies the bit.
 */
export function inheritedOverrideValue(input: InheritedInput, bit: bigint): { allowed: boolean; source: InheritedSource } {
  const subject = input.subject;
  const everyoneId = input.everyone_role_id;
  const roleIds = subject.type === "member" ? subject.roles : subject.id === everyoneId ? [] : [subject.id];
  const memberRoles: [string, bigint][] = input.roles.filter(([id]) => roleIds.includes(id)).map(([id, p]) => [id, big(p)]);
  const base = roomLevelPermissions(false, big(input.everyone_permissions), memberRoles);
  if (hasPermission(base, Permission.ADMINISTRATOR)) return { allowed: true, source: "role" };
  const userId = subject.type === "member" ? subject.id : "";
  const touches = (o: OverrideInput) => ((big(o.allow) | big(o.deny)) & bit & CHANNEL_SCOPED) !== 0n;
  let source: InheritedSource = "role";
  // The category below the edited channel: every override that applies to the subject.
  const below = input.category_overrides ?? [];
  const applies = (o: OverrideInput) => (o.subject_type === "role" ? o.subject_id === everyoneId || roleIds.includes(o.subject_id) : o.subject_id === userId);
  if (below.some((o) => applies(o) && touches(o))) source = "category";
  let perms = applyOverrides(base, below, everyoneId, userId, memberRoles);
  // The edited layer: role overrides only (a member's own override is the one being edited), never the subject's own.
  const layer = input.layer_overrides.filter((o) => o.subject_type === "role" && !(subject.type === "role" && o.subject_id === subject.id));
  if (layer.some((o) => o.subject_id === everyoneId && touches(o))) source = "everyone";
  if (layer.some((o) => o.subject_id !== everyoneId && roleIds.includes(o.subject_id) && touches(o))) source = "roles";
  perms = applyOverrides(perms, layer, everyoneId, "", memberRoles);
  return { allowed: hasPermission(perms, bit), source };
}
