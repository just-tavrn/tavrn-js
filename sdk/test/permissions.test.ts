// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ALL_PERMISSIONS,
  BOT_ALWAYS,
  CHANNEL_SCOPED,
  CHANNEL_SCOPED_GROUPS,
  DIRECT_PERMISSIONS,
  EVERYONE_RESTRICTED,
  PERMISSION_LABELS,
  Permission,
  SCOPE_NAMES,
  SYSTEM_CHANNEL_DENIED,
  capBot,
  computePermissions,
  hasPermission,
  inheritedOverrideValue,
  isBotKind,
  isChannelScoped,
  isEveryoneRestricted,
  noBotsEffective,
  parsePermissions,
  scopeMask,
  type InheritedInput,
  type NoBotsInput,
  type OverrideInput,
  type PermissionInput,
} from "../src/permissions";

interface Vector {
  name: string;
  input: PermissionInput;
  expected: string;
}

describe("computePermissions", () => {
  const vectors = JSON.parse(readFileSync(new URL("../../protocol/testvectors/permissions.json", import.meta.url), "utf8")) as Vector[];

  it.each(vectors.map((v) => [v.name, v] as const))("protocol test vector: %s", (_, v) => {
    expect(computePermissions(v.input).toString()).toBe(v.expected);
  });

  it("defines whisper initiation independently in Voice channel/category overrides", () => {
    expect(Permission.WHISPER).toBe(1n << 41n);
    expect(CHANNEL_SCOPED & Permission.WHISPER).toBe(Permission.WHISPER);
    expect(EVERYONE_RESTRICTED & Permission.WHISPER).toBe(0n);
    expect(CHANNEL_SCOPED_GROUPS.find(g => g.group === "voice")?.permissions).toContain("WHISPER");
    expect(PERMISSION_LABELS.find(p => p.name === "WHISPER")?.group).toBe("Voice");
  });

  it("ALL contains every permission and fits in i64", () => {
    for (const bit of Object.values(Permission)) expect(hasPermission(ALL_PERMISSIONS, bit)).toBe(true);
    expect(ALL_PERMISSIONS < 1n << 63n).toBe(true);
    expect(parsePermissions("nope")).toBe(0n);
    expect(parsePermissions(ALL_PERMISSIONS.toString())).toBe(ALL_PERMISSIONS);
  });

  it("@everyone restrictions match the node (server/src/permissions.rs EVERYONE_RESTRICTED)", () => {
    // Same bits as the Rust constant: administrator, room/role/channel management, audit log, kick, ban,
    // timeout, emojis, whiteboard management, webhooks, files, move, mute, manage messages, manage nicknames,
    // applications, purge.
    expect(EVERYONE_RESTRICTED.toString()).toBe("4611686268363406212");
    expect(isEveryoneRestricted("MANAGE_APPLICATIONS")).toBe(true);
    expect(isEveryoneRestricted("ADMINISTRATOR")).toBe(true);
    expect(isEveryoneRestricted("MANAGE_WHITEBOARD")).toBe(true);
    expect(isEveryoneRestricted("MANAGE_WEBHOOKS")).toBe(true);
    expect(isEveryoneRestricted("USE_WHITEBOARD")).toBe(false);
    expect(isEveryoneRestricted("SEND_MESSAGES")).toBe(false);
  });
});

describe("noBotsEffective (APPLICATIONS.md §3.5)", () => {
  const vectors = JSON.parse(readFileSync(new URL("../../protocol/testvectors/no_bots.json", import.meta.url), "utf8")) as { name: string; input: NoBotsInput; expected: boolean }[];

  it.each(vectors.map((v) => [v.name, v] as const))("protocol test vector: %s", (_, v) => {
    expect(noBotsEffective(v.input)).toBe(v.expected);
  });
});

describe("manage_applications (bit 35)", () => {
  it("is a management bit covered by the rooms:manage scope only", () => {
    expect(Permission.MANAGE_APPLICATIONS).toBe(1n << 35n);
    expect(hasPermission(scopeMask(["rooms:manage"]), Permission.MANAGE_APPLICATIONS)).toBe(true);
    expect(hasPermission(scopeMask(["moderation", "commands", "messages:write"]), Permission.MANAGE_APPLICATIONS)).toBe(false);
  });
});

describe("voice_status (bit 38)", () => {
  it("is channel-scoped, grantable to @everyone and covered by rooms:manage", () => {
    expect(Permission.VOICE_STATUS).toBe(1n << 38n);
    expect(isChannelScoped("VOICE_STATUS")).toBe(true);
    expect(isEveryoneRestricted("VOICE_STATUS")).toBe(false);
    expect(hasPermission(scopeMask(["rooms:manage"]), Permission.VOICE_STATUS)).toBe(true);
    expect(hasPermission(scopeMask(["voice", "moderation"]), Permission.VOICE_STATUS)).toBe(false);
    expect(CHANNEL_SCOPED_GROUPS.find((g) => g.group === "voice")!.permissions).toContain("VOICE_STATUS");
    expect(PERMISSION_LABELS.find((p) => p.name === "VOICE_STATUS")?.group).toBe("Voice");
  });
});

describe("create_polls (bit 39)", () => {
  it("is channel-scoped, grantable to @everyone, in DMs, covered by messages:write and denied in system channels", () => {
    expect(Permission.CREATE_POLLS).toBe(1n << 39n);
    expect(isChannelScoped("CREATE_POLLS")).toBe(true);
    expect(isEveryoneRestricted("CREATE_POLLS")).toBe(false);
    expect(hasPermission(scopeMask(["messages:write"]), Permission.CREATE_POLLS)).toBe(true);
    expect(hasPermission(scopeMask(["messages:read", "rooms:manage"]), Permission.CREATE_POLLS)).toBe(false);
    expect(hasPermission(DIRECT_PERMISSIONS, Permission.CREATE_POLLS)).toBe(true);
    expect(hasPermission(SYSTEM_CHANNEL_DENIED, Permission.CREATE_POLLS)).toBe(true);
    expect(CHANNEL_SCOPED_GROUPS.find((g) => g.group === "text")!.permissions).toContain("CREATE_POLLS");
    expect(PERMISSION_LABELS.find((p) => p.name === "CREATE_POLLS")?.group).toBe("Text");
  });
});

describe("use_components (bit 40)", () => {
  it("is channel-scoped, grantable to @everyone, in DMs, covered by no scope and allowed in system channels", () => {
    expect(Permission.USE_COMPONENTS).toBe(1n << 40n);
    expect(isChannelScoped("USE_COMPONENTS")).toBe(true);
    expect(CHANNEL_SCOPED).toBe(4226218394111n);
    expect(isEveryoneRestricted("USE_COMPONENTS")).toBe(false);
    expect(hasPermission(scopeMask(SCOPE_NAMES), Permission.USE_COMPONENTS)).toBe(false);
    expect(hasPermission(DIRECT_PERMISSIONS, Permission.USE_COMPONENTS)).toBe(true);
    expect(hasPermission(SYSTEM_CHANNEL_DENIED, Permission.USE_COMPONENTS)).toBe(false);
    expect(CHANNEL_SCOPED_GROUPS.find((g) => g.group === "text")!.permissions).toContain("USE_COMPONENTS");
    expect(PERMISSION_LABELS.find((p) => p.name === "USE_COMPONENTS")?.group).toBe("Text");
  });
});

describe("bot inputs (APPLICATIONS.md §2.4)", () => {
  it("scope masks never contain administrator, restore_history or use_components and cover every other bit", () => {
    expect(scopeMask([])).toBe(BOT_ALWAYS);
    expect(scopeMask(["nonsense"])).toBe(BOT_ALWAYS);
    const all = scopeMask(SCOPE_NAMES);
    expect(hasPermission(all, Permission.ADMINISTRATOR)).toBe(false);
    expect(hasPermission(all, Permission.RESTORE_HISTORY)).toBe(false);
    expect(hasPermission(all, Permission.USE_COMPONENTS)).toBe(false);
    expect(all | Permission.ADMINISTRATOR | Permission.RESTORE_HISTORY | Permission.USE_COMPONENTS).toBe(ALL_PERMISSIONS);
  });

  it("caps bots only and fails closed for unknown kinds", () => {
    expect(capBot(ALL_PERMISSIONS, "user", true, [])).toBe(ALL_PERMISSIONS);
    expect(capBot(ALL_PERMISSIONS, undefined, true, [])).toBe(ALL_PERMISSIONS);
    expect(capBot(ALL_PERMISSIONS, "bot", true, null)).toBe(0n);
    expect(capBot(ALL_PERMISSIONS, "webhook", false, [])).toBe(BOT_ALWAYS);
    expect(isBotKind("something-new")).toBe(true);
  });
});

describe("EVERYONE_RESTRICTED", () => {
  it("lists exactly the management-class bits of protocol/permissions.md", () => {
    const doc = readFileSync(new URL("../../protocol/permissions.md", import.meta.url), "utf8");
    const section = doc.split("## Restricted for @everyone")[1]!.split("## ")[0]!;
    const bits = [...section.matchAll(/^\| (\d+) \| `/gm)].map((m) => BigInt(m[1]!));
    const fromDoc = bits.reduce((acc, b) => acc | (1n << b), 0n);
    expect(fromDoc).toBe(EVERYONE_RESTRICTED);
  });

  it("keeps the everyday bits grantable", () => {
    for (const bit of [Permission.VIEW_CHANNEL, Permission.SEND_MESSAGES, Permission.CONNECT, Permission.SPEAK, Permission.CREATE_INVITES, Permission.ADD_REACTIONS]) expect(isEveryoneRestricted(bit)).toBe(false);
    for (const bit of [Permission.ADMINISTRATOR, Permission.MANAGE_ROLES, Permission.BAN_MEMBERS, Permission.MOVE_MEMBERS]) expect(isEveryoneRestricted(bit)).toBe(true);
  });
});

describe("CHANNEL_SCOPED (layered overrides)", () => {
  it("lists exactly the channel-scoped bits of protocol/permissions.md and matches the node", () => {
    const doc = readFileSync(new URL("../../protocol/permissions.md", import.meta.url), "utf8");
    const section = doc.split("## Channel-scoped bits")[1]!.split("\n## ")[0]!;
    const bits = [...section.matchAll(/^\| (\d+) \| `/gm)].map((m) => BigInt(m[1]!));
    expect(bits.reduce((acc, b) => acc | (1n << b), 0n)).toBe(CHANNEL_SCOPED);
    // Same value as permissions::CHANNEL_SCOPED of the node.
    expect(CHANNEL_SCOPED.toString()).toBe("4226218394111");
    expect(isChannelScoped("VIEW_CHANNEL")).toBe(true);
    expect(isChannelScoped("MANAGE_ROLES")).toBe(true);
    for (const room of ["ADMINISTRATOR", "MANAGE_ROOM", "KICK_MEMBERS", "PURGE", "CHANGE_NICKNAME", "MANAGE_APPLICATIONS"] as const) expect(isChannelScoped(room)).toBe(false);
  });

  it("the editor groups cover every scoped bit exactly once", () => {
    const names = CHANNEL_SCOPED_GROUPS.flatMap((g) => g.permissions);
    expect(new Set(names).size).toBe(names.length);
    expect(names.reduce((acc, n) => acc | Permission[n], 0n)).toBe(CHANNEL_SCOPED);
    expect(CHANNEL_SCOPED_GROUPS.map((g) => g.group)).toEqual(["general", "text", "voice", "files", "management"]);
  });

  it("ignores room-level bits inside overrides", () => {
    const input: PermissionInput = {
      user_id: "u1", is_owner: false, everyone_role_id: "r0", everyone_permissions: Permission.VIEW_CHANNEL,
      member_roles: [], timed_out: false, category_overrides: [],
      channel_overrides: [{ subject_type: "role", subject_id: "r0", allow: Permission.KICK_MEMBERS | Permission.SEND_MESSAGES, deny: 0n }],
    };
    expect(computePermissions(input)).toBe(Permission.VIEW_CHANNEL | Permission.SEND_MESSAGES);
  });
});

describe("inheritedOverrideValue (what a neutral override shows in the editors)", () => {
  const base = { everyone_role_id: "r0", everyone_permissions: Permission.VIEW_CHANNEL | Permission.SEND_MESSAGES, roles: [["r1", Permission.ATTACH_FILES]] as [string, bigint][] };

  it("in the category editor the role base decides", () => {
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r0" }, category_overrides: null, layer_overrides: [] }, Permission.SEND_MESSAGES)).toEqual({ allowed: true, source: "role" });
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r1" }, category_overrides: null, layer_overrides: [] }, Permission.ATTACH_FILES)).toEqual({ allowed: true, source: "role" });
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r0" }, category_overrides: null, layer_overrides: [] }, Permission.ATTACH_FILES)).toEqual({ allowed: false, source: "role" });
  });

  it("in the channel editor a category override that touches the bit decides", () => {
    const category_overrides = [
      { subject_type: "role" as const, subject_id: "r0", allow: 0n, deny: Permission.SEND_MESSAGES },
      { subject_type: "role" as const, subject_id: "r1", allow: Permission.SEND_MESSAGES, deny: 0n },
    ];
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r0" }, category_overrides, layer_overrides: [] }, Permission.SEND_MESSAGES)).toEqual({ allowed: false, source: "category" });
    // A role sees @everyone's category override underneath its own.
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r1" }, category_overrides, layer_overrides: [] }, Permission.SEND_MESSAGES)).toEqual({ allowed: true, source: "category" });
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r0" }, category_overrides, layer_overrides: [] }, Permission.VIEW_CHANNEL)).toEqual({ allowed: true, source: "role" });
  });

  it("a member subject inherits from @everyone and the member's roles", () => {
    const category_overrides = [{ subject_type: "member" as const, subject_id: "u1", allow: 0n, deny: Permission.VIEW_CHANNEL }];
    expect(inheritedOverrideValue({ ...base, subject: { type: "member", id: "u1", roles: ["r1"] }, category_overrides, layer_overrides: [] }, Permission.VIEW_CHANNEL)).toEqual({ allowed: false, source: "category" });
    expect(inheritedOverrideValue({ ...base, subject: { type: "member", id: "u1", roles: ["r1"] }, category_overrides: [], layer_overrides: [] }, Permission.ATTACH_FILES)).toEqual({ allowed: true, source: "role" });
  });

  it("administrator on the role base means allowed", () => {
    const admin = { ...base, roles: [["r1", Permission.ADMINISTRATOR]] as [string, bigint][] };
    expect(inheritedOverrideValue({ ...admin, subject: { type: "role", id: "r1" }, category_overrides: [{ subject_type: "role", subject_id: "r1", allow: 0n, deny: Permission.SEND_MESSAGES }], layer_overrides: [] }, Permission.SEND_MESSAGES)).toEqual({ allowed: true, source: "role" });
  });

  const role = (subject_id: string, allow: bigint, deny: bigint): OverrideInput => ({ subject_type: "role", subject_id, allow, deny });
  const member = (subject_id: string, allow: bigint, deny: bigint): OverrideInput => ({ subject_type: "member", subject_id, allow, deny });

  it("the edited layer's @everyone override decides for a neutral role (category editor)", () => {
    // Owner's case: the category denies view_channel to @everyone, the Moderator's override is neutral.
    const mods = { ...base, roles: [["mod", 0n]] as [string, bigint][] };
    const layer_overrides = [role("r0", 0n, Permission.VIEW_CHANNEL), role("mod", 0n, 0n)];
    const input: InheritedInput = { ...mods, subject: { type: "role", id: "mod" }, category_overrides: null, layer_overrides };
    expect(inheritedOverrideValue(input, Permission.VIEW_CHANNEL)).toEqual({ allowed: false, source: "everyone" });
    // The hint agrees with the evaluation of a member who has only that role.
    const evaluated = computePermissions({ user_id: "u1", is_owner: false, everyone_role_id: "r0", everyone_permissions: mods.everyone_permissions, member_roles: [["mod", 0n]], category_overrides: layer_overrides, channel_overrides: [] });
    expect(hasPermission(evaluated, Permission.VIEW_CHANNEL)).toBe(false);
    // A bit the @everyone override leaves alone still comes from the role base.
    expect(inheritedOverrideValue(input, Permission.SEND_MESSAGES)).toEqual({ allowed: true, source: "role" });
  });

  it("the edited layer's @everyone override decides in the channel editor too, on top of the category", () => {
    const category_overrides = [role("r0", 0n, Permission.SEND_MESSAGES)];
    const layer_overrides = [role("r0", Permission.SEND_MESSAGES, Permission.VIEW_CHANNEL)];
    const input: InheritedInput = { ...base, subject: { type: "role", id: "r1" }, category_overrides, layer_overrides };
    expect(inheritedOverrideValue(input, Permission.VIEW_CHANNEL)).toEqual({ allowed: false, source: "everyone" });
    // The channel's @everyone allow overrules the category's deny: the last layer that touches the bit names it.
    expect(inheritedOverrideValue(input, Permission.SEND_MESSAGES)).toEqual({ allowed: true, source: "everyone" });
    // Without a channel override the category still decides.
    expect(inheritedOverrideValue({ ...input, layer_overrides: [] }, Permission.SEND_MESSAGES)).toEqual({ allowed: false, source: "category" });
  });

  it("@everyone as the subject skips its own override of the edited layer", () => {
    const layer_overrides = [role("r0", 0n, Permission.VIEW_CHANNEL), role("r1", Permission.ATTACH_FILES, 0n)];
    const input: InheritedInput = { ...base, subject: { type: "role", id: "r0" }, category_overrides: null, layer_overrides };
    expect(inheritedOverrideValue(input, Permission.VIEW_CHANNEL)).toEqual({ allowed: true, source: "role" });
    // Another role's override does not apply to @everyone.
    expect(inheritedOverrideValue(input, Permission.ATTACH_FILES)).toEqual({ allowed: false, source: "role" });
  });

  it("the subject's own override is ignored (the hint is what a neutral bit gives)", () => {
    const layer_overrides = [role("r1", Permission.VIEW_CHANNEL, Permission.SEND_MESSAGES), member("u1", 0n, Permission.ATTACH_FILES)];
    const asRole: InheritedInput = { ...base, subject: { type: "role", id: "r1" }, category_overrides: null, layer_overrides };
    expect(inheritedOverrideValue(asRole, Permission.SEND_MESSAGES)).toEqual({ allowed: true, source: "role" });
    const asMember: InheritedInput = { ...base, subject: { type: "member", id: "u1", roles: ["r1"] }, category_overrides: null, layer_overrides: [member("u1", 0n, Permission.ATTACH_FILES)] };
    expect(inheritedOverrideValue(asMember, Permission.ATTACH_FILES)).toEqual({ allowed: true, source: "role" });
    // Another member's override in the layer does not apply either.
    expect(inheritedOverrideValue({ ...asMember, layer_overrides: [member("u2", 0n, Permission.ATTACH_FILES)] }, Permission.ATTACH_FILES)).toEqual({ allowed: true, source: "role" });
  });

  it("a member subject gets the role base of their roles, then @everyone and their roles' overrides of the layer", () => {
    const roles = [["r1", Permission.ATTACH_FILES], ["r2", Permission.CREATE_POLLS], ["r3", 0n]] as [string, bigint][];
    const subject = { type: "member" as const, id: "u1", roles: ["r1", "r2"] };
    const plain: InheritedInput = { ...base, roles, subject, category_overrides: null, layer_overrides: [] };
    expect(inheritedOverrideValue(plain, Permission.ATTACH_FILES)).toEqual({ allowed: true, source: "role" });
    expect(inheritedOverrideValue(plain, Permission.CREATE_POLLS)).toEqual({ allowed: true, source: "role" });
    const layer_overrides = [
      role("r0", 0n, Permission.VIEW_CHANNEL | Permission.SEND_MESSAGES),
      role("r1", Permission.VIEW_CHANNEL, 0n),
      role("r2", 0n, Permission.ATTACH_FILES),
      role("r3", Permission.SEND_MESSAGES, 0n),
    ];
    const layered: InheritedInput = { ...plain, layer_overrides };
    // @everyone denies view_channel, the member's role r1 allows it again.
    expect(inheritedOverrideValue(layered, Permission.VIEW_CHANNEL)).toEqual({ allowed: true, source: "roles" });
    // A role override of the member flips a bit of the role base.
    expect(inheritedOverrideValue(layered, Permission.ATTACH_FILES)).toEqual({ allowed: false, source: "roles" });
    // r3 is not one of the member's roles: @everyone's deny stays.
    expect(inheritedOverrideValue(layered, Permission.SEND_MESSAGES)).toEqual({ allowed: false, source: "everyone" });
    // The same as the evaluation of that member.
    const evaluated = computePermissions({ user_id: "u1", is_owner: false, everyone_role_id: "r0", everyone_permissions: base.everyone_permissions, member_roles: [["r1", Permission.ATTACH_FILES], ["r2", Permission.CREATE_POLLS]], category_overrides: layer_overrides, channel_overrides: [] });
    expect(hasPermission(evaluated, Permission.ATTACH_FILES)).toBe(false);
    expect(hasPermission(evaluated, Permission.SEND_MESSAGES)).toBe(false);
  });

  it("administrator on the role base stays allowed whatever the edited layer says", () => {
    const admin = { ...base, roles: [["r1", Permission.ADMINISTRATOR]] as [string, bigint][] };
    const layer_overrides = [role("r0", 0n, Permission.VIEW_CHANNEL)];
    expect(inheritedOverrideValue({ ...admin, subject: { type: "role", id: "r1" }, category_overrides: null, layer_overrides }, Permission.VIEW_CHANNEL)).toEqual({ allowed: true, source: "role" });
    expect(inheritedOverrideValue({ ...admin, subject: { type: "member", id: "u1", roles: ["r1"] }, category_overrides: null, layer_overrides }, Permission.VIEW_CHANNEL)).toEqual({ allowed: true, source: "role" });
  });
});

describe("the permission lists the clients render are complete", () => {
  const names = Object.keys(Permission) as (keyof typeof Permission)[];

  it("every permission bit has a label (the role editor lists PERMISSION_LABELS)", () => {
    const labelled = new Set(PERMISSION_LABELS.map((p) => p.name));
    expect(names.filter((n) => !labelled.has(n))).toEqual([]);
    expect(PERMISSION_LABELS.filter((p) => !(p.name in Permission)).map((p) => p.name)).toEqual([]);
  });

  it("every channel-scoped bit is in a channel group and vice versa (the channel override editor lists CHANNEL_SCOPED_GROUPS)", () => {
    const grouped = new Set(CHANNEL_SCOPED_GROUPS.flatMap((g) => g.permissions));
    const scoped = names.filter((n) => (CHANNEL_SCOPED & Permission[n]) !== 0n);
    expect(scoped.filter((n) => !grouped.has(n))).toEqual([]);
    expect([...grouped].filter((n) => (CHANNEL_SCOPED & Permission[n]) === 0n)).toEqual([]);
  });
});
