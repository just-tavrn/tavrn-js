// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ALL_PERMISSIONS,
  BOT_ALWAYS,
  CHANNEL_SCOPED,
  CHANNEL_SCOPED_GROUPS,
  EVERYONE_RESTRICTED,
  Permission,
  SCOPE_NAMES,
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
  type NoBotsInput,
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
    expect(EVERYONE_RESTRICTED.toString()).toBe("4611686130924452740");
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

describe("bot inputs (APPLICATIONS.md §2.4)", () => {
  it("scope masks never contain administrator and cover every other bit", () => {
    expect(scopeMask([])).toBe(BOT_ALWAYS);
    expect(scopeMask(["nonsense"])).toBe(BOT_ALWAYS);
    const all = scopeMask(SCOPE_NAMES);
    expect(hasPermission(all, Permission.ADMINISTRATOR)).toBe(false);
    expect(all | Permission.ADMINISTRATOR).toBe(ALL_PERMISSIONS);
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
    expect(CHANNEL_SCOPED.toString()).toBe("103049789951");
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
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r0" }, category_overrides: null }, Permission.SEND_MESSAGES)).toEqual({ allowed: true, source: "role" });
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r1" }, category_overrides: null }, Permission.ATTACH_FILES)).toEqual({ allowed: true, source: "role" });
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r0" }, category_overrides: null }, Permission.ATTACH_FILES)).toEqual({ allowed: false, source: "role" });
  });

  it("in the channel editor a category override that touches the bit decides", () => {
    const category_overrides = [
      { subject_type: "role" as const, subject_id: "r0", allow: 0n, deny: Permission.SEND_MESSAGES },
      { subject_type: "role" as const, subject_id: "r1", allow: Permission.SEND_MESSAGES, deny: 0n },
    ];
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r0" }, category_overrides }, Permission.SEND_MESSAGES)).toEqual({ allowed: false, source: "category" });
    // A role sees @everyone's category override underneath its own.
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r1" }, category_overrides }, Permission.SEND_MESSAGES)).toEqual({ allowed: true, source: "category" });
    expect(inheritedOverrideValue({ ...base, subject: { type: "role", id: "r0" }, category_overrides }, Permission.VIEW_CHANNEL)).toEqual({ allowed: true, source: "role" });
  });

  it("a member subject inherits from @everyone and the member's roles", () => {
    const category_overrides = [{ subject_type: "member" as const, subject_id: "u1", allow: 0n, deny: Permission.VIEW_CHANNEL }];
    expect(inheritedOverrideValue({ ...base, subject: { type: "member", id: "u1", roles: ["r1"] }, category_overrides }, Permission.VIEW_CHANNEL)).toEqual({ allowed: false, source: "category" });
    expect(inheritedOverrideValue({ ...base, subject: { type: "member", id: "u1", roles: ["r1"] }, category_overrides: [] }, Permission.ATTACH_FILES)).toEqual({ allowed: true, source: "role" });
  });

  it("administrator on the role base means allowed", () => {
    const admin = { ...base, roles: [["r1", Permission.ADMINISTRATOR]] as [string, bigint][] };
    expect(inheritedOverrideValue({ ...admin, subject: { type: "role", id: "r1" }, category_overrides: [{ subject_type: "role", subject_id: "r1", allow: 0n, deny: Permission.SEND_MESSAGES }] }, Permission.SEND_MESSAGES)).toEqual({ allowed: true, source: "role" });
  });
});
