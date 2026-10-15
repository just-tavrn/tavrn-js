// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { activityRequest, checkContent, presenceRequest, uploadCategory } from "../src";

const vectors = JSON.parse(readFileSync(new URL("../../protocol/testvectors/upload_categories.json", import.meta.url), "utf8")) as {
  cases: { name: string; file_name: string; mime: string; head_hex: string | null; category: string; executable: boolean }[];
};

describe("content checks (PROTOCOL.md §7, APPLICATIONS.md §6.4)", () => {
  it("accepts text, actions, embeds and other types, refuses reserved ones and over-long bodies", () => {
    checkContent({ type: "text", body: "hi" });
    checkContent({ type: "action", body: "waves" });
    checkContent({ type: "text", body: "", embeds: [{ description: "Done", footer: "ci" }] });
    checkContent({ type: "poll", question: "?" });
    expect(() => checkContent({ type: "text", body: "x".repeat(4001) })).toThrow(RangeError);
    expect(() => checkContent({ type: "text", body: "  " })).toThrow(RangeError);
    expect(() => checkContent({ type: "text", body: "", embeds: Array(11).fill({ title: "t" }) })).toThrow(expect.objectContaining({ code: "message.embeds_invalid" }));
    expect(() => checkContent({ type: "action", body: "x", embeds: [{ title: "t" }] })).toThrow(/only text/);
    expect(() => checkContent({ type: "system.pin" })).toThrow(/reserved/);
    expect(() => checkContent({ type: "poll.vote" })).toThrow(/reserved/);
    expect(() => checkContent({ body: "x" })).toThrow(TypeError);
  });
});

describe("presence (PROTOCOL.md §6a)", () => {
  const now = Date.parse("2026-10-15T10:00:00Z");
  it("builds the request and checks status, custom status and expiry", () => {
    expect(presenceRequest({ status: "online" })).toEqual({ status: "online" });
    expect(presenceRequest({ customStatus: null })).toEqual({ custom_status: null });
    expect(presenceRequest({ customStatus: { emoji: "🚀", expiresAt: new Date(now + 3600_000) } }, now)).toEqual({ custom_status: { text: "", emoji: "🚀", expires_at: "2026-10-15T11:00:00.000Z" } });
    expect(() => presenceRequest({})).toThrow(RangeError);
    expect(() => presenceRequest({ customStatus: { text: "x", expiresAt: new Date(now - 1) } }, now)).toThrow(RangeError);
    expect(() => presenceRequest({ customStatus: { text: "x", expiresAt: new Date(now + 31 * 86400_000) } }, now)).toThrow(RangeError);
    expect(() => presenceRequest({ customStatus: { text: "a\u0007b" } })).toThrow(/control/);
  });

  it("builds activities within the limits", () => {
    expect(activityRequest({ type: "playing", name: " Chess ", state: "Move 12", startedAt: new Date(now - 1000), endsAt: new Date(now + 600_000) }, now)).toEqual({
      type: "playing",
      name: "Chess",
      state: "Move 12",
      started_at: new Date(now - 1000).toISOString(),
      ends_at: new Date(now + 600_000).toISOString(),
    });
    expect(() => activityRequest({ type: "playing", name: "x", startedAt: new Date(now + 3600_000) }, now)).toThrow(RangeError);
    expect(() => activityRequest({ type: "playing", name: "x", endsAt: new Date(now + 8 * 86400_000) }, now)).toThrow(RangeError);
    expect(() => activityRequest({ type: "playing", name: "" }, now)).toThrow(RangeError);
  });
});

describe("upload categories (PROTOCOL.md §7a)", () => {
  it("classifies by extension, then type; executables and SVG as the node does", () => {
    expect(uploadCategory("photo.JPG")).toBe("images");
    expect(uploadCategory("song.flac")).toBe("audio");
    expect(uploadCategory("clip.webm")).toBe("video");
    expect(uploadCategory("report.pdf")).toBe("documents");
    expect(uploadCategory("logo.svg", "image/svg+xml")).toBe("documents");
    expect(uploadCategory("drawing", "image/svg+xml")).toBe("documents");
    expect(uploadCategory("backup.tar.gz")).toBe("archives");
    expect(uploadCategory("blob", "image/png")).toBe("images");
    expect(uploadCategory("setup.exe")).toBe("executable");
    expect(uploadCategory("photo.png.exe", "image/png")).toBe("executable");
    expect(uploadCategory("x", "application/x-msdownload")).toBe("executable");
    expect(uploadCategory("data.bin.unknown")).toBe("other");
  });

  it("is the SDK's table: content first when the bytes are given, the protocol's vectors hold", () => {
    expect(uploadCategory("notes.txt", "text/plain", new TextEncoder().encode("MZ\u0090"))).toBe("executable");
    expect(uploadCategory("image.txt", "text/plain", new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))).toBe("images");
    expect(uploadCategory("a.lzma")).toBe("archives");
    for (const c of vectors.cases) {
      const head = c.head_hex === null ? undefined : new Uint8Array((c.head_hex.match(/../g) ?? []).map((b) => parseInt(b, 16)));
      expect(uploadCategory(c.file_name, c.mime, head), c.name).toBe(c.executable ? "executable" : c.category);
    }
  });
});
