// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DANGEROUS_EXTENSIONS, UPLOAD_HEAD_BYTES, classifyUpload, declaredCategory, executableKind, extensionOf, extensionsOf } from "../src";

interface Case {
  name: string;
  file_name: string;
  mime: string;
  head_hex: string | null;
  category: string;
  executable: boolean;
}

const doc = JSON.parse(readFileSync(new URL("../../protocol/testvectors/upload_categories.json", import.meta.url), "utf8")) as { cases: Case[] };

function hex(s: string): Uint8Array {
  return new Uint8Array((s.match(/../g) ?? []).map((b) => parseInt(b, 16)));
}

describe("upload categories (PROTOCOL.md §7a)", () => {
  it("passes the protocol's vectors", () => {
    expect(doc.cases.length).toBeGreaterThan(30);
    for (const c of doc.cases) {
      const got = classifyUpload(c.file_name, c.mime, c.head_hex === null ? undefined : hex(c.head_hex));
      expect(got, c.name).toEqual({ category: c.category, executable: c.executable });
    }
  });

  it("declares executables as such and everything else by its category", () => {
    expect(declaredCategory(classifyUpload("setup.exe"))).toBe("executable");
    expect(declaredCategory(classifyUpload("a.png"))).toBe("images");
    expect(declaredCategory(classifyUpload("a"))).toBe("other");
  });

  it("names the kind of an executable for download warnings", () => {
    expect(executableKind("setup.msi", "")).toBe("installer");
    expect(executableKind("x.docm", "")).toBe("macro_document");
    expect(executableKind("x", "", new Uint8Array([0x7f, 0x45, 0x4c, 0x46]))).toBe("linux");
    expect(executableKind("x", "application/vnd.android.package-archive")).toBe("mobile_app");
    expect(executableKind("photo.png", "image/png")).toBeNull();
  });

  it("finds a disk image signature within the head bytes", () => {
    const head = new Uint8Array(UPLOAD_HEAD_BYTES);
    head.set([..."CD001"].map((c) => c.charCodeAt(0)), 0x8001);
    expect(classifyUpload("photo.jpg", "image/jpeg", head)).toEqual({ category: "other", executable: true });
    expect(executableKind("photo.jpg", "image/jpeg", head)).toBe("disk_image");
  });

  it("exposes the tables for pickers and warnings", () => {
    expect(extensionOf("Archive.TAR.GZ")).toBe("gz");
    expect(extensionsOf("archives")).toContain("lzma");
    expect(extensionsOf("other")).toEqual([]);
    expect(DANGEROUS_EXTENSIONS.has("settingcontent-ms")).toBe(true);
    expect(DANGEROUS_EXTENSIONS.has("chm")).toBe(true);
    expect(DANGEROUS_EXTENSIONS.size).toBe(105);
  });
});
