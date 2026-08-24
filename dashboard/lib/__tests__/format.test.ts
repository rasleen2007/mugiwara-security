import { describe, expect, it } from "vitest";
import { formatBytes, formatDateTime, truncate } from "@/lib/format";

describe("formatBytes", () => {
  it("formats bytes and human units", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(1048576)).toBe("1.0 MB");
    expect(formatBytes(536870912)).toBe("512 MB");
  });

  it("renders a dash for null/undefined/NaN", () => {
    expect(formatBytes(null)).toBe("—");
    expect(formatBytes(undefined)).toBe("—");
    expect(formatBytes(Number.NaN)).toBe("—");
  });
});

describe("formatDateTime", () => {
  it("formats an ISO timestamp without seconds", () => {
    const out = formatDateTime("2026-03-01T12:30:00Z");
    expect(out).toMatch(/2026/);
    expect(out).not.toMatch(/:\d\d:\d\d/);
  });

  it("returns a dash for null/undefined", () => {
    expect(formatDateTime(null)).toBe("—");
    expect(formatDateTime(undefined)).toBe("—");
  });

  it("falls back to the raw string when unparseable", () => {
    expect(formatDateTime("not-a-date")).toBe("not-a-date");
  });
});

describe("truncate", () => {
  it("leaves short strings untouched", () => {
    expect(truncate("abc", 10)).toBe("abc");
  });

  it("truncates long strings with an ellipsis", () => {
    const out = truncate("abcdefghij", 5);
    expect(out.length).toBeLessThanOrEqual(5);
    expect(out.endsWith("…")).toBe(true);
  });
});
