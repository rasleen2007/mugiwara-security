import { describe, expect, it } from "vitest";
import { validateEmail, validatePassword, validateProjectName } from "@/lib/validators";

describe("validateEmail", () => {
  it("accepts a normal address", () => {
    expect(validateEmail("user@example.com")).toBeNull();
  });

  it("rejects empty and malformed addresses", () => {
    expect(validateEmail("")).toContain("required");
    expect(validateEmail("   ")).toContain("required");
    expect(validateEmail("nope")).toContain("valid email");
    expect(validateEmail("a@b")).toContain("valid email");
  });
});

describe("validatePassword", () => {
  it("accepts any non-empty password", () => {
    expect(validatePassword("hunter2")).toBeNull();
  });

  it("rejects an empty password", () => {
    expect(validatePassword("")).toContain("required");
  });
});

describe("validateProjectName", () => {
  it("accepts a normal name and trims whitespace", () => {
    expect(validateProjectName("  webshop  ")).toBeNull();
  });

  it("rejects empty names", () => {
    expect(validateProjectName("   ")).toContain("required");
  });

  it("rejects names over 200 characters", () => {
    expect(validateProjectName("x".repeat(201))).toContain("200 characters");
    expect(validateProjectName("x".repeat(200))).toBeNull();
  });
});
