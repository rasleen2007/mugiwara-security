import { describe, expect, it } from "vitest";
import {
  SIGNUP_MIN_PASSWORD_LENGTH,
  validateEmail,
  validatePassword,
  validatePasswordConfirmation,
  validateProjectName,
  validateSignupPassword,
} from "@/lib/validators";

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

describe("validateSignupPassword", () => {
  it("accepts passwords at or above the minimum length", () => {
    expect(validateSignupPassword("a".repeat(SIGNUP_MIN_PASSWORD_LENGTH))).toBeNull();
    expect(validateSignupPassword("correct horse battery staple")).toBeNull();
  });

  it("rejects empty and too-short passwords", () => {
    expect(validateSignupPassword("")).toContain("required");
    const err = validateSignupPassword("abc");
    expect(err).toContain(String(SIGNUP_MIN_PASSWORD_LENGTH));
  });
});

describe("validatePasswordConfirmation", () => {
  it("accepts a matching confirmation", () => {
    expect(validatePasswordConfirmation("secret123", "secret123")).toBeNull();
  });

  it("rejects an empty confirmation", () => {
    expect(validatePasswordConfirmation("secret123", "")).toContain("confirm");
  });

  it("rejects a mismatched confirmation", () => {
    expect(validatePasswordConfirmation("secret123", "secret124")).toContain(
      "do not match"
    );
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
