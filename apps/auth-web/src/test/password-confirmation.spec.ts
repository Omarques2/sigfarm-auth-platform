import { describe, expect, it } from "vitest";
import { shouldShowPasswordMismatch } from "../lib/password-confirmation";

describe("shouldShowPasswordMismatch", () => {
  it("returns false when primary password is empty", () => {
    expect(shouldShowPasswordMismatch("", "abc")).toBe(false);
  });

  it("returns false when confirmation password is empty", () => {
    expect(shouldShowPasswordMismatch("abc", "")).toBe(false);
  });

  it("returns true when both fields have content and differ", () => {
    expect(shouldShowPasswordMismatch("abc123", "abc124")).toBe(true);
  });

  it("returns false when both fields match", () => {
    expect(shouldShowPasswordMismatch("SenhaForte#2026", "SenhaForte#2026")).toBe(false);
  });
});
