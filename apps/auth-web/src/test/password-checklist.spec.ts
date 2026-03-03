import { describe, expect, it } from "vitest";
import { shouldShowPasswordChecklist } from "../lib/password-checklist";

describe("shouldShowPasswordChecklist", () => {
  it("returns false when both password fields are empty", () => {
    expect(
      shouldShowPasswordChecklist({
        primaryPassword: "",
        confirmationPassword: "",
        isStrongPassword: false,
      }),
    ).toBe(false);
  });

  it("returns true when password has characters and is still weak", () => {
    expect(
      shouldShowPasswordChecklist({
        primaryPassword: "abc",
        confirmationPassword: "",
        isStrongPassword: false,
      }),
    ).toBe(true);
  });

  it("returns true when only confirmation has characters and password is weak", () => {
    expect(
      shouldShowPasswordChecklist({
        primaryPassword: "",
        confirmationPassword: "abc",
        isStrongPassword: false,
      }),
    ).toBe(true);
  });

  it("returns false when password is already strong", () => {
    expect(
      shouldShowPasswordChecklist({
        primaryPassword: "SenhaForte#2026",
        confirmationPassword: "SenhaForte#2026",
        isStrongPassword: true,
      }),
    ).toBe(false);
  });
});
