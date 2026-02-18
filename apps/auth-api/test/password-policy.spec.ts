import { describe, expect, it } from "vitest";
import { isPasswordPolicyCompliant } from "../src/auth/password-policy.js";

describe("password policy", () => {
  it("accepts strong password", () => {
    expect(isPasswordPolicyCompliant("StrongPass123!")).toBe(true);
  });

  it("rejects weak passwords", () => {
    expect(isPasswordPolicyCompliant("short")).toBe(false);
    expect(isPasswordPolicyCompliant("alllowercase123!")).toBe(false);
    expect(isPasswordPolicyCompliant("ALLUPPERCASE123!")).toBe(false);
    expect(isPasswordPolicyCompliant("NoNumberPassword!")).toBe(false);
    expect(isPasswordPolicyCompliant("NoSpecial12345")).toBe(false);
  });
});
