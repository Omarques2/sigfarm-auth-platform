import { describe, expect, it } from "vitest";
import { resolveSafeReturnTo } from "../lib/return-to";

const baseInput = {
  appBaseUrl: "https://auth.sigfarmintelligence.com/",
  defaultReturnTo: "https://bi.sigfarmintelligence.com/",
  allowedOrigins: [
    "https://bi.sigfarmintelligence.com",
    "https://testbi.sigfarmintelligence.com",
    "https://landwatch.sigfarmintelligence.com",
    "https://testlandwatch.sigfarmintelligence.com",
  ],
};

describe("resolveSafeReturnTo", () => {
  it("returns default target when returnTo is missing", () => {
    const result = resolveSafeReturnTo({
      ...baseInput,
      returnTo: undefined,
    });

    expect(result).toBe(baseInput.defaultReturnTo);
  });

  it("accepts relative paths on auth web origin", () => {
    const result = resolveSafeReturnTo({
      ...baseInput,
      returnTo: "/dashboard?tab=overview",
    });

    expect(result).toBe("https://auth.sigfarmintelligence.com/dashboard?tab=overview");
  });

  it("accepts absolute URLs from trusted origins", () => {
    const result = resolveSafeReturnTo({
      ...baseInput,
      returnTo: encodeURIComponent("https://landwatch.sigfarmintelligence.com/home"),
    });

    expect(result).toBe("https://landwatch.sigfarmintelligence.com/home");
  });

  it("blocks absolute URLs from non-trusted origins", () => {
    const result = resolveSafeReturnTo({
      ...baseInput,
      returnTo: "https://evil.example.com/steal",
    });

    expect(result).toBe(baseInput.defaultReturnTo);
  });

  it("blocks unsafe protocols", () => {
    const result = resolveSafeReturnTo({
      ...baseInput,
      returnTo: "javascript:alert(1)",
    });

    expect(result).toBe(baseInput.defaultReturnTo);
  });

  it("uses trusted referrer when returnTo is missing", () => {
    const result = resolveSafeReturnTo({
      ...baseInput,
      returnTo: undefined,
      referrer: "https://bi.sigfarmintelligence.com/reports/7?tab=overview",
    });

    expect(result).toBe("https://bi.sigfarmintelligence.com/reports/7?tab=overview");
  });

  it("blocks auth login route as return target", () => {
    const result = resolveSafeReturnTo({
      ...baseInput,
      returnTo: "/login",
    });

    expect(result).toBe(baseInput.defaultReturnTo);
  });

  it("blocks auth referrer route to avoid login loop", () => {
    const result = resolveSafeReturnTo({
      ...baseInput,
      returnTo: undefined,
      allowedOrigins: [...baseInput.allowedOrigins, "https://auth.sigfarmintelligence.com"],
      referrer: "https://auth.sigfarmintelligence.com/login?returnTo=https%3A%2F%2Fbi.sigfarmintelligence.com%2F",
    });

    expect(result).toBe(baseInput.defaultReturnTo);
  });
});
