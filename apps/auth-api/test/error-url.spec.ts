import { describe, expect, it } from "vitest";
import { buildAuthErrorUrl } from "../src/auth/error-url.js";
import { loadEnv } from "../src/config/env.js";

describe("auth error url", () => {
  it("points to the portal callback, which handles ?error=", () => {
    expect(buildAuthErrorUrl("https://auth.sigfarmintelligence.com")).toBe(
      "https://auth.sigfarmintelligence.com/auth/callback",
    );
  });

  it("ignores any path on the base url", () => {
    expect(buildAuthErrorUrl("https://auth.example.com/verify-email")).toBe(
      "https://auth.example.com/auth/callback",
    );
  });

  it("has no query string (Better Auth appends ?error= unconditionally)", () => {
    expect(buildAuthErrorUrl("https://auth.example.com")).not.toContain("?");
  });

  it("is undefined without a portal url (keeps Better Auth default)", () => {
    expect(buildAuthErrorUrl(undefined)).toBeUndefined();
  });
});

describe("env authWebBaseUrl", () => {
  const base = { NODE_ENV: "test" } as NodeJS.ProcessEnv;

  it("uses AUTH_WEB_BASE_URL origin when set", () => {
    const env = loadEnv({
      ...base,
      AUTH_WEB_BASE_URL: "https://portal.example.com/x",
      AUTH_EMAIL_VERIFY_PAGE_URL: "https://other.example.com/verify-email",
    });
    expect(env.authWebBaseUrl).toBe("https://portal.example.com");
  });

  it("falls back to the origin of AUTH_EMAIL_VERIFY_PAGE_URL", () => {
    const env = loadEnv({
      ...base,
      AUTH_EMAIL_VERIFY_PAGE_URL: "https://auth.sigfarmintelligence.com/verify-email",
    });
    expect(env.authWebBaseUrl).toBe("https://auth.sigfarmintelligence.com");
  });

  it("is undefined when neither is set", () => {
    expect(loadEnv(base).authWebBaseUrl).toBeUndefined();
  });
});
