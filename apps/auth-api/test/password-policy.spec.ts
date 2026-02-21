import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  getPwnedPasswordReuseCount,
  isPasswordCompromised,
  isPasswordPolicyCompliant,
} from "../src/auth/password-policy.js";

describe("password policy", () => {
  it("accepts passwords with enough length", () => {
    expect(isPasswordPolicyCompliant("frase longa segura")).toBe(true);
  });

  it("rejects too short passwords", () => {
    expect(isPasswordPolicyCompliant("short")).toBe(false);
  });

  it("detects compromised password through pwned range response", async () => {
    const password = "compromised-passphrase";
    const digest = createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
    const suffix = digest.slice(5);
    const mockedFetch = vi.fn(async () => new Response(`${suffix}:42\nABCDEF:1\n`));

    const count = await getPwnedPasswordReuseCount(password, {
      enabled: true,
      timeoutMs: 1_000,
      fetchImpl: mockedFetch as unknown as typeof fetch,
    });

    expect(count).toBe(42);
    await expect(
      isPasswordCompromised(password, {
        enabled: true,
        timeoutMs: 1_000,
        fetchImpl: mockedFetch as unknown as typeof fetch,
      }),
    ).resolves.toBe(true);
  });

  it("fails open when pwned service is unavailable", async () => {
    const mockedFetch = vi.fn(async () => {
      throw new Error("network down");
    });

    const count = await getPwnedPasswordReuseCount("any-long-passphrase", {
      enabled: true,
      timeoutMs: 1_000,
      fetchImpl: mockedFetch as unknown as typeof fetch,
    });

    expect(count).toBeNull();
    await expect(
      isPasswordCompromised("any-long-passphrase", {
        enabled: true,
        timeoutMs: 1_000,
        fetchImpl: mockedFetch as unknown as typeof fetch,
      }),
    ).resolves.toBe(false);
  });
});
