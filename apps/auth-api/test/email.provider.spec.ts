import { describe, expect, it, vi } from "vitest";
import type { AppEnv } from "../src/config/env.js";
import {
  AzureAcsEmailProvider,
  ConsoleEmailProvider,
  FallbackEmailProvider,
  createEmailProvider,
  type EmailProvider,
} from "../src/email/email.provider.js";

function buildEnv(overrides?: Partial<AppEnv>): AppEnv {
  return {
    nodeEnv: "development",
    port: 3000,
    betterAuthBaseUrl: "https://auth.sigfarmintelligence.com",
    betterAuthSecret: "dev-only-secret-change-me-dev-only-secret",
    betterAuthTrustedOrigins: ["http://localhost:3000"],
    accessTokenTtlSeconds: 900,
    refreshTokenTtlSeconds: 60 * 60 * 24 * 30,
    jwtIssuer: "https://auth.sigfarmintelligence.com",
    jwtAudience: "sigfarm-apps",
    jwtKid: "sigfarm-auth-k1",
    rateLimitWindowSeconds: 60,
    rateLimitMaxRequests: 60,
    rateLimitLoginMaxRequests: 10,
    requireEmailVerification: true,
    authEmailVerifyPageUrl: "https://auth.sigfarmintelligence.com/verify-email",
    authEmailResetPageUrl: "https://auth.sigfarmintelligence.com/reset-password",
    authEmailSendTimeoutMs: 10_000,
    authEmailRetryAttempts: 3,
    authEmailRetryBaseDelayMs: 250,
    ...overrides,
  };
}

describe("email provider", () => {
  it("throws in staging when provider is not configured", () => {
    const env = buildEnv({ nodeEnv: "staging" });
    expect(() => createEmailProvider(env)).toThrow(/not configured/i);
  });

  it("uses console provider in development and logs token preview only", async () => {
    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {
      return;
    });
    const env = buildEnv({
      nodeEnv: "development",
      emailProvider: "console",
    });
    const provider = createEmailProvider(env);

    await provider.sendVerificationEmail({
      to: "user@sigfarm.com",
      token: "very-secret-token",
      correlationId: "cid-1",
    });

    expect(infoSpy).toHaveBeenCalledTimes(1);
    expect(infoSpy.mock.calls[0]?.[1]).toMatchObject({
      to: "user@sigfarm.com",
      correlationId: "cid-1",
      tokenPreview: "very-s...",
    });
    expect(JSON.stringify(infoSpy.mock.calls[0])).not.toContain("very-secret-token");
    infoSpy.mockRestore();
  });

  it("throws when azure provider is configured without connection string", () => {
    const env = buildEnv({
      nodeEnv: "staging",
      emailProvider: "azure-acs",
      acsEmailSender: "DoNotReply@mail.sigfarmintelligence.com",
    });
    expect(() => createEmailProvider(env)).toThrow(/ACS_EMAIL_CONNECTION_STRING/);
  });

  it("falls back to console in development when azure config is incomplete", async () => {
    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {
      return;
    });
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {
      return;
    });
    const env = buildEnv({
      nodeEnv: "development",
      emailProvider: "azure-acs",
    });
    const provider = createEmailProvider(env);

    await provider.sendResetPasswordEmail({
      to: "user@sigfarm.com",
      token: "dev-fallback-token",
      correlationId: "cid-fallback",
    });

    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(infoSpy).toHaveBeenCalledTimes(1);
    warnSpy.mockRestore();
    infoSpy.mockRestore();
  });

  it("retries azure send and succeeds on later attempt", async () => {
    const beginSend = vi.fn();
    beginSend
      .mockRejectedValueOnce(new Error("temporary outage 1"))
      .mockRejectedValueOnce(new Error("temporary outage 2"))
      .mockResolvedValue({
        pollUntilDone: async () => ({ status: "Succeeded" }),
      });

    const provider: EmailProvider = new AzureAcsEmailProvider({
      connectionString: "endpoint=https://example/;accesskey=key",
      senderAddress: "DoNotReply@mail.sigfarmintelligence.com",
      verifyPageUrl: "https://auth.sigfarmintelligence.com/verify-email",
      resetPageUrl: "https://auth.sigfarmintelligence.com/reset-password",
      emailClient: {
        beginSend,
      } as {
        beginSend: (...args: unknown[]) => Promise<{ pollUntilDone: () => Promise<unknown> }>;
      },
      maxAttempts: 3,
      retryBaseDelayMs: 1,
      sendTimeoutMs: 1_000,
    });

    await expect(
      provider.sendResetPasswordEmail({
        to: "user@sigfarm.com",
        token: "token-123",
        correlationId: "cid-retry",
      }),
    ).resolves.toBeUndefined();

    expect(beginSend).toHaveBeenCalledTimes(3);
  });

  it("builds verification email with shared auth frontend URL", async () => {
    const beginSend = vi.fn().mockResolvedValue({
      pollUntilDone: async () => ({ status: "Succeeded" }),
    });

    const provider: EmailProvider = new AzureAcsEmailProvider({
      connectionString: "endpoint=https://example/;accesskey=key",
      senderAddress: "DoNotReply@mail.sigfarmintelligence.com",
      verifyPageUrl: "https://auth.sigfarmintelligence.com/verify-email",
      resetPageUrl: "https://auth.sigfarmintelligence.com/reset-password",
      emailClient: {
        beginSend,
      } as {
        beginSend: (...args: unknown[]) => Promise<{ pollUntilDone: () => Promise<unknown> }>;
      },
      maxAttempts: 1,
    });

    await provider.sendVerificationEmail({
      to: "user@sigfarm.com",
      token: "token-front",
      correlationId: "cid-front",
    });

    const sentMessage = beginSend.mock.calls[0]?.[0] as { content?: { plainText?: string } };
    const plainText = sentMessage?.content?.plainText ?? "";
    expect(plainText).toContain("https://auth.sigfarmintelligence.com/verify-email?token=token-front");
    expect(plainText).not.toContain("/api/auth/verify-email");
  });

  it("times out when azure beginSend does not resolve", async () => {
    const beginSend = vi.fn().mockImplementation(
      () =>
        new Promise<never>(() => {
          return;
        }),
    );

    const provider: EmailProvider = new AzureAcsEmailProvider({
      connectionString: "endpoint=https://example/;accesskey=key",
      senderAddress: "DoNotReply@mail.sigfarmintelligence.com",
      verifyPageUrl: "https://auth.sigfarmintelligence.com/verify-email",
      resetPageUrl: "https://auth.sigfarmintelligence.com/reset-password",
      emailClient: {
        beginSend,
      } as {
        beginSend: (...args: unknown[]) => Promise<{ pollUntilDone: () => Promise<unknown> }>;
      },
      maxAttempts: 1,
      sendTimeoutMs: 20,
    });

    await expect(
      provider.sendVerificationEmail({
        to: "user@sigfarm.com",
        token: "token-timeout",
        correlationId: "cid-timeout",
      }),
    ).rejects.toThrow(/beginSend timeout/i);
  });

  it("falls back to console provider when primary provider fails", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {
      return;
    });
    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {
      return;
    });

    const failingPrimary: EmailProvider = {
      async sendVerificationEmail() {
        throw new Error("primary-down");
      },
      async sendResetPasswordEmail() {
        throw new Error("primary-down");
      },
      async sendEmailChangeCode() {
        throw new Error("primary-down");
      },
    };

    const provider = new FallbackEmailProvider(
      failingPrimary,
      new ConsoleEmailProvider(),
      "test",
    );

    await expect(
      provider.sendVerificationEmail({
        to: "user@sigfarm.com",
        token: "token-fallback",
        correlationId: "cid-fallback-runtime",
      }),
    ).resolves.toBeUndefined();

    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(infoSpy).toHaveBeenCalledTimes(1);

    warnSpy.mockRestore();
    infoSpy.mockRestore();
  });

  it("builds email-change message with one-time verification code", async () => {
    const beginSend = vi.fn().mockResolvedValue({
      pollUntilDone: async () => ({ status: "Succeeded" }),
    });

    const provider: EmailProvider = new AzureAcsEmailProvider({
      connectionString: "endpoint=https://example/;accesskey=key",
      senderAddress: "DoNotReply@mail.sigfarmintelligence.com",
      verifyPageUrl: "https://auth.sigfarmintelligence.com/verify-email",
      resetPageUrl: "https://auth.sigfarmintelligence.com/reset-password",
      emailClient: {
        beginSend,
      } as {
        beginSend: (...args: unknown[]) => Promise<{ pollUntilDone: () => Promise<unknown> }>;
      },
      maxAttempts: 1,
    });

    await provider.sendEmailChangeCode({
      to: "updated@sigfarm.com",
      token: "123456",
      correlationId: "cid-email-change",
    });

    const sentMessage = beginSend.mock.calls[0]?.[0] as { content?: { plainText?: string } };
    const plainText = sentMessage?.content?.plainText ?? "";
    expect(plainText).toContain("Codigo: 123456");
    expect(plainText).not.toContain("/reset-password");
  });
});
