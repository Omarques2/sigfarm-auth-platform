import { describe, expect, it } from "vitest";
import {
  ErrorEnvelopeSchema,
  LogoutSuccessSchema,
  AccessTokenClaimsSchema,
  MeSuccessSchema,
  RefreshSuccessSchema,
  SessionSuccessSchema,
} from "../src/index.js";

describe("auth contracts v1", () => {
  it("validates /v1/auth/session response", () => {
    const parsed = SessionSuccessSchema.parse({
      data: {
        sessionId: "sess_abc",
        userId: "11111111-1111-4111-8111-111111111111",
        amr: "entra",
        globalStatus: "active",
        issuedAt: "2026-02-16T14:00:00.000Z",
        expiresAt: "2026-02-16T15:00:00.000Z",
      },
      meta: {
        contractVersion: "v1",
        correlationId: "corr_001",
      },
    });

    expect(parsed.data.sessionId).toBe("sess_abc");
  });

  it("validates /v1/auth/me response", () => {
    const parsed = MeSuccessSchema.parse({
      data: {
        userId: "11111111-1111-4111-8111-111111111111",
        email: "user@sigfarm.com",
        emailVerified: true,
        displayName: "Sigfarm User",
        globalStatus: "active",
        apps: [
          { appKey: "LANDWATCH", roles: ["user"] },
          { appKey: "PBI_EMBED", roles: ["platform_admin"] },
        ],
      },
      meta: {
        contractVersion: "v1",
        correlationId: "corr_002",
      },
    });

    expect(parsed.data.apps).toHaveLength(2);
  });

  it("validates /v1/auth/logout response", () => {
    const parsed = LogoutSuccessSchema.parse({
      data: {
        revoked: true,
      },
      meta: {
        contractVersion: "v1",
        correlationId: "corr_003",
      },
    });

    expect(parsed.data.revoked).toBe(true);
  });

  it("validates /v1/auth/refresh response", () => {
    const parsed = RefreshSuccessSchema.parse({
      data: {
        accessToken: "token-access",
        refreshToken: "token-refresh",
        expiresInSeconds: 900,
        tokenType: "Bearer",
      },
      meta: {
        contractVersion: "v1",
        correlationId: "corr_004",
      },
    });

    expect(parsed.data.tokenType).toBe("Bearer");
  });

  it("validates canonical auth error envelope", () => {
    const parsed = ErrorEnvelopeSchema.parse({
      error: {
        code: "UNAUTHORIZED",
        message: "No active session",
      },
      meta: {
        contractVersion: "v1",
        correlationId: "corr_005",
      },
    });

    expect(parsed.error.code).toBe("UNAUTHORIZED");
  });

  it("validates canonical access token claims", () => {
    const parsed = AccessTokenClaimsSchema.parse({
      sub: "11111111-1111-4111-8111-111111111111",
      sid: "sess_abc",
      amr: "password",
      email: "user@sigfarm.com",
      emailVerified: true,
      globalStatus: "active",
      apps: [{ appKey: "PBI_EMBED", roles: ["user"] }],
      ver: 1,
      iss: "https://auth.sigfarmintelligence.com",
      aud: "sigfarm-apps",
    });

    expect(parsed.amr).toBe("password");
  });
});
