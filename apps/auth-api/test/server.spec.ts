import { describe, expect, it } from "vitest";
import {
  ErrorEnvelopeSchema,
  LogoutSuccessSchema,
  MeSuccessSchema,
  RefreshSuccessSchema,
  SessionSuccessSchema,
} from "@sigfarm/auth-contracts";
import { buildServer, type AppDependencies } from "../src/index.js";

type AuthMethod = "entra" | "password";
type AuthStatus = "pending" | "active" | "disabled";

type SessionRecord = {
  sessionId: string;
  userId: string;
  amr: AuthMethod;
  refreshToken: string;
  revoked: boolean;
  issuedAt: Date;
  expiresAt: Date;
  usedRefresh: Set<string>;
};

function encodeToken(payload: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

function decodeToken(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token, "base64url").toString("utf8")) as Record<string, unknown>;
}

function buildDependencies(): AppDependencies {
  const now = new Date("2026-02-16T14:00:00.000Z");
  const sessions = new Map<string, SessionRecord>();
  const refreshIndex = new Map<string, string>();
  const user = {
    id: "11111111-1111-4111-8111-111111111111",
    email: "user@sigfarm.com",
    emailVerified: true,
    name: "Sigfarm User",
    status: "active" as AuthStatus,
    apps: [
      { appKey: "LANDWATCH", roles: ["app_user"] },
      { appKey: "PBI_EMBED", roles: ["platform_admin"] },
    ],
  };

  const dependencies: AppDependencies = {
    authGateway: {
      async mount() {
        return;
      },
      async getSession(headers) {
        if (headers.get("x-test-auth-session") !== "ok") {
          return null;
        }
        return {
          user: {
            id: user.id,
            email: user.email,
            emailVerified: user.emailVerified,
            name: user.name,
          },
        };
      },
      async signOut() {
        return;
      },
    },
    identityService: {
      async ensureFromAuthUser() {
        return;
      },
      async getSnapshot(userId: string) {
        if (userId !== user.id) return null;
        return {
          userId: user.id,
          email: user.email,
          emailVerified: user.emailVerified,
          displayName: user.name,
          globalStatus: user.status,
          apps: user.apps,
        };
      },
      async resolveAuthMethod() {
        return "password";
      },
    },
    sessionService: {
      async issueSession(input) {
        const sessionId = `sess_${sessions.size + 1}`;
        const refreshToken = `rt_${sessions.size + 1}_0000000000000000`;
        const record: SessionRecord = {
          sessionId,
          userId: input.userId,
          amr: input.amr,
          refreshToken,
          revoked: false,
          issuedAt: now,
          expiresAt: new Date("2026-03-01T14:00:00.000Z"),
          usedRefresh: new Set<string>(),
        };
        sessions.set(sessionId, record);
        refreshIndex.set(refreshToken, sessionId);
        return {
          sessionId,
          userId: input.userId,
          amr: input.amr,
          refreshToken,
          issuedAt: record.issuedAt,
          expiresAt: record.expiresAt,
        };
      },
      async rotateSession(input) {
        const sessionId = refreshIndex.get(input.refreshToken);
        if (!sessionId) return { kind: "invalid" as const };
        const record = sessions.get(sessionId);
        if (!record || record.revoked) return { kind: "invalid" as const };
        if (record.usedRefresh.has(input.refreshToken)) {
          record.revoked = true;
          return { kind: "reuse" as const, sessionId: record.sessionId };
        }
        if (record.refreshToken !== input.refreshToken) {
          record.revoked = true;
          return { kind: "reuse" as const, sessionId: record.sessionId };
        }
        record.usedRefresh.add(input.refreshToken);
        const nextRefreshToken = `rt_${sessionId}_${record.usedRefresh.size}_0000000000000000`;
        record.refreshToken = nextRefreshToken;
        refreshIndex.set(nextRefreshToken, sessionId);
        return {
          kind: "ok" as const,
          sessionId: record.sessionId,
          userId: record.userId,
          amr: record.amr,
          refreshToken: nextRefreshToken,
          issuedAt: now,
          expiresAt: record.expiresAt,
        };
      },
      async getActiveSession(sessionId: string) {
        const record = sessions.get(sessionId);
        if (!record || record.revoked) return null;
        return {
          sessionId: record.sessionId,
          userId: record.userId,
          amr: record.amr,
          issuedAt: record.issuedAt,
          expiresAt: record.expiresAt,
        };
      },
      async revokeBySessionId(sessionId: string) {
        const record = sessions.get(sessionId);
        if (!record) return false;
        record.revoked = true;
        return true;
      },
      async revokeByRefreshToken(refreshToken: string) {
        const sessionId = refreshIndex.get(refreshToken);
        if (!sessionId) return false;
        const record = sessions.get(sessionId);
        if (!record) return false;
        record.revoked = true;
        return true;
      },
    },
    tokenService: {
      async issueAccessToken(input) {
        const token = encodeToken({
          ...input,
          issuedAt: "2026-02-16T14:00:00.000Z",
          expiresAt: "2026-02-16T14:15:00.000Z",
        });
        return {
          token,
          expiresInSeconds: 900,
          issuedAt: new Date("2026-02-16T14:00:00.000Z"),
          expiresAt: new Date("2026-02-16T14:15:00.000Z"),
        };
      },
      async verifyAccessToken(token) {
        const payload = decodeToken(token);
        return {
          sub: String(payload.sub),
          sid: String(payload.sid),
          amr: payload.amr as AuthMethod,
          email: String(payload.email),
          emailVerified: Boolean(payload.emailVerified),
          globalStatus: payload.globalStatus as AuthStatus,
          apps: (payload.apps as Array<{ appKey: string; roles: string[] }>) ?? [],
          ver: Number(payload.ver ?? 1),
        };
      },
      getJwks() {
        return {
          keys: [{ kty: "RSA", kid: "test-k1", alg: "RS256", use: "sig" }],
        };
      },
    },
    auditService: {
      async record() {
        return;
      },
    },
    accountFlowService: {
      async discoverEmail(input) {
        if (input.email === "user@sigfarm.com") {
          return {
            accountState: "active",
            retryAfterSeconds: 0,
          };
        }
        if (input.email === "pending@sigfarm.com") {
          return {
            accountState: "pending_verification",
            retryAfterSeconds: 60,
          };
        }
        return {
          accountState: "missing",
          retryAfterSeconds: 0,
        };
      },
      async requestPasswordResetCode() {
        return {
          status: "sent",
          retryAfterSeconds: 60,
        };
      },
      async verifyPasswordResetCode(input) {
        return input.code === "123456";
      },
      async completePasswordResetWithCode(input) {
        return input.code === "123456";
      },
      async updateAccountProfile(input) {
        if (input.userId !== user.id) {
          return { displayName: null };
        }
        user.name = input.name ?? "";
        return {
          displayName: input.name,
        };
      },
      async requestEmailChangeCode(input) {
        if (input.newEmail.toLowerCase() === user.email.toLowerCase()) {
          return {
            status: "same_as_current" as const,
            retryAfterSeconds: 0,
          };
        }
        return {
          status: "sent" as const,
          retryAfterSeconds: 60,
        };
      },
      async confirmEmailChangeCode(input) {
        if (input.code !== "123456") {
          return {
            updated: false,
            reason: "invalid_or_expired" as const,
          };
        }
        user.email = input.newEmail.toLowerCase();
        user.emailVerified = true;
        return {
          updated: true,
        };
      },
    },
  };

  return dependencies;
}

describe("auth-api epic-02", () => {
  it("returns health ok", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });
    const response = await app.inject({ method: "GET", url: "/health" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok" });
    await app.close();
  });

  it("returns unauthorized for refresh without auth session or token", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });
    const response = await app.inject({ method: "POST", url: "/v1/auth/refresh" });
    expect(response.statusCode).toBe(401);
    const parsed = ErrorEnvelopeSchema.parse(response.json());
    expect(parsed.error.code).toBe("UNAUTHORIZED");
    await app.close();
  });

  it("exchanges auth session for access/refresh tokens", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });
    const response = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: {
        "x-test-auth-session": "ok",
      },
    });
    expect(response.statusCode).toBe(200);
    const parsed = RefreshSuccessSchema.parse(response.json());
    expect(parsed.data.tokenType).toBe("Bearer");
    expect(parsed.data.accessToken.length).toBeGreaterThan(20);
    expect(parsed.data.refreshToken.length).toBeGreaterThan(5);
    await app.close();
  });

  it("returns session and me from a valid access token", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });

    const refreshResponse = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: {
        "x-test-auth-session": "ok",
      },
    });
    const refresh = RefreshSuccessSchema.parse(refreshResponse.json());

    const sessionResponse = await app.inject({
      method: "GET",
      url: "/v1/auth/session",
      headers: {
        authorization: `Bearer ${refresh.data.accessToken}`,
      },
    });
    expect(sessionResponse.statusCode).toBe(200);
    const session = SessionSuccessSchema.parse(sessionResponse.json());
    expect(session.data.userId).toBe("11111111-1111-4111-8111-111111111111");

    const meResponse = await app.inject({
      method: "GET",
      url: "/v1/auth/me",
      headers: {
        authorization: `Bearer ${refresh.data.accessToken}`,
      },
    });
    expect(meResponse.statusCode).toBe(200);
    const me = MeSuccessSchema.parse(meResponse.json());
    expect(me.data.email).toBe("user@sigfarm.com");
    expect(me.data.apps).toHaveLength(2);

    await app.close();
  });

  it("rotates refresh token and detects reuse", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });

    const exchangeResponse = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: {
        "x-test-auth-session": "ok",
      },
    });
    const exchanged = RefreshSuccessSchema.parse(exchangeResponse.json());

    const rotateResponse = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: {
        refreshToken: exchanged.data.refreshToken,
      },
    });
    expect(rotateResponse.statusCode).toBe(200);
    const rotated = RefreshSuccessSchema.parse(rotateResponse.json());
    expect(rotated.data.refreshToken).not.toBe(exchanged.data.refreshToken);

    const reuseResponse = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: {
        refreshToken: exchanged.data.refreshToken,
      },
    });
    expect(reuseResponse.statusCode).toBe(401);
    const reuseError = ErrorEnvelopeSchema.parse(reuseResponse.json());
    expect(reuseError.error.code).toBe("UNAUTHORIZED");

    await app.close();
  });

  it("returns logout success and publishes JWKS", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });

    const exchangeResponse = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: {
        "x-test-auth-session": "ok",
      },
    });
    const exchanged = RefreshSuccessSchema.parse(exchangeResponse.json());

    const logoutResponse = await app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      headers: {
        authorization: `Bearer ${exchanged.data.accessToken}`,
      },
    });
    expect(logoutResponse.statusCode).toBe(200);
    LogoutSuccessSchema.parse(logoutResponse.json());

    const jwksResponse = await app.inject({
      method: "GET",
      url: "/.well-known/jwks.json",
    });
    expect(jwksResponse.statusCode).toBe(200);
    expect(jwksResponse.json()).toEqual({
      keys: [{ kty: "RSA", kid: "test-k1", alg: "RS256", use: "sig" }],
    });

    await app.close();
  });

  it("discovers account state by email", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });
    const trustedHeaders = {
      origin: "http://localhost:3000",
    };

    const active = await app.inject({
      method: "POST",
      url: "/v1/auth/email/discover",
      headers: trustedHeaders,
      payload: {
        email: "user@sigfarm.com",
      },
    });
    expect(active.statusCode).toBe(200);
    expect(active.json().data.accountState).toBe("active");

    const pending = await app.inject({
      method: "POST",
      url: "/v1/auth/email/discover",
      headers: trustedHeaders,
      payload: {
        email: "pending@sigfarm.com",
      },
    });
    expect(pending.statusCode).toBe(200);
    expect(pending.json().data.accountState).toBe("pending_verification");

    const missing = await app.inject({
      method: "POST",
      url: "/v1/auth/email/discover",
      headers: trustedHeaders,
      payload: {
        email: "new@sigfarm.com",
      },
    });
    expect(missing.statusCode).toBe(200);
    expect(missing.json().data.accountState).toBe("missing");

    const untrusted = await app.inject({
      method: "POST",
      url: "/v1/auth/email/discover",
      headers: {
        origin: "http://evil.local",
      },
      payload: {
        email: "pending@sigfarm.com",
      },
    });
    expect(untrusted.statusCode).toBe(200);
    expect(untrusted.json().data.accountState).toBe("active");

    await app.close();
  });

  it("requests, verifies and completes password reset code flow", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });

    const requestCode = await app.inject({
      method: "POST",
      url: "/v1/auth/password-reset/request-code",
      payload: {
        email: "user@sigfarm.com",
      },
    });
    expect(requestCode.statusCode).toBe(200);
    expect(requestCode.json().data.status).toBe("sent");

    const verifyInvalid = await app.inject({
      method: "POST",
      url: "/v1/auth/password-reset/verify-code",
      payload: {
        email: "user@sigfarm.com",
        code: "000000",
      },
    });
    expect(verifyInvalid.statusCode).toBe(200);
    expect(verifyInvalid.json().data.valid).toBe(false);

    const verifyValid = await app.inject({
      method: "POST",
      url: "/v1/auth/password-reset/verify-code",
      payload: {
        email: "user@sigfarm.com",
        code: "123456",
      },
    });
    expect(verifyValid.statusCode).toBe(200);
    expect(verifyValid.json().data.valid).toBe(true);

    const weakPassword = await app.inject({
      method: "POST",
      url: "/v1/auth/password-reset/complete-code",
      payload: {
        email: "user@sigfarm.com",
        code: "123456",
        newPassword: "weakpass",
      },
    });
    expect(weakPassword.statusCode).toBe(400);

    const complete = await app.inject({
      method: "POST",
      url: "/v1/auth/password-reset/complete-code",
      payload: {
        email: "user@sigfarm.com",
        code: "123456",
        newPassword: "N3wPassw0rd!!",
      },
    });
    expect(complete.statusCode).toBe(200);
    expect(complete.json().data.updated).toBe(true);

    await app.close();
  });

  it("does not expose legacy MFA endpoints", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });

    const response = await app.inject({
      method: "GET",
      url: "/v1/auth/mfa/status",
      headers: {
        "x-test-auth-session": "ok",
      },
    });

    expect(response.statusCode).toBe(404);
    await app.close();
  });

  it("gets and updates account profile", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });

    const getProfile = await app.inject({
      method: "GET",
      url: "/v1/auth/account",
      headers: {
        "x-test-auth-session": "ok",
      },
    });
    expect(getProfile.statusCode).toBe(200);
    expect(getProfile.json().data.email).toBe("user@sigfarm.com");

    const updateProfile = await app.inject({
      method: "POST",
      url: "/v1/auth/account/profile",
      headers: {
        "x-test-auth-session": "ok",
      },
      payload: {
        name: "Novo Nome",
      },
    });
    expect(updateProfile.statusCode).toBe(200);
    expect(updateProfile.json().data.displayName).toBe("Novo Nome");

    await app.close();
  });

  it("requests and confirms email change with verification code", async () => {
    const app = await buildServer({ dependencies: buildDependencies() });

    const requestCode = await app.inject({
      method: "POST",
      url: "/v1/auth/account/email-change/request-code",
      headers: {
        "x-test-auth-session": "ok",
      },
      payload: {
        newEmail: "updated@sigfarm.com",
      },
    });
    expect(requestCode.statusCode).toBe(200);
    expect(requestCode.json().data.status).toBe("sent");

    const confirmInvalid = await app.inject({
      method: "POST",
      url: "/v1/auth/account/email-change/confirm-code",
      headers: {
        "x-test-auth-session": "ok",
      },
      payload: {
        newEmail: "updated@sigfarm.com",
        code: "000000",
      },
    });
    expect(confirmInvalid.statusCode).toBe(200);
    expect(confirmInvalid.json().data.updated).toBe(false);

    const confirmValid = await app.inject({
      method: "POST",
      url: "/v1/auth/account/email-change/confirm-code",
      headers: {
        "x-test-auth-session": "ok",
      },
      payload: {
        newEmail: "updated@sigfarm.com",
        code: "123456",
      },
    });
    expect(confirmValid.statusCode).toBe(200);
    expect(confirmValid.json().data.updated).toBe(true);

    await app.close();
  });

});
