import { CONTRACT_VERSION } from "@sigfarm/auth-contracts";
import { afterEach, describe, expect, it } from "vitest";
import { createAuthClient } from "../src/index.js";

const REAL_FETCH = globalThis.fetch;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json",
    },
  });
}

describe("contract tests: auth-client-vue <-> auth api", () => {
  afterEach(() => {
    globalThis.fetch = REAL_FETCH;
  });

  it("accepts canonical refresh/session/me/logout payloads", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);

      if (url.endsWith("/v1/auth/refresh")) {
        return jsonResponse({
          data: {
            accessToken: "access-token",
            refreshToken: "refresh-token",
            expiresInSeconds: 900,
            tokenType: "Bearer",
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-refresh",
          },
        });
      }

      if (url.endsWith("/v1/auth/session")) {
        return jsonResponse({
          data: {
            sessionId: "session-id",
            userId: "11111111-1111-4111-8111-111111111111",
            amr: "password",
            globalStatus: "active",
            issuedAt: "2026-02-18T16:00:00.000Z",
            expiresAt: "2026-02-18T17:00:00.000Z",
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-session",
          },
        });
      }

      if (url.endsWith("/v1/auth/me")) {
        return jsonResponse({
          data: {
            userId: "11111111-1111-4111-8111-111111111111",
            email: "user@sigfarm.com",
            emailVerified: true,
            displayName: "Sigfarm User",
            globalStatus: "active",
            apps: [{ appKey: "PBI_EMBED", roles: ["user"] }],
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-me",
          },
        });
      }

      if (url.endsWith("/v1/auth/logout")) {
        return jsonResponse({
          data: {
            revoked: true,
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-logout",
          },
        });
      }

      return new Response("not-found", { status: 404 });
    }) as typeof fetch;

    const client = createAuthClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
      authPortalBaseUrl: "https://auth.sigfarmintelligence.com",
      appBaseUrl: "https://bi.sigfarmintelligence.com",
      allowedReturnOrigins: ["https://bi.sigfarmintelligence.com"],
      defaultReturnTo: "https://bi.sigfarmintelligence.com/home",
    });

    await client.exchangeSession();
    const session = await client.ensureSession();
    const me = await client.ensureProfile();
    await client.logout();

    expect(session?.data.sessionId).toBe("session-id");
    expect(me?.data.email).toBe("user@sigfarm.com");
    expect(client.getTokenSnapshot()).toBeNull();
  });
});