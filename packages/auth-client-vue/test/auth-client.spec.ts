import { CONTRACT_VERSION } from "@sigfarm/auth-contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthClient, resolveSafeReturnTo } from "../src/index.js";

const REAL_FETCH = globalThis.fetch;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json",
    },
  });
}

describe("auth-client-vue", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    globalThis.fetch = REAL_FETCH;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("coalesces concurrent refresh calls with single-flight", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            accessToken: "access-initial",
            refreshToken: "refresh-initial",
            expiresInSeconds: 900,
            tokenType: "Bearer",
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-initial",
          },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            accessToken: "access-rotated",
            refreshToken: "refresh-rotated",
            expiresInSeconds: 900,
            tokenType: "Bearer",
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-rotated",
          },
        }),
      );
    globalThis.fetch = fetchMock;

    const client = createAuthClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
      authPortalBaseUrl: "https://auth.sigfarmintelligence.com",
      appBaseUrl: "https://bi.sigfarmintelligence.com",
      allowedReturnOrigins: ["https://bi.sigfarmintelligence.com"],
      defaultReturnTo: "https://bi.sigfarmintelligence.com/home",
    });

    await client.exchangeSession();
    await Promise.all([client.refreshSession(), client.refreshSession(), client.refreshSession()]);

    const refreshCalls = fetchMock.mock.calls.filter(([url]) =>
      String(url).includes("/v1/auth/refresh"),
    );
    expect(refreshCalls).toHaveLength(2);
    expect(client.getTokenSnapshot()?.accessToken).toBe("access-rotated");
  });

  it("retries background refresh after transient failure", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            accessToken: "access-initial",
            refreshToken: "refresh-initial",
            expiresInSeconds: 4,
            tokenType: "Bearer",
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-initial",
          },
        }),
      )
      .mockRejectedValueOnce(new Error("temporary network outage"))
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            accessToken: "access-recovered",
            refreshToken: "refresh-recovered",
            expiresInSeconds: 900,
            tokenType: "Bearer",
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-recovered",
          },
        }),
      );
    globalThis.fetch = fetchMock;

    const client = createAuthClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
      authPortalBaseUrl: "https://auth.sigfarmintelligence.com",
      appBaseUrl: "https://bi.sigfarmintelligence.com",
      allowedReturnOrigins: ["https://bi.sigfarmintelligence.com"],
      defaultReturnTo: "https://bi.sigfarmintelligence.com/home",
      backgroundRefreshSkewSeconds: 1,
      backgroundRetryDelaysMs: [100, 200],
    });

    await client.exchangeSession();

    await vi.advanceTimersByTimeAsync(3100);
    await vi.advanceTimersByTimeAsync(120);

    expect(client.getTokenSnapshot()?.accessToken).toBe("access-recovered");
    const refreshCalls = fetchMock.mock.calls.filter(([url]) =>
      String(url).includes("/v1/auth/refresh"),
    );
    expect(refreshCalls).toHaveLength(3);
  });

  it("attaches bearer token and retries once after 401", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            accessToken: "access-1",
            refreshToken: "refresh-1",
            expiresInSeconds: 900,
            tokenType: "Bearer",
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-1",
          },
        }),
      )
      .mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }))
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            accessToken: "access-2",
            refreshToken: "refresh-2",
            expiresInSeconds: 900,
            tokenType: "Bearer",
          },
          meta: {
            contractVersion: CONTRACT_VERSION,
            correlationId: "corr-2",
          },
        }),
      )
      .mockResolvedValueOnce(new Response("ok", { status: 200 }));
    globalThis.fetch = fetchMock;

    const client = createAuthClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
      authPortalBaseUrl: "https://auth.sigfarmintelligence.com",
      appBaseUrl: "https://bi.sigfarmintelligence.com",
      allowedReturnOrigins: ["https://bi.sigfarmintelligence.com"],
      defaultReturnTo: "https://bi.sigfarmintelligence.com/home",
    });

    await client.exchangeSession();
    const response = await client.authFetch("https://api.sigfarmintelligence.com/private");

    expect(response.status).toBe(200);
    const protectedCalls = fetchMock.mock.calls.filter(([url]) =>
      String(url).includes("api.sigfarmintelligence.com/private"),
    );
    expect(protectedCalls).toHaveLength(2);

    const secondAttemptHeaders = new Headers(protectedCalls[1]?.[1]?.headers);
    expect(secondAttemptHeaders.get("authorization")).toBe("Bearer access-2");
  });

  it("throws contract error when refresh payload is invalid", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({
        data: {
          accessToken: "missing-fields",
        },
        meta: {
          contractVersion: CONTRACT_VERSION,
          correlationId: "corr-invalid",
        },
      }),
    );
    globalThis.fetch = fetchMock;

    const client = createAuthClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
      authPortalBaseUrl: "https://auth.sigfarmintelligence.com",
      appBaseUrl: "https://bi.sigfarmintelligence.com",
      allowedReturnOrigins: ["https://bi.sigfarmintelligence.com"],
      defaultReturnTo: "https://bi.sigfarmintelligence.com/home",
    });

    await expect(client.exchangeSession()).rejects.toMatchObject({
      name: "AuthContractError",
    });
  });

  it("builds login URL with safe return target", () => {
    const client = createAuthClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
      authPortalBaseUrl: "https://auth.sigfarmintelligence.com",
      appBaseUrl: "https://bi.sigfarmintelligence.com",
      allowedReturnOrigins: ["https://bi.sigfarmintelligence.com", "https://landwatch.sigfarmintelligence.com"],
      defaultReturnTo: "https://bi.sigfarmintelligence.com/home",
    });

    const safeTarget = resolveSafeReturnTo({
      returnTo: "https://evil.local/phish",
      appBaseUrl: "https://bi.sigfarmintelligence.com",
      allowedOrigins: ["https://bi.sigfarmintelligence.com", "https://landwatch.sigfarmintelligence.com"],
      defaultReturnTo: "https://bi.sigfarmintelligence.com/home",
    });
    expect(safeTarget).toBe("https://bi.sigfarmintelligence.com/home");

    const loginUrl = client.buildLoginUrl({ returnTo: "https://landwatch.sigfarmintelligence.com/dashboard" });
    expect(loginUrl).toContain("https://auth.sigfarmintelligence.com/login");
    expect(loginUrl).toContain("returnTo=");
  });
});