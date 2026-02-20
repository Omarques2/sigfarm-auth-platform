import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthApiClient } from "../lib/auth-api";

const originalFetch = globalThis.fetch;

function mockJsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json",
    },
  });
}

describe("AuthApiClient", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("requests social sign-in URL via Better Auth endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse(200, {
        redirect: false,
        url: "https://login.microsoftonline.com/auth",
      }),
    );
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    const url = await client.startMicrosoftSignIn({
      callbackURL: "https://auth.sigfarmintelligence.com/auth/callback",
      errorCallbackURL: "https://auth.sigfarmintelligence.com/auth/callback",
    });

    expect(url).toBe("https://login.microsoftonline.com/auth");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [requestUrl, requestInit] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(requestUrl.toString()).toBe("https://auth.sigfarmintelligence.com/api/auth/sign-in/social");
    expect(requestInit.method).toBe("POST");
  });

  it("requests google social sign-in URL via Better Auth endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse(200, {
        redirect: false,
        url: "https://accounts.google.com/o/oauth2/v2/auth",
      }),
    );
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    const url = await client.startGoogleSignIn({
      callbackURL: "https://auth.sigfarmintelligence.com/auth/callback",
      errorCallbackURL: "https://auth.sigfarmintelligence.com/auth/callback",
    });

    expect(url).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [requestUrl, requestInit] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(requestUrl.toString()).toBe("https://auth.sigfarmintelligence.com/api/auth/sign-in/social");
    expect(requestInit.method).toBe("POST");
    expect(requestInit.body).toBe(
      JSON.stringify({
        provider: "google",
        callbackURL: "https://auth.sigfarmintelligence.com/auth/callback",
        errorCallbackURL: "https://auth.sigfarmintelligence.com/auth/callback",
        disableRedirect: true,
      }),
    );
  });

  it("returns null session on unauthorized response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse(401, {
        error: {
          message: "Unauthorized",
        },
      }),
    );
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    const session = await client.getSession();

    expect(session).toBeNull();
  });

  it("calls send verification email endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse(200, {
        status: true,
      }),
    );
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    await client.sendVerificationEmail({
      email: "user@sigfarm.com",
      callbackURL: "https://auth.sigfarmintelligence.com/auth/callback",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [requestUrl, requestInit] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(requestUrl.toString()).toBe(
      "https://auth.sigfarmintelligence.com/api/auth/send-verification-email",
    );
    expect(requestInit.method).toBe("POST");
    expect(requestInit.body).toBe(
      JSON.stringify({
        email: "user@sigfarm.com",
        callbackURL: "https://auth.sigfarmintelligence.com/auth/callback",
      }),
    );
  });

  it("calls email discover endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse(200, {
        data: {
          accountState: "active",
          retryAfterSeconds: 0,
        },
      }),
    );
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    const result = await client.discoverEmail("user@sigfarm.com");

    expect(result.accountState).toBe("active");
    const [requestUrl, requestInit] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(requestUrl.toString()).toBe("https://auth.sigfarmintelligence.com/v1/auth/email/discover");
    expect(requestInit.method).toBe("POST");
    expect(requestInit.body).toBe(JSON.stringify({ email: "user@sigfarm.com" }));
  });

  it("calls reset code endpoints", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        mockJsonResponse(200, {
          data: {
            status: "sent",
            retryAfterSeconds: 60,
          },
        }),
      )
      .mockResolvedValueOnce(
        mockJsonResponse(200, {
          data: {
            valid: true,
          },
        }),
      )
      .mockResolvedValueOnce(
        mockJsonResponse(200, {
          data: {
            updated: true,
          },
        }),
      );
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    const requested = await client.requestPasswordResetCode("user@sigfarm.com");
    expect(requested.status).toBe("sent");
    expect(requested.retryAfterSeconds).toBe(60);

    const verified = await client.verifyPasswordResetCode({
      email: "user@sigfarm.com",
      code: "123456",
    });
    expect(verified.valid).toBe(true);

    const completed = await client.completePasswordResetWithCode({
      email: "user@sigfarm.com",
      code: "123456",
      newPassword: "N3wPassw0rd!!",
    });
    expect(completed.updated).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("handles missing account when requesting reset code", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse(200, {
        data: {
          status: "missing",
          retryAfterSeconds: 0,
        },
      }),
    );
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    const requested = await client.requestPasswordResetCode("missing@sigfarm.com");
    expect(requested.status).toBe("missing");
    expect(requested.retryAfterSeconds).toBe(0);
  });

  it("calls sign-out endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse(200, {
        success: true,
      }),
    );
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    await client.signOut();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [requestUrl, requestInit] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(requestUrl.toString()).toBe("https://auth.sigfarmintelligence.com/api/auth/sign-out");
    expect(requestInit.method).toBe("POST");
  });

  it("calls refresh exchange endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockJsonResponse(200, { data: {} }));
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    await client.exchangeSession();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [requestUrl, requestInit] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(requestUrl.toString()).toBe("https://auth.sigfarmintelligence.com/v1/auth/refresh");
    expect(requestInit.method).toBe("POST");
    expect(requestInit.body).toBe("{}");
  });

  it("calls account profile and email-change endpoints", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        mockJsonResponse(200, {
          data: {
            userId: "11111111-1111-4111-8111-111111111111",
            email: "user@sigfarm.com",
            emailVerified: true,
            displayName: "Sigfarm User",
          },
        }),
      )
      .mockResolvedValueOnce(
        mockJsonResponse(200, {
          data: {
            userId: "11111111-1111-4111-8111-111111111111",
            email: "user@sigfarm.com",
            emailVerified: true,
            displayName: "Novo Nome",
          },
        }),
      )
      .mockResolvedValueOnce(
        mockJsonResponse(200, {
          data: {
            status: "sent",
            retryAfterSeconds: 60,
          },
        }),
      )
      .mockResolvedValueOnce(
        mockJsonResponse(200, {
          data: {
            updated: true,
          },
        }),
      );
    globalThis.fetch = fetchMock as typeof globalThis.fetch;

    const client = new AuthApiClient({
      authApiBaseUrl: "https://auth.sigfarmintelligence.com",
    });

    const account = await client.getAccountProfile();
    expect(account.email).toBe("user@sigfarm.com");

    const updatedProfile = await client.updateAccountProfile({ name: "Novo Nome" });
    expect(updatedProfile.displayName).toBe("Novo Nome");

    const requested = await client.requestEmailChangeCode("updated@sigfarm.com");
    expect(requested.status).toBe("sent");
    expect(requested.retryAfterSeconds).toBe(60);

    const confirmed = await client.confirmEmailChangeCode({
      newEmail: "updated@sigfarm.com",
      code: "123456",
    });
    expect(confirmed.updated).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });
});
