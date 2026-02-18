import {
  ErrorEnvelopeSchema,
  MeSuccessSchema,
  LogoutSuccessSchema,
  RefreshSuccessSchema,
  SessionSuccessSchema,
  type MeSuccess,
  type RefreshSuccess,
  type SessionSuccess,
} from "@sigfarm/auth-contracts";
import { z } from "zod";
import { AuthApiError, AuthContractError, readAuthErrorCode, readAuthErrorMessage } from "./errors.js";
import { resolveSafeReturnTo } from "./return-to.js";
import type {
  AuthClientConfig,
  AuthClientState,
  AuthTokenSnapshot,
  BuildLoginUrlInput,
  EnsureProfileResult,
  EnsureSessionResult,
  ExchangeSessionResult,
  RefreshSessionResult,
  SignInWithMicrosoftInput,
} from "./types.js";

type RequestOptions = {
  method: "GET" | "POST";
  body?: unknown;
  bearerToken?: string;
};

const socialSignInSchema = z.object({
  redirect: z.boolean(),
  url: z.string().url().optional(),
});

export class AuthClient {
  private readonly authApiRoot: URL;
  private readonly authApiAuthPath: URL;
  private readonly authPortalBase: URL;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly backgroundSkewSeconds: number;
  private readonly backgroundRetryDelaysMs: number[];
  private readonly onStateChange: ((state: AuthClientState) => void) | undefined;

  private tokenSnapshot: AuthTokenSnapshot | null = null;
  private refreshInFlight: Promise<AuthTokenSnapshot> | null = null;
  private backgroundTimer: ReturnType<typeof setTimeout> | null = null;
  private nextBackgroundRetryAttempt = 0;

  constructor(private readonly config: AuthClientConfig) {
    this.authApiRoot = new URL("/", config.authApiBaseUrl);
    this.authApiAuthPath = new URL("/api/auth/", config.authApiBaseUrl);
    this.authPortalBase = new URL("/", config.authPortalBaseUrl);
    this.fetchImpl = config.fetch ?? fetch;
    this.now = config.now ?? Date.now;
    this.backgroundSkewSeconds = Math.max(0, config.backgroundRefreshSkewSeconds ?? 30);
    this.backgroundRetryDelaysMs =
      config.backgroundRetryDelaysMs && config.backgroundRetryDelaysMs.length > 0
        ? [...config.backgroundRetryDelaysMs]
        : [1_000, 3_000, 8_000];
    this.onStateChange = config.onStateChange;
  }

  buildLoginUrl(input?: BuildLoginUrlInput): string {
    const safeReturnTo = resolveSafeReturnTo({
      returnTo: input?.returnTo,
      appBaseUrl: this.config.appBaseUrl,
      authPortalBaseUrl: this.config.authPortalBaseUrl,
      defaultReturnTo: this.config.defaultReturnTo,
      allowedOrigins: this.config.allowedReturnOrigins,
      ...(input?.referrer ? { referrer: input.referrer } : {}),
    });
    const loginUrl = new URL("/login", this.authPortalBase);
    loginUrl.searchParams.set("returnTo", safeReturnTo);
    return loginUrl.toString();
  }

  async startMicrosoftSignIn(input: SignInWithMicrosoftInput): Promise<string> {
    const response = await this.requestJson("api-auth/sign-in/social", {
      method: "POST",
      body: {
        provider: "microsoft",
        callbackURL: input.callbackURL,
        errorCallbackURL: input.errorCallbackURL,
        disableRedirect: true,
      },
    });

    const parsed = socialSignInSchema.parse(response);
    if (!parsed.url) {
      throw new AuthContractError({
        endpoint: "/api/auth/sign-in/social",
        message: "Missing social redirect URL",
        details: response,
      });
    }
    return parsed.url;
  }

  async exchangeSession(): Promise<ExchangeSessionResult> {
    const session = await this.refreshWithSingleFlight({ reason: "exchange", forceExchange: true });
    return { session };
  }

  async refreshSession(): Promise<RefreshSessionResult> {
    const session = await this.refreshWithSingleFlight({ reason: "manual", forceExchange: false });
    return { session };
  }

  async getAccessToken(): Promise<string | null> {
    if (!this.tokenSnapshot) return null;
    if (!this.isTokenFresh(this.tokenSnapshot, 5_000)) {
      try {
        await this.refreshWithSingleFlight({ reason: "manual", forceExchange: false });
      } catch {
        return null;
      }
    }
    return this.tokenSnapshot?.accessToken ?? null;
  }

  getTokenSnapshot(): AuthTokenSnapshot | null {
    return this.tokenSnapshot ? { ...this.tokenSnapshot } : null;
  }

  async ensureSession(): Promise<EnsureSessionResult> {
    const token = await this.getAccessToken();
    if (!token) return null;

    try {
      const payload = await this.requestJson("v1-auth/session", {
        method: "GET",
        bearerToken: token,
      });
      const parsed = SessionSuccessSchema.safeParse(payload);
      if (!parsed.success) {
        throw new AuthContractError({
          endpoint: "/v1/auth/session",
          message: "Invalid /v1/auth/session payload",
          details: parsed.error.flatten(),
        });
      }
      return parsed.data;
    } catch (error) {
      if (error instanceof AuthApiError && error.status === 401) {
        this.clearSession();
        return null;
      }
      throw error;
    }
  }

  async ensureProfile(): Promise<EnsureProfileResult> {
    const token = await this.getAccessToken();
    if (!token) return null;

    try {
      const payload = await this.requestJson("v1-auth/me", {
        method: "GET",
        bearerToken: token,
      });
      const parsed = MeSuccessSchema.safeParse(payload);
      if (!parsed.success) {
        throw new AuthContractError({
          endpoint: "/v1/auth/me",
          message: "Invalid /v1/auth/me payload",
          details: parsed.error.flatten(),
        });
      }
      return parsed.data;
    } catch (error) {
      if (error instanceof AuthApiError && error.status === 401) {
        this.clearSession();
        return null;
      }
      throw error;
    }
  }

  async authFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
    let token = await this.getAccessToken();

    if (!token) {
      try {
        await this.exchangeSession();
        token = this.tokenSnapshot?.accessToken ?? null;
      } catch {
        token = null;
      }
    }

    const firstAttempt = await this.fetchImpl(input, withAuthorization(init, token));
    if (firstAttempt.status !== 401) return firstAttempt;

    try {
      await this.refreshWithSingleFlight({ reason: "manual", forceExchange: false });
    } catch {
      return firstAttempt;
    }

    const updatedToken = this.tokenSnapshot?.accessToken ?? null;
    return await this.fetchImpl(input, withAuthorization(init, updatedToken));
  }

  async logout(): Promise<void> {
    const payload = {
      ...(this.tokenSnapshot?.refreshToken ? { refreshToken: this.tokenSnapshot.refreshToken } : {}),
    };
    try {
      const response = await this.requestJson("v1-auth/logout", {
        method: "POST",
        body: payload,
        ...(this.tokenSnapshot?.accessToken ? { bearerToken: this.tokenSnapshot.accessToken } : {}),
      });
      const parsed = LogoutSuccessSchema.safeParse(response);
      if (!parsed.success) {
        throw new AuthContractError({
          endpoint: "/v1/auth/logout",
          message: "Invalid /v1/auth/logout payload",
          details: parsed.error.flatten(),
        });
      }
    } catch {
      // Best effort logout: always clear local session even if network/server fails.
    }

    this.clearSession();
  }

  clearSession(): void {
    this.tokenSnapshot = null;
    this.nextBackgroundRetryAttempt = 0;
    this.clearBackgroundTimer();
    this.emitState({ status: "anonymous" });
  }

  destroy(): void {
    this.clearBackgroundTimer();
    this.refreshInFlight = null;
    this.tokenSnapshot = null;
  }

  private async refreshWithSingleFlight(input: {
    reason: "manual" | "background" | "exchange";
    forceExchange: boolean;
  }): Promise<AuthTokenSnapshot> {
    if (this.refreshInFlight) return this.refreshInFlight;

    this.emitState({ status: "refreshing", reason: input.reason });

    this.refreshInFlight = this.refreshInternal(input)
      .then((session) => {
        this.emitState({ status: "authenticated", session });
        return session;
      })
      .catch((error) => {
        const message = error instanceof Error ? error.message : "Authentication refresh failed";
        const code =
          error instanceof AuthContractError
            ? "CONTRACT"
            : error instanceof AuthApiError
              ? (error.code ?? "UNKNOWN")
              : error instanceof TypeError
                ? "NETWORK"
                : "UNKNOWN";
        this.emitState({ status: "error", code, message });
        throw error;
      })
      .finally(() => {
        this.refreshInFlight = null;
      });

    return this.refreshInFlight;
  }

  private async refreshInternal(input: { forceExchange: boolean }): Promise<AuthTokenSnapshot> {
    const body = this.buildRefreshRequestBody(input.forceExchange);
    const payload = await this.requestJson("v1-auth/refresh", {
      method: "POST",
      body,
    });

    const parsed = RefreshSuccessSchema.safeParse(payload);
    if (!parsed.success) {
      throw new AuthContractError({
        endpoint: "/v1/auth/refresh",
        message: "Invalid /v1/auth/refresh payload",
        details: parsed.error.flatten(),
      });
    }

    return this.updateTokenSnapshot(parsed.data);
  }

  private buildRefreshRequestBody(forceExchange: boolean): Record<string, string> {
    if (forceExchange) return {};

    if (this.tokenSnapshot?.refreshToken) {
      return {
        refreshToken: this.tokenSnapshot.refreshToken,
      };
    }

    return {};
  }

  private updateTokenSnapshot(payload: RefreshSuccess): AuthTokenSnapshot {
    const expiresAtEpochMs = this.now() + payload.data.expiresInSeconds * 1000;
    this.tokenSnapshot = {
      accessToken: payload.data.accessToken,
      refreshToken: payload.data.refreshToken,
      tokenType: payload.data.tokenType,
      expiresAtEpochMs,
      expiresInSeconds: payload.data.expiresInSeconds,
    };
    this.nextBackgroundRetryAttempt = 0;
    this.scheduleBackgroundRefresh();
    return this.tokenSnapshot;
  }

  private scheduleBackgroundRefresh(): void {
    if (!this.tokenSnapshot) return;

    const refreshInMs =
      this.tokenSnapshot.expiresAtEpochMs - this.now() - this.backgroundSkewSeconds * 1000;
    const delay = Math.max(0, refreshInMs);

    this.clearBackgroundTimer();
    this.backgroundTimer = setTimeout(() => {
      void this.runBackgroundRefresh();
    }, delay);
  }

  private async runBackgroundRefresh(): Promise<void> {
    try {
      await this.refreshWithSingleFlight({ reason: "background", forceExchange: false });
    } catch {
      const retryDelay = this.backgroundRetryDelaysMs[this.nextBackgroundRetryAttempt];
      if (retryDelay === undefined) {
        this.clearSession();
        return;
      }
      this.nextBackgroundRetryAttempt += 1;
      this.clearBackgroundTimer();
      this.backgroundTimer = setTimeout(() => {
        void this.runBackgroundRefresh();
      }, retryDelay);
    }
  }

  private clearBackgroundTimer(): void {
    if (!this.backgroundTimer) return;
    clearTimeout(this.backgroundTimer);
    this.backgroundTimer = null;
  }

  private isTokenFresh(snapshot: AuthTokenSnapshot, skewMs: number): boolean {
    return this.now() + skewMs < snapshot.expiresAtEpochMs;
  }

  private emitState(state: AuthClientState): void {
    this.onStateChange?.(state);
  }

  private async requestJson(target: "v1-auth/refresh" | "v1-auth/session" | "v1-auth/me" | "v1-auth/logout" | "api-auth/sign-in/social", options: RequestOptions): Promise<unknown> {
    const correlationId = createCorrelationId();
    const url = this.resolveUrl(target);
    const headers = new Headers({
      "x-correlation-id": correlationId,
    });
    if (options.body !== undefined) {
      headers.set("content-type", "application/json");
    }
    if (options.bearerToken) {
      headers.set("authorization", `Bearer ${options.bearerToken}`);
    }

    const response = await this.fetchImpl(url, {
      method: options.method,
      credentials: "include",
      headers,
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
    });

    const payload = await parseResponseBody(response);

    if (!response.ok) {
      const parsedError = ErrorEnvelopeSchema.safeParse(payload);
      const message =
        parsedError.success
          ? parsedError.data.error.message
          : readAuthErrorMessage(payload) ?? response.statusText ?? "Auth request failed";
      throw new AuthApiError({
        message,
        status: response.status,
        correlationId: response.headers.get("x-correlation-id") ?? correlationId,
        code: parsedError.success ? parsedError.data.error.code : readAuthErrorCode(payload),
        details: payload,
      });
    }

    return payload;
  }

  private resolveUrl(target: "v1-auth/refresh" | "v1-auth/session" | "v1-auth/me" | "v1-auth/logout" | "api-auth/sign-in/social"): URL {
    if (target.startsWith("api-auth/")) {
      return new URL(target.slice("api-auth/".length), this.authApiAuthPath);
    }
    return new URL(target.slice("v1-auth/".length), new URL("/v1/auth/", this.authApiRoot));
  }
}

export function createAuthClient(config: AuthClientConfig): AuthClient {
  return new AuthClient(config);
}

function withAuthorization(init: RequestInit, token: string | null): RequestInit {
  const headers = new Headers(init.headers ?? undefined);
  if (token) {
    headers.set("authorization", `Bearer ${token}`);
  }

  return {
    ...init,
    headers,
  };
}

async function parseResponseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function createCorrelationId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `cid-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
