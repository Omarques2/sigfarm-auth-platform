import type { AuthErrorCode, MeSuccess, RefreshSuccess, SessionSuccess } from "@sigfarm/auth-contracts";

export type AuthFetch = typeof fetch;

export type AuthTokenSnapshot = {
  accessToken: string;
  refreshToken: string;
  tokenType: RefreshSuccess["data"]["tokenType"];
  expiresAtEpochMs: number;
  expiresInSeconds: number;
};

export type AuthClientConfig = {
  authApiBaseUrl: string;
  authPortalBaseUrl: string;
  appBaseUrl: string;
  allowedReturnOrigins: string[];
  defaultReturnTo: string;
  backgroundRefreshSkewSeconds?: number;
  backgroundRetryDelaysMs?: number[];
  fetch?: AuthFetch;
  now?: () => number;
  onStateChange?: (state: AuthClientState) => void;
};

export type AuthClientState =
  | { status: "anonymous" }
  | { status: "authenticated"; session: AuthTokenSnapshot }
  | { status: "refreshing"; reason: "manual" | "background" | "exchange" }
  | { status: "error"; code: AuthErrorCode | "NETWORK" | "CONTRACT" | "UNKNOWN"; message: string };

export type BuildLoginUrlInput = {
  returnTo?: string | null;
  referrer?: string;
};

export type ExchangeSessionResult = {
  session: AuthTokenSnapshot;
};

export type RefreshSessionResult = {
  session: AuthTokenSnapshot;
};

export type EnsureSessionResult = SessionSuccess | null;

export type EnsureProfileResult = MeSuccess | null;

export type SignInWithMicrosoftInput = {
  callbackURL: string;
  errorCallbackURL: string;
};