export { AuthClient, createAuthClient } from "./auth-client.js";
export { AuthApiError, AuthContractError, readAuthErrorCode, readAuthErrorMessage } from "./errors.js";
export { resolveSafeReturnTo } from "./return-to.js";
export type {
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