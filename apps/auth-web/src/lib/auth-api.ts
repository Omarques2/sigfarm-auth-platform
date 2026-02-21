import { authWebEnv } from "../config/env";

export class AuthApiError extends Error {
  readonly status: number;
  readonly correlationId: string;
  readonly details: unknown;

  constructor(input: { message: string; status: number; correlationId: string; details?: unknown }) {
    super(input.message);
    this.name = "AuthApiError";
    this.status = input.status;
    this.correlationId = input.correlationId;
    this.details = input.details;
  }
}

type RequestOptions = {
  method: "GET" | "POST";
  body?: unknown;
};

type GetSessionResponse = {
  user: {
    id: string;
    email: string;
    name: string;
    emailVerified: boolean;
  };
  session: {
    id: string;
    userId: string;
    expiresAt: string;
  };
};

type SignInEmailInput = {
  email: string;
  password: string;
  callbackURL?: string;
};

type SignUpEmailInput = {
  name: string;
  email: string;
  password: string;
  callbackURL?: string;
};

type RequestPasswordResetInput = {
  email: string;
  redirectTo: string;
};

type SendVerificationEmailInput = {
  email: string;
  callbackURL?: string;
};

type DiscoverEmailResponse = {
  accountState: "missing" | "pending_verification" | "active";
  retryAfterSeconds: number;
};

type RequestPasswordResetCodeResponse = {
  status: "sent" | "cooldown";
  retryAfterSeconds: number;
};

type VerifyPasswordResetCodeInput = {
  email: string;
  code: string;
};

type VerifyPasswordResetCodeResponse = {
  valid: boolean;
};

type CompletePasswordResetWithCodeInput = {
  email: string;
  code: string;
  newPassword: string;
};

type CompletePasswordResetWithCodeResponse = {
  updated: boolean;
};

type SignInWithMicrosoftInput = {
  callbackURL: string;
  errorCallbackURL: string;
};

type SocialProvider = "microsoft" | "google";

type SignInWithSocialResult = {
  url?: string;
  redirect: boolean;
};

type AccountProfileResponse = {
  userId: string;
  email: string;
  emailVerified: boolean;
  displayName: string | null;
};

type UpdateAccountProfileInput = {
  name: string | null;
};

type RequestEmailChangeCodeResponse = {
  status: "sent" | "cooldown" | "same_as_current" | "already_in_use";
  retryAfterSeconds: number;
};

type ConfirmEmailChangeCodeInput = {
  newEmail: string;
  code: string;
};

type ConfirmEmailChangeCodeResponse = {
  updated: boolean;
  reason?: "invalid_or_expired" | "same_as_current" | "already_in_use";
};

type AuthApiClientConfig = {
  authApiBaseUrl: string;
};

const NETWORK_RETRY_ATTEMPTS = 1;
const NETWORK_RETRY_DELAY_MS = 220;

export class AuthApiClient {
  private readonly authBasePath: string;
  private readonly rootBasePath: string;

  constructor(private readonly config: AuthApiClientConfig) {
    this.authBasePath = new URL("/api/auth/", config.authApiBaseUrl).toString();
    this.rootBasePath = new URL("/", config.authApiBaseUrl).toString();
  }

  async getSession(): Promise<GetSessionResponse | null> {
    try {
      return await this.request<GetSessionResponse>("/get-session", {
        method: "GET",
      });
    } catch (error) {
      if (error instanceof AuthApiError && error.status === 401) {
        return null;
      }
      throw error;
    }
  }

  async signInEmail(input: SignInEmailInput): Promise<void> {
    await this.request("/sign-in/email", {
      method: "POST",
      body: {
        email: input.email,
        password: input.password,
        rememberMe: true,
        ...(input.callbackURL ? { callbackURL: input.callbackURL } : {}),
      },
    });
  }

  async signUpEmail(input: SignUpEmailInput): Promise<void> {
    await this.request("/sign-up/email", {
      method: "POST",
      body: {
        name: input.name,
        email: input.email,
        password: input.password,
        ...(input.callbackURL ? { callbackURL: input.callbackURL } : {}),
      },
    });
  }

  async verifyEmail(token: string): Promise<void> {
    await this.request(`/verify-email?token=${encodeURIComponent(token)}`, {
      method: "GET",
    });
  }

  async requestPasswordReset(input: RequestPasswordResetInput): Promise<void> {
    await this.request("/request-password-reset", {
      method: "POST",
      body: {
        email: input.email,
        redirectTo: input.redirectTo,
      },
    });
  }

  async discoverEmail(email: string): Promise<DiscoverEmailResponse> {
    const response = await this.rootRequest<{ data: DiscoverEmailResponse }>(
      "/v1/auth/email/discover",
      {
        method: "POST",
        body: {
          email,
        },
      },
    );
    return response.data;
  }

  async requestPasswordResetCode(email: string): Promise<RequestPasswordResetCodeResponse> {
    const response = await this.rootRequest<{ data: RequestPasswordResetCodeResponse }>(
      "/v1/auth/password-reset/request-code",
      {
        method: "POST",
        body: {
          email,
        },
      },
    );
    return response.data;
  }

  async verifyPasswordResetCode(
    input: VerifyPasswordResetCodeInput,
  ): Promise<VerifyPasswordResetCodeResponse> {
    const response = await this.rootRequest<{ data: VerifyPasswordResetCodeResponse }>(
      "/v1/auth/password-reset/verify-code",
      {
        method: "POST",
        body: {
          email: input.email,
          code: input.code,
        },
      },
    );
    return response.data;
  }

  async completePasswordResetWithCode(
    input: CompletePasswordResetWithCodeInput,
  ): Promise<CompletePasswordResetWithCodeResponse> {
    const response = await this.rootRequest<{ data: CompletePasswordResetWithCodeResponse }>(
      "/v1/auth/password-reset/complete-code",
      {
        method: "POST",
        body: {
          email: input.email,
          code: input.code,
          newPassword: input.newPassword,
        },
      },
    );
    return response.data;
  }

  async sendVerificationEmail(input: SendVerificationEmailInput): Promise<void> {
    await this.request("/send-verification-email", {
      method: "POST",
      body: {
        email: input.email,
        ...(input.callbackURL ? { callbackURL: input.callbackURL } : {}),
      },
    });
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    await this.request("/reset-password", {
      method: "POST",
      body: {
        token,
        newPassword,
      },
    });
  }

  async startMicrosoftSignIn(input: SignInWithMicrosoftInput): Promise<string> {
    return await this.startSocialSignIn("microsoft", input);
  }

  async startGoogleSignIn(input: SignInWithMicrosoftInput): Promise<string> {
    return await this.startSocialSignIn("google", input);
  }

  private async startSocialSignIn(
    provider: SocialProvider,
    input: SignInWithMicrosoftInput,
  ): Promise<string> {
    const response = await this.request<SignInWithSocialResult>("/sign-in/social", {
      method: "POST",
      body: {
        provider,
        callbackURL: input.callbackURL,
        errorCallbackURL: input.errorCallbackURL,
        disableRedirect: true,
      },
    });
    if (!response.url) {
      throw new Error(`${provider} sign-in endpoint did not return redirect URL`);
    }
    return response.url;
  }

  async exchangeSession(): Promise<void> {
    await this.rootRequest("/v1/auth/refresh", {
      method: "POST",
      body: {},
    });
  }

  async getAccountProfile(): Promise<AccountProfileResponse> {
    const response = await this.rootRequest<{ data: AccountProfileResponse }>(
      "/v1/auth/account",
      { method: "GET" },
    );
    return response.data;
  }

  async updateAccountProfile(input: UpdateAccountProfileInput): Promise<AccountProfileResponse> {
    const response = await this.rootRequest<{ data: AccountProfileResponse }>(
      "/v1/auth/account/profile",
      {
        method: "POST",
        body: {
          name: input.name,
        },
      },
    );
    return response.data;
  }

  async requestEmailChangeCode(newEmail: string): Promise<RequestEmailChangeCodeResponse> {
    const response = await this.rootRequest<{ data: RequestEmailChangeCodeResponse }>(
      "/v1/auth/account/email-change/request-code",
      {
        method: "POST",
        body: {
          newEmail,
        },
      },
    );
    return response.data;
  }

  async confirmEmailChangeCode(
    input: ConfirmEmailChangeCodeInput,
  ): Promise<ConfirmEmailChangeCodeResponse> {
    const response = await this.rootRequest<{ data: ConfirmEmailChangeCodeResponse }>(
      "/v1/auth/account/email-change/confirm-code",
      {
        method: "POST",
        body: {
          newEmail: input.newEmail,
          code: input.code,
        },
      },
    );
    return response.data;
  }

  async signOut(): Promise<void> {
    await this.request("/sign-out", {
      method: "POST",
      body: {},
    });
  }

  private async request<T>(path: string, options: RequestOptions): Promise<T> {
    const url = new URL(stripLeadingSlash(path), this.authBasePath);
    return await this.fetchJson<T>(url, options);
  }

  private async rootRequest<T>(path: string, options: RequestOptions): Promise<T> {
    const url = new URL(stripLeadingSlash(path), this.rootBasePath);
    return await this.fetchJson<T>(url, options);
  }

  private async fetchJson<T>(url: URL, options: RequestOptions): Promise<T> {
    const correlationId = createCorrelationId();
    const requestInit: RequestInit = {
      method: options.method,
      credentials: "include",
      headers: {
        "x-correlation-id": correlationId,
        ...(options.body ? { "content-type": "application/json" } : {}),
      },
      ...(options.body ? { body: JSON.stringify(options.body) } : {}),
    };
    const response = await this.fetchWithRetry(url, requestInit);

    const responseBody = await parseResponseBody(response);
    if (!response.ok) {
      throw new AuthApiError({
        message: readErrorMessage(responseBody) ?? response.statusText ?? "Auth API request failed",
        status: response.status,
        correlationId,
        details: responseBody,
      });
    }
    return responseBody as T;
  }

  private async fetchWithRetry(url: URL, requestInit: RequestInit): Promise<Response> {
    let attempt = 0;

    while (true) {
      try {
        return await fetch(url, requestInit);
      } catch (error) {
        if (!isRetryableNetworkError(error) || attempt >= NETWORK_RETRY_ATTEMPTS) {
          throw error;
        }

        attempt += 1;
        await sleep(NETWORK_RETRY_DELAY_MS * attempt);
      }
    }
  }
}

export const authApiClient = new AuthApiClient({
  authApiBaseUrl: authWebEnv.authApiBaseUrl,
});

function createCorrelationId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `cid-${Date.now()}-${Math.random().toString(16).slice(2)}`;
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

function readErrorMessage(value: unknown): string | null {
  if (typeof value === "string" && value.length > 0) return value;
  if (!value || typeof value !== "object") return null;

  const fromError = (value as { error?: { message?: unknown } }).error?.message;
  if (typeof fromError === "string" && fromError.length > 0) return fromError;

  const fromMessage = (value as { message?: unknown }).message;
  if (typeof fromMessage === "string" && fromMessage.length > 0) return fromMessage;

  return null;
}

function stripLeadingSlash(value: string): string {
  if (value.startsWith("/")) return value.slice(1);
  return value;
}

function isRetryableNetworkError(error: unknown): boolean {
  if (!(error instanceof TypeError)) return false;
  const message = error.message.toLowerCase();
  return message.includes("failed to fetch") || message.includes("network");
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
