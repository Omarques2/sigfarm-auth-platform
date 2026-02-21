import { z } from "zod";

const NODE_ENV_VALUES = ["development", "test", "staging", "production"] as const;
const EMAIL_PROVIDER_VALUES = ["console", "azure-acs"] as const;

function parseCsv(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue;
  return value === "true";
}

function parseOptionalString(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

const envSchema = z.object({
  NODE_ENV: z.enum(NODE_ENV_VALUES).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  BETTER_AUTH_BASE_URL: z.string().url().optional(),
  BETTER_AUTH_SECRET: z.string().min(24).optional(),
  BETTER_AUTH_TRUSTED_ORIGINS: z.string().optional(),
  ENTRA_CLIENT_ID: z.string().min(1).optional(),
  ENTRA_CLIENT_SECRET: z.string().min(1).optional(),
  ENTRA_TENANT_ID: z.string().min(1).optional(),
  GOOGLE_CLIENT_ID: z.string().min(1).optional(),
  GOOGLE_CLIENT_SECRET: z.string().min(1).optional(),
  AUTH_ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  AUTH_REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 30),
  AUTH_JWT_ISSUER: z.string().url().optional(),
  AUTH_JWT_AUDIENCE: z.string().min(1).default("sigfarm-apps"),
  AUTH_JWT_KID: z.string().min(1).default("sigfarm-auth-k1"),
  AUTH_JWT_PRIVATE_KEY_PEM: z.string().optional(),
  AUTH_JWT_PUBLIC_KEY_PEM: z.string().optional(),
  AUTH_RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().positive().default(60),
  AUTH_RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(60),
  AUTH_RATE_LIMIT_LOGIN_MAX_REQUESTS: z.coerce.number().int().positive().default(10),
  AUTH_REQUIRE_EMAIL_VERIFICATION: z.string().optional(),
  AUTH_PWNED_PASSWORD_CHECK_ENABLED: z.string().optional(),
  AUTH_PWNED_PASSWORD_CHECK_TIMEOUT_MS: z.coerce.number().int().positive().default(1_800),
  EMAIL_PROVIDER: z.enum(EMAIL_PROVIDER_VALUES).optional(),
  ACS_EMAIL_CONNECTION_STRING: z.string().optional(),
  ACS_EMAIL_SENDER: z.string().optional(),
  ACS_EMAIL_REPLY_TO: z.string().optional(),
  AUTH_EMAIL_VERIFY_PAGE_URL: z.string().url().optional(),
  AUTH_EMAIL_RESET_PAGE_URL: z.string().url().optional(),
  AUTH_EMAIL_SEND_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  AUTH_EMAIL_RETRY_ATTEMPTS: z.coerce.number().int().positive().default(3),
  AUTH_EMAIL_RETRY_BASE_DELAY_MS: z.coerce.number().int().positive().default(250),
  AUTH_RESET_CODE_TTL_SECONDS: z.coerce.number().int().positive().default(10 * 60),
  AUTH_RESEND_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(60),
});

export type AppEnv = {
  nodeEnv: (typeof NODE_ENV_VALUES)[number];
  port: number;
  betterAuthBaseUrl: string;
  betterAuthSecret: string;
  betterAuthTrustedOrigins: string[];
  entraClientId?: string;
  entraClientSecret?: string;
  entraTenantId?: string;
  googleClientId?: string;
  googleClientSecret?: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  jwtIssuer: string;
  jwtAudience: string;
  jwtKid: string;
  jwtPrivateKeyPem?: string;
  jwtPublicKeyPem?: string;
  rateLimitWindowSeconds: number;
  rateLimitMaxRequests: number;
  rateLimitLoginMaxRequests: number;
  requireEmailVerification: boolean;
  authPwnedPasswordCheckEnabled?: boolean;
  authPwnedPasswordCheckTimeoutMs?: number;
  emailProvider?: (typeof EMAIL_PROVIDER_VALUES)[number];
  acsEmailConnectionString?: string;
  acsEmailSender?: string;
  acsEmailReplyTo?: string;
  authEmailVerifyPageUrl: string;
  authEmailResetPageUrl: string;
  authEmailSendTimeoutMs: number;
  authEmailRetryAttempts: number;
  authEmailRetryBaseDelayMs: number;
  authResetCodeTtlSeconds: number;
  authResendCooldownSeconds: number;
};

export function loadEnv(rawEnv: NodeJS.ProcessEnv = process.env): AppEnv {
  const parsed = envSchema.parse(rawEnv);
  const baseUrl = parsed.BETTER_AUTH_BASE_URL ?? `http://localhost:${parsed.PORT}`;
  const isProduction = parsed.NODE_ENV === "production";
  const acsEmailConnectionString = parseOptionalString(parsed.ACS_EMAIL_CONNECTION_STRING);
  const acsEmailSender = parseOptionalString(parsed.ACS_EMAIL_SENDER);
  const acsEmailReplyTo = parseOptionalString(parsed.ACS_EMAIL_REPLY_TO);
  const authEmailVerifyPageUrl = parsed.AUTH_EMAIL_VERIFY_PAGE_URL ?? `${baseUrl}/verify-email`;
  const authEmailResetPageUrl = parsed.AUTH_EMAIL_RESET_PAGE_URL ?? `${baseUrl}/reset-password`;
  const betterAuthSecret =
    parsed.BETTER_AUTH_SECRET ??
    (isProduction ? "" : "dev-only-secret-change-me-dev-only-secret");

  if (isProduction && betterAuthSecret.length < 24) {
    throw new Error("BETTER_AUTH_SECRET is required in production and must be at least 24 chars");
  }

  return {
    nodeEnv: parsed.NODE_ENV,
    port: parsed.PORT,
    betterAuthBaseUrl: baseUrl,
    betterAuthSecret,
    betterAuthTrustedOrigins: parseCsv(parsed.BETTER_AUTH_TRUSTED_ORIGINS),
    ...(parsed.ENTRA_CLIENT_ID ? { entraClientId: parsed.ENTRA_CLIENT_ID } : {}),
    ...(parsed.ENTRA_CLIENT_SECRET ? { entraClientSecret: parsed.ENTRA_CLIENT_SECRET } : {}),
    ...(parsed.ENTRA_TENANT_ID ? { entraTenantId: parsed.ENTRA_TENANT_ID } : {}),
    ...(parsed.GOOGLE_CLIENT_ID ? { googleClientId: parsed.GOOGLE_CLIENT_ID } : {}),
    ...(parsed.GOOGLE_CLIENT_SECRET ? { googleClientSecret: parsed.GOOGLE_CLIENT_SECRET } : {}),
    accessTokenTtlSeconds: parsed.AUTH_ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTtlSeconds: parsed.AUTH_REFRESH_TOKEN_TTL_SECONDS,
    jwtIssuer: parsed.AUTH_JWT_ISSUER ?? baseUrl,
    jwtAudience: parsed.AUTH_JWT_AUDIENCE,
    jwtKid: parsed.AUTH_JWT_KID,
    ...(parsed.AUTH_JWT_PRIVATE_KEY_PEM
      ? { jwtPrivateKeyPem: parsed.AUTH_JWT_PRIVATE_KEY_PEM }
      : {}),
    ...(parsed.AUTH_JWT_PUBLIC_KEY_PEM ? { jwtPublicKeyPem: parsed.AUTH_JWT_PUBLIC_KEY_PEM } : {}),
    rateLimitWindowSeconds: parsed.AUTH_RATE_LIMIT_WINDOW_SECONDS,
    rateLimitMaxRequests: parsed.AUTH_RATE_LIMIT_MAX_REQUESTS,
    rateLimitLoginMaxRequests: parsed.AUTH_RATE_LIMIT_LOGIN_MAX_REQUESTS,
    requireEmailVerification: parseBoolean(parsed.AUTH_REQUIRE_EMAIL_VERIFICATION, true),
    authPwnedPasswordCheckEnabled: parseBoolean(
      parsed.AUTH_PWNED_PASSWORD_CHECK_ENABLED,
      parsed.NODE_ENV !== "test",
    ),
    authPwnedPasswordCheckTimeoutMs: parsed.AUTH_PWNED_PASSWORD_CHECK_TIMEOUT_MS,
    ...(parsed.EMAIL_PROVIDER ? { emailProvider: parsed.EMAIL_PROVIDER } : {}),
    ...(acsEmailConnectionString ? { acsEmailConnectionString } : {}),
    ...(acsEmailSender ? { acsEmailSender } : {}),
    ...(acsEmailReplyTo ? { acsEmailReplyTo } : {}),
    authEmailVerifyPageUrl,
    authEmailResetPageUrl,
    authEmailSendTimeoutMs: parsed.AUTH_EMAIL_SEND_TIMEOUT_MS,
    authEmailRetryAttempts: parsed.AUTH_EMAIL_RETRY_ATTEMPTS,
    authEmailRetryBaseDelayMs: parsed.AUTH_EMAIL_RETRY_BASE_DELAY_MS,
    authResetCodeTtlSeconds: parsed.AUTH_RESET_CODE_TTL_SECONDS,
    authResendCooldownSeconds: parsed.AUTH_RESEND_COOLDOWN_SECONDS,
  };
}
