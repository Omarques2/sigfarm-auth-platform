import { hash, verify } from "@node-rs/argon2";
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { toNodeHandler } from "better-auth/node";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { PrismaClient } from "@prisma/client";
import type { AppEnv } from "../config/env.js";
import type { EmailProvider } from "../email/email.provider.js";
import type { AuditEventInput, AuditService } from "./audit.service.js";
import type { AuthUser, IdentityService } from "./identity.service.js";
import { mapMicrosoftProfileToUser } from "./microsoft-profile.js";
import {
  DEFAULT_PWNED_PASSWORD_TIMEOUT_MS,
  PASSWORD_COMPROMISED_MESSAGE,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  PASSWORD_POLICY_MESSAGE,
  isPasswordCompromised,
  isPasswordPolicyCompliant,
} from "./password-policy.js";

export type AuthGatewaySession = {
  user: AuthUser;
};

export interface AuthGateway {
  mount(app: FastifyInstance): Promise<void> | void;
  getSession(headers: Headers): Promise<AuthGatewaySession | null>;
  signOut(headers: Headers): Promise<void>;
}

type CreateAuthGatewayOptions = {
  env: AppEnv;
  prisma: PrismaClient;
  identityService: IdentityService;
  auditService: AuditService;
  emailProvider: EmailProvider;
};

export function createBetterAuthGateway(options: CreateAuthGatewayOptions): AuthGateway {
  const allowedCorsOrigins = buildAllowedCorsOrigins(
    options.env.betterAuthTrustedOrigins,
    options.env.betterAuthBaseUrl,
  );
  const socialProviders = {
    ...(options.env.entraClientId && options.env.entraClientSecret && options.env.entraTenantId
      ? {
          microsoft: {
            clientId: options.env.entraClientId,
            clientSecret: options.env.entraClientSecret,
            tenantId: options.env.entraTenantId,
            mapProfileToUser: mapMicrosoftProfileToUser,
          },
        }
      : {}),
    ...(options.env.googleClientId && options.env.googleClientSecret
      ? {
          google: {
            clientId: options.env.googleClientId,
            clientSecret: options.env.googleClientSecret,
          },
        }
      : {}),
  };

  const auth = betterAuth({
    baseURL: options.env.betterAuthBaseUrl,
    basePath: "/api/auth",
    secret: options.env.betterAuthSecret,
    trustedOrigins: options.env.betterAuthTrustedOrigins,
    database: prismaAdapter(options.prisma, {
      provider: "postgresql",
      transaction: true,
    }),
    advanced: {
      useSecureCookies: options.env.nodeEnv === "production",
      database: {
        generateId: false,
      },
    },
    rateLimit: {
      enabled: true,
      window: options.env.rateLimitWindowSeconds,
      max: options.env.rateLimitMaxRequests,
      storage: "database",
      modelName: "rateLimit",
      customRules: {
        "/sign-in/email": {
          window: options.env.rateLimitWindowSeconds,
          max: options.env.rateLimitLoginMaxRequests,
        },
        "/request-password-reset": {
          window: options.env.rateLimitWindowSeconds,
          max: options.env.rateLimitLoginMaxRequests,
        },
        "/verify-email": {
          window: options.env.rateLimitWindowSeconds,
          max: options.env.rateLimitLoginMaxRequests,
        },
      },
    },
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: options.env.requireEmailVerification,
      minPasswordLength: PASSWORD_MIN_LENGTH,
      maxPasswordLength: PASSWORD_MAX_LENGTH,
      revokeSessionsOnPasswordReset: true,
      password: {
        hash: (password) =>
          hash(password, {
            algorithm: 2,
            memoryCost: 19456,
            timeCost: 2,
            parallelism: 1,
            outputLen: 32,
          }),
        verify: async ({ hash: passwordHash, password }) => verify(passwordHash, password),
      },
      sendResetPassword: async ({ user, token }, request) => {
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
        await options.identityService.registerEmailToken({
          userId: user.id,
          token,
          tokenType: "reset",
          expiresAt,
        });
        const correlationId = resolveCorrelationIdFromRequest(request);
        runInBackground(async () => {
          await options.emailProvider.sendResetPasswordEmail({
            to: user.email,
            token,
            correlationId,
          });
        }, "password-reset-email");
        await options.auditService.record({
          eventType: "auth.password_reset.requested",
          actorUserId: user.id,
          payload: {
            email: user.email,
          },
          ...auditMetaFromRequest(request),
        });
      },
      onPasswordReset: async ({ user }, request) => {
        await options.identityService.consumeLatestResetToken(user.id);
        const correlationId = resolveCorrelationIdFromRequest(request);
        runInBackground(async () => {
          await options.emailProvider.sendPasswordChangedAlert({
            to: user.email,
            correlationId,
          });
        }, "password-changed-alert");
        await options.auditService.record({
          eventType: "auth.password_reset.completed",
          actorUserId: user.id,
          payload: {
            email: user.email,
          },
          ...auditMetaFromRequest(request),
        });
      },
    },
    emailVerification: {
      sendOnSignUp: true,
      sendOnSignIn: true,
      expiresIn: 60 * 60,
      sendVerificationEmail: async ({ user, token }, request) => {
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
        await options.identityService.registerEmailToken({
          userId: user.id,
          token,
          tokenType: "verify",
          expiresAt,
        });
        const correlationId = resolveCorrelationIdFromRequest(request);
        runInBackground(async () => {
          await options.emailProvider.sendVerificationEmail({
            to: user.email,
            token,
            correlationId,
          });
        }, "email-verification");
        await options.auditService.record({
          eventType: "auth.email_verification.requested",
          actorUserId: user.id,
          payload: {
            email: user.email,
          },
          ...auditMetaFromRequest(request),
        });
      },
      beforeEmailVerification: async (user, request) => {
        const token = extractTokenFromRequest(request);
        if (!token) return;
        await options.identityService.validateUnusedEmailToken({
          userId: user.id,
          token,
          tokenType: "verify",
        });
      },
      afterEmailVerification: async (user, request) => {
        const token = extractTokenFromRequest(request);
        if (token) {
          await options.identityService.consumeEmailToken({
            userId: user.id,
            token,
            tokenType: "verify",
          });
        }
        await options.identityService.markEmailVerified(user.id);
        await options.auditService.record({
          eventType: "auth.email_verification.completed",
          actorUserId: user.id,
          payload: {
            email: user.email,
          },
          ...auditMetaFromRequest(request),
        });
      },
    },
    ...(Object.keys(socialProviders).length > 0 ? { socialProviders } : {}),
    account: {
      accountLinking: {
        enabled: true,
        trustedProviders: ["microsoft", "google", "email-password"],
        allowDifferentEmails: false,
      },
      encryptOAuthTokens: true,
    },
    onAPIError: {
      onError: async (error) => {
        const errorMessage =
          error instanceof Error ? error.message : typeof error === "string" ? error : "unknown";
        await options.auditService.record({
          eventType: "auth.api.error",
          payload: { message: errorMessage },
        });
      },
    },
    databaseHooks: {
      user: {
        create: {
          after: async (user) => {
            await options.identityService.ensureFromAuthUser({
              id: user.id,
              email: user.email,
              emailVerified: user.emailVerified,
              name: user.name,
            });
            await options.auditService.record({
              eventType: "auth.user.created",
              actorUserId: user.id,
              payload: { email: user.email },
            });
          },
        },
        update: {
          after: async (user) => {
            await options.identityService.ensureFromAuthUser({
              id: user.id,
              email: user.email,
              emailVerified: user.emailVerified,
              name: user.name,
            });
          },
        },
      },
      account: {
        create: {
          after: async (account) => {
            await options.identityService.syncProviderAccount({
              userId: account.userId,
              providerId: account.providerId,
              accountId: account.accountId,
              ...(account.password ? { passwordHash: account.password } : {}),
            });
            await options.auditService.record({
              eventType: "auth.account.linked",
              actorUserId: account.userId,
              payload: {
                provider: account.providerId,
              },
            });
          },
        },
        update: {
          after: async (account) => {
            await options.identityService.syncProviderAccount({
              userId: account.userId,
              providerId: account.providerId,
              accountId: account.accountId,
              ...(account.password ? { passwordHash: account.password } : {}),
            });
          },
        },
      },
      session: {
        create: {
          after: async (session) => {
            await options.auditService.record({
              eventType: "auth.session.created",
              actorUserId: session.userId,
              payload: {
                sessionToken: session.token.slice(0, 8),
              },
              ...(session.ipAddress ? { ip: session.ipAddress } : {}),
              ...(session.userAgent ? { userAgent: session.userAgent } : {}),
            });
          },
        },
        delete: {
          after: async (session) => {
            await options.auditService.record({
              eventType: "auth.session.deleted",
              actorUserId: session.userId,
              payload: {
                sessionToken: session.token.slice(0, 8),
              },
            });
          },
        },
      },
    },
  });

  return {
    async mount(app: FastifyInstance): Promise<void> {
      const nodeHandler = toNodeHandler(auth.handler);
      app.route({
        method: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        url: "/api/auth/*",
        config: {
          rateLimit: {
            max: options.env.rateLimitLoginMaxRequests,
            timeWindow: `${options.env.rateLimitWindowSeconds} second`,
          },
        },
        handler: async (request, reply) => {
          applyCorsHeaders(request, reply, allowedCorsOrigins);
          if (request.method === "OPTIONS") {
            reply.code(204).send();
            return;
          }
          const violation = await readPasswordPolicyViolation(request, options.env);
          if (violation) {
            reply.code(422).send({
              error: {
                code: violation.code,
                message: violation.message,
              },
            });
            return;
          }
          const nodeRequest = request.raw as typeof request.raw & { body?: unknown };
          if (request.body !== undefined) {
            nodeRequest.body = request.body;
          }
          reply.hijack();
          try {
            await nodeHandler(nodeRequest, reply.raw);
          } catch (error) {
            request.log.error({ err: error }, "better-auth route handler failed");
            writeAuthGatewayInternalError(request, reply);
          }
        },
      });
    },
    async getSession(headers: Headers): Promise<AuthGatewaySession | null> {
      const session = await auth.api.getSession({ headers });
      if (!session) return null;
      return {
        user: {
          id: session.user.id,
          email: session.user.email,
          emailVerified: session.user.emailVerified,
          name: session.user.name,
        },
      };
    },
    async signOut(headers: Headers): Promise<void> {
      await auth.api.signOut({ headers });
    },
  };
}

type PasswordPolicyViolation = {
  code: "PASSWORD_POLICY_VIOLATION" | "PASSWORD_COMPROMISED";
  message: string;
};

async function readPasswordPolicyViolation(
  request: FastifyRequest,
  env: AppEnv,
): Promise<PasswordPolicyViolation | null> {
  if (request.method !== "POST") return null;
  const endpoint = readRequestPathname(request.url);
  if (endpoint !== "/api/auth/sign-up/email" && endpoint !== "/api/auth/reset-password") {
    return null;
  }

  const payload = readBodyObject(request.body);
  if (!payload) return null;

  const fieldName = endpoint === "/api/auth/sign-up/email" ? "password" : "newPassword";
  const value = payload[fieldName];
  if (typeof value !== "string") return null;

  if (!isPasswordPolicyCompliant(value)) {
    return {
      code: "PASSWORD_POLICY_VIOLATION",
      message: PASSWORD_POLICY_MESSAGE,
    };
  }

  const compromised = await isPasswordCompromised(value, {
    enabled: env.authPwnedPasswordCheckEnabled ?? env.nodeEnv !== "test",
    timeoutMs: env.authPwnedPasswordCheckTimeoutMs ?? DEFAULT_PWNED_PASSWORD_TIMEOUT_MS,
  });

  if (!compromised) {
    return null;
  }

  return {
    code: "PASSWORD_COMPROMISED",
    message: PASSWORD_COMPROMISED_MESSAGE,
  };
}

function readRequestPathname(rawUrl: string): string {
  try {
    return new URL(rawUrl, "http://localhost").pathname;
  } catch {
    return rawUrl;
  }
}

function readBodyObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object") return null;
  return value as Record<string, unknown>;
}

function extractTokenFromRequest(request?: Request): string | undefined {
  if (!request) return undefined;
  const url = new URL(request.url);
  return url.searchParams.get("token") ?? undefined;
}

function auditMetaFromRequest(request?: Request): Pick<AuditEventInput, "ip" | "userAgent"> {
  if (!request) return {};
  const ip = request.headers.get("x-forwarded-for");
  const userAgent = request.headers.get("user-agent");
  return {
    ...(ip ? { ip } : {}),
    ...(userAgent ? { userAgent } : {}),
  };
}

function resolveCorrelationIdFromRequest(request?: Request): string {
  const correlationId = request?.headers.get("x-correlation-id")?.trim();
  if (correlationId) return correlationId;
  return crypto.randomUUID();
}

function runInBackground(task: () => Promise<void>, taskName: string): void {
  void task().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    // eslint-disable-next-line no-console
    console.error("[auth-background-task:error]", {
      taskName,
      message,
    });
  });
}

function writeAuthGatewayInternalError(request: FastifyRequest, reply: FastifyReply): void {
  const rawResponse = reply.raw;
  if (rawResponse.writableEnded) {
    return;
  }

  const correlationId = resolveGatewayCorrelationId(request, reply);
  const payload = JSON.stringify({
    code: "AUTH_INTERNAL_ERROR",
    message: "Authentication gateway request failed",
    correlationId,
  });

  if (!rawResponse.headersSent) {
    rawResponse.statusCode = 500;
    rawResponse.setHeader("content-type", "application/json; charset=utf-8");
    rawResponse.setHeader("content-length", Buffer.byteLength(payload).toString());
  }
  rawResponse.end(payload);
}

function resolveGatewayCorrelationId(request: FastifyRequest, reply: FastifyReply): string {
  const fromReplyHeader = reply.raw.getHeader("x-correlation-id");
  if (typeof fromReplyHeader === "string" && fromReplyHeader.trim().length > 0) {
    return fromReplyHeader;
  }
  const fromRequestHeader = request.headers["x-correlation-id"];
  if (typeof fromRequestHeader === "string" && fromRequestHeader.trim().length > 0) {
    return fromRequestHeader;
  }
  return crypto.randomUUID();
}

function applyCorsHeaders(
  request: FastifyRequest,
  reply: FastifyReply,
  allowedOrigins: Set<string>,
): void {
  const requestOrigin = normalizeOrigin(
    typeof request.headers.origin === "string" ? request.headers.origin : undefined,
  );
  if (!requestOrigin || !allowedOrigins.has(requestOrigin)) {
    return;
  }

  const rawResponse = reply.raw;
  rawResponse.setHeader("access-control-allow-origin", requestOrigin);
  rawResponse.setHeader("access-control-allow-credentials", "true");
  rawResponse.setHeader("access-control-allow-methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS");

  const requestedHeaders = request.headers["access-control-request-headers"];
  if (typeof requestedHeaders === "string" && requestedHeaders.trim().length > 0) {
    rawResponse.setHeader("access-control-allow-headers", requestedHeaders);
  }

  rawResponse.setHeader("vary", appendVaryHeader(rawResponse.getHeader("vary"), "Origin"));
}

function buildAllowedCorsOrigins(trustedOrigins: string[], baseUrl: string): Set<string> {
  const allowed = new Set<string>();
  const baseOrigin = normalizeOrigin(baseUrl);
  if (baseOrigin) {
    allowed.add(baseOrigin);
  }

  for (const candidate of trustedOrigins) {
    const origin = normalizeOrigin(candidate);
    if (origin) {
      allowed.add(origin);
    }
  }
  return allowed;
}

function normalizeOrigin(value: string | undefined): string | null {
  if (!value) return null;
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function appendVaryHeader(currentValue: string | number | string[] | undefined, next: string): string {
  if (Array.isArray(currentValue)) {
    const merged = [...new Set([...currentValue.flatMap((item) => item.split(",")), next])];
    return merged.map((item) => item.trim()).filter((item) => item.length > 0).join(", ");
  }
  const current = typeof currentValue === "string" ? currentValue : "";
  const items = current
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  if (!items.includes(next)) {
    items.push(next);
  }
  return items.join(", ");
}
