import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { pathToFileURL } from "node:url";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import {
  CONTRACT_VERSION,
  ErrorEnvelopeSchema,
  LogoutSuccessSchema,
  MeSuccessSchema,
  RefreshSuccessSchema,
  SessionSuccessSchema,
  type AuthMethod,
  type AuthStatus,
  type LogoutSuccess,
  type MeSuccess,
  type RefreshSuccess,
  type SessionSuccess,
  type AuthErrorCode,
} from "@sigfarm/auth-contracts";
import { z } from "zod";
import { loadEnv, type AppEnv } from "./config/env.js";
import { getPrismaClient } from "./db/prisma.js";
import { createEmailProvider } from "./email/email.provider.js";
import {
  createBetterAuthGateway,
  type AuthGateway,
  type AuthGatewaySession,
} from "./auth/better-auth.gateway.js";
import {
  JwtTokenService,
  type AccessTokenClaims,
  type IssuedAccessToken,
} from "./auth/jwt-token.service.js";
import {
  PrismaSessionService,
  type ActiveSession,
  type IssuedSession,
  type RotateSessionResult,
  type SessionService,
} from "./auth/session.service.js";
import {
  PrismaIdentityService,
  type AuthUser,
  type IdentityService,
  type UserSnapshot,
} from "./auth/identity.service.js";
import { PrismaAuditService, type AuditService } from "./auth/audit.service.js";
import {
  PrismaAccountFlowService,
  type AccountFlowService,
} from "./auth/account-flow.service.js";
import {
  DEFAULT_PWNED_PASSWORD_TIMEOUT_MS,
  PASSWORD_COMPROMISED_MESSAGE,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  PASSWORD_POLICY_MESSAGE,
  isPasswordCompromised,
  isPasswordPolicyCompliant,
} from "./auth/password-policy.js";

type RefreshRequestBody = {
  refreshToken?: string;
};

type LogoutRequestBody = {
  refreshToken?: string;
};

export interface TokenService {
  issueAccessToken(input: AccessTokenClaims): Promise<IssuedAccessToken>;
  verifyAccessToken(token: string): Promise<AccessTokenClaims>;
  getJwks(): { keys: unknown[] };
}

export interface AppDependencies {
  authGateway: AuthGateway;
  identityService: IdentityService;
  sessionService: SessionService;
  tokenService: TokenService;
  auditService: AuditService;
  accountFlowService: AccountFlowService;
}

type BuildServerOptions = {
  env?: AppEnv;
  dependencies?: AppDependencies;
};

const refreshBodySchema = z
  .object({
    refreshToken: z.string().min(16).optional(),
  })
  .optional();

const logoutBodySchema = z
  .object({
    refreshToken: z.string().min(16).optional(),
  })
  .optional();

const discoverEmailBodySchema = z.object({
  email: z.string().email(),
});

const requestResetCodeBodySchema = z.object({
  email: z.string().email(),
});

const verifyResetCodeBodySchema = z.object({
  email: z.string().email(),
  code: z.string().regex(/^\d{6}$/),
});

const completeResetCodeBodySchema = z.object({
  email: z.string().email(),
  code: z.string().regex(/^\d{6}$/),
  newPassword: z
    .string()
    .min(PASSWORD_MIN_LENGTH, PASSWORD_POLICY_MESSAGE)
    .max(PASSWORD_MAX_LENGTH, PASSWORD_POLICY_MESSAGE)
    .refine(isPasswordPolicyCompliant, {
      message: PASSWORD_POLICY_MESSAGE,
    }),
});

const updateAccountProfileBodySchema = z.object({
  name: z
    .string()
    .trim()
    .max(120)
    .nullable()
    .optional(),
});

const requestEmailChangeCodeBodySchema = z.object({
  newEmail: z.string().email(),
});

const confirmEmailChangeCodeBodySchema = z.object({
  newEmail: z.string().email(),
  code: z.string().regex(/^\d{6}$/),
});

export async function buildServer(options?: BuildServerOptions): Promise<FastifyInstance> {
  const env = options?.env ?? loadEnv();
  const dependencies = options?.dependencies ?? (await createDefaultDependencies(env));
  const trustedOriginSet = buildTrustedOriginSet(env);

  const app = Fastify({
    logger: {
      level: env.nodeEnv === "production" ? "info" : "debug",
      redact: {
        paths: [
          "req.headers.authorization",
          "req.headers.cookie",
          "response.headers.set-cookie",
          "req.body.password",
          "req.body.refreshToken",
        ],
        remove: true,
      },
    },
  });

  await app.register(cookie);
  await app.register(cors, {
    origin: (origin, callback) => {
      if (!origin) {
        callback(null, true);
        return;
      }
      callback(null, isTrustedOrigin(origin, trustedOriginSet));
    },
    credentials: true,
  });
  await app.register(rateLimit, {
    max: env.rateLimitMaxRequests,
    timeWindow: `${env.rateLimitWindowSeconds} second`,
  });

  app.addHook("onRequest", async (req, reply) => {
    const correlationId = resolveCorrelationId(req.headers["x-correlation-id"]);
    reply.header("x-correlation-id", correlationId);
  });

  await dependencies.authGateway.mount(app);

  app.get("/health", async () => ({ status: "ok" }));

  app.get("/.well-known/jwks.json", async () => dependencies.tokenService.getJwks());

  app.post("/v1/auth/refresh", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const body = parseBodyOrReply(refreshBodySchema, request, reply) as
      | RefreshRequestBody
      | undefined
      | null;
    if (body === null) return;
    const clientMeta = getClientMeta(request);

    if (body?.refreshToken) {
      const rotation = await dependencies.sessionService.rotateSession({
        refreshToken: body.refreshToken,
        ...clientMeta,
      });

      if (rotation.kind === "invalid" || rotation.kind === "reuse") {
        await dependencies.auditService.record({
          eventType:
            rotation.kind === "reuse"
              ? "auth.refresh.reuse_detected"
              : "auth.refresh.invalid_token",
          ...(rotation.kind === "reuse" ? { sessionId: rotation.sessionId } : {}),
          ...clientMeta,
        });
        return reply.status(401).send(authError("UNAUTHORIZED", "Invalid refresh token", correlationId));
      }

      const payload = await issueTokenPairFromSession(
        dependencies,
        rotation,
        rotation.sessionId,
        correlationId,
      );
      return reply.send(payload);
    }

    const externalSession = await dependencies.authGateway.getSession(toHeaders(request.headers));
    if (!externalSession) {
      return reply.status(401).send(authError("UNAUTHORIZED", "No active session", correlationId));
    }

    await dependencies.identityService.ensureFromAuthUser(externalSession.user);

    const snapshot = await dependencies.identityService.getSnapshot(externalSession.user.id);
    if (!snapshot) {
      return reply.status(401).send(authError("UNAUTHORIZED", "No active session", correlationId));
    }
    if (snapshot.globalStatus === "disabled") {
      return reply.status(403).send(authError("ACCOUNT_DISABLED", "Account disabled", correlationId));
    }

    const amr = await dependencies.identityService.resolveAuthMethod(snapshot.userId);
    const issued = await dependencies.sessionService.issueSession({
      userId: snapshot.userId,
      amr,
      ...clientMeta,
    });

    await dependencies.auditService.record({
      eventType: "auth.session.exchange",
      actorUserId: snapshot.userId,
      sessionId: issued.sessionId,
      payload: { amr },
      ...clientMeta,
    });

    const payload = await issueTokenPairFromSession(
      dependencies,
      issued,
      issued.sessionId,
      correlationId,
    );
    return reply.send(payload);
  });

  app.get("/v1/auth/session", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const claims = await readAccessClaims(request, dependencies.tokenService);
    if (!claims) {
      return reply.status(401).send(authError("UNAUTHORIZED", "Invalid access token", correlationId));
    }

    const activeSession = await dependencies.sessionService.getActiveSession(claims.sid);
    if (!activeSession || activeSession.userId !== claims.sub) {
      return reply.status(401).send(authError("UNAUTHORIZED", "Session revoked or expired", correlationId));
    }

    const snapshot = await dependencies.identityService.getSnapshot(claims.sub);
    if (!snapshot) {
      return reply.status(401).send(authError("UNAUTHORIZED", "User not found", correlationId));
    }
    if (snapshot.globalStatus === "disabled") {
      return reply.status(403).send(authError("ACCOUNT_DISABLED", "Account disabled", correlationId));
    }

    const payload: SessionSuccess = {
      data: {
        sessionId: activeSession.sessionId,
        userId: activeSession.userId,
        amr: activeSession.amr,
        globalStatus: snapshot.globalStatus,
        issuedAt: activeSession.issuedAt.toISOString(),
        expiresAt: activeSession.expiresAt.toISOString(),
      },
      meta: successMeta(correlationId),
    };
    return reply.send(SessionSuccessSchema.parse(payload));
  });

  app.get("/v1/auth/me", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const claims = await readAccessClaims(request, dependencies.tokenService);
    if (!claims) {
      return reply.status(401).send(authError("UNAUTHORIZED", "Invalid access token", correlationId));
    }

    const activeSession = await dependencies.sessionService.getActiveSession(claims.sid);
    if (!activeSession || activeSession.userId !== claims.sub) {
      return reply.status(401).send(authError("UNAUTHORIZED", "Session revoked or expired", correlationId));
    }

    const snapshot = await dependencies.identityService.getSnapshot(claims.sub);
    if (!snapshot) {
      return reply.status(401).send(authError("UNAUTHORIZED", "User not found", correlationId));
    }
    if (snapshot.globalStatus === "disabled") {
      return reply.status(403).send(authError("ACCOUNT_DISABLED", "Account disabled", correlationId));
    }

    const payload: MeSuccess = {
      data: {
        userId: snapshot.userId,
        email: snapshot.email,
        emailVerified: snapshot.emailVerified,
        displayName: snapshot.displayName,
        globalStatus: snapshot.globalStatus,
        apps: snapshot.apps,
      },
      meta: successMeta(correlationId),
    };
    return reply.send(MeSuccessSchema.parse(payload));
  });

  app.get("/v1/auth/account", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const snapshot = await resolveAuthenticatedSnapshot(request, dependencies);
    if (!snapshot) {
      return reply.status(401).send(authError("UNAUTHORIZED", "No active session", correlationId));
    }
    if (snapshot.globalStatus === "disabled") {
      return reply.status(403).send(authError("ACCOUNT_DISABLED", "Account disabled", correlationId));
    }

    return reply.send({
      data: {
        userId: snapshot.userId,
        email: snapshot.email,
        emailVerified: snapshot.emailVerified,
        displayName: snapshot.displayName,
      },
      meta: successMeta(correlationId),
    });
  });

  app.post("/v1/auth/account/profile", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const body = parseBodyOrReply(updateAccountProfileBodySchema, request, reply);
    if (!body) return;

    const snapshot = await resolveAuthenticatedSnapshot(request, dependencies);
    if (!snapshot) {
      return reply.status(401).send(authError("UNAUTHORIZED", "No active session", correlationId));
    }
    if (snapshot.globalStatus === "disabled") {
      return reply.status(403).send(authError("ACCOUNT_DISABLED", "Account disabled", correlationId));
    }

    const updated = await dependencies.accountFlowService.updateAccountProfile({
      userId: snapshot.userId,
      name: body.name ?? null,
    });

    return reply.send({
      data: {
        userId: snapshot.userId,
        email: snapshot.email,
        emailVerified: snapshot.emailVerified,
        displayName: updated.displayName,
      },
      meta: successMeta(correlationId),
    });
  });

  app.post("/v1/auth/account/email-change/request-code", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const body = parseBodyOrReply(requestEmailChangeCodeBodySchema, request, reply);
    if (!body) return;

    const snapshot = await resolveAuthenticatedSnapshot(request, dependencies);
    if (!snapshot) {
      return reply.status(401).send(authError("UNAUTHORIZED", "No active session", correlationId));
    }
    if (snapshot.globalStatus === "disabled") {
      return reply.status(403).send(authError("ACCOUNT_DISABLED", "Account disabled", correlationId));
    }

    const result = await dependencies.accountFlowService.requestEmailChangeCode({
      userId: snapshot.userId,
      currentEmail: snapshot.email,
      newEmail: body.newEmail,
      correlationId,
    });

    return reply.send({
      data: result,
      meta: successMeta(correlationId),
    });
  });

  app.post("/v1/auth/account/email-change/confirm-code", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const body = parseBodyOrReply(confirmEmailChangeCodeBodySchema, request, reply);
    if (!body) return;

    const snapshot = await resolveAuthenticatedSnapshot(request, dependencies);
    if (!snapshot) {
      return reply.status(401).send(authError("UNAUTHORIZED", "No active session", correlationId));
    }
    if (snapshot.globalStatus === "disabled") {
      return reply.status(403).send(authError("ACCOUNT_DISABLED", "Account disabled", correlationId));
    }

    const result = await dependencies.accountFlowService.confirmEmailChangeCode({
      userId: snapshot.userId,
      currentEmail: snapshot.email,
      newEmail: body.newEmail,
      code: body.code,
      ...getClientMeta(request),
    });

    return reply.send({
      data: result,
      meta: successMeta(correlationId),
    });
  });

  app.post("/v1/auth/logout", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const body = parseBodyOrReply(logoutBodySchema, request, reply) as
      | LogoutRequestBody
      | undefined
      | null;
    if (body === null) return;
    let revoked = false;

    if (body?.refreshToken) {
      revoked = (await dependencies.sessionService.revokeByRefreshToken(body.refreshToken)) || revoked;
    }

    const claims = await readAccessClaims(request, dependencies.tokenService);
    if (claims) {
      revoked = (await dependencies.sessionService.revokeBySessionId(claims.sid)) || revoked;
    }

    await dependencies.authGateway.signOut(toHeaders(request.headers));

    await dependencies.auditService.record({
      eventType: "auth.session.logout",
      ...(claims?.sub ? { actorUserId: claims.sub } : {}),
      ...(claims?.sid ? { sessionId: claims.sid } : {}),
      payload: {
        revoked,
      },
      ...getClientMeta(request),
    });

    const payload: LogoutSuccess = {
      data: {
        revoked,
      },
      meta: successMeta(correlationId),
    };
    return reply.send(LogoutSuccessSchema.parse(payload));
  });

  app.post(
    "/v1/auth/email/discover",
    {
      config: {
        rateLimit: {
          max: env.rateLimitLoginMaxRequests,
          timeWindow: `${env.rateLimitWindowSeconds} second`,
          keyGenerator: (request) => buildEmailRateLimitKey(request, "discover"),
        },
      },
    },
    async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const body = parseBodyOrReply(discoverEmailBodySchema, request, reply);
    if (!body) return;

    const requestOrigin =
      typeof request.headers.origin === "string" ? request.headers.origin : undefined;
    if (!isTrustedOrigin(requestOrigin, trustedOriginSet)) {
      return reply.send({
        data: {
          accountState: "active",
          retryAfterSeconds: 0,
        },
        meta: successMeta(correlationId),
      });
    }

    const discovered = await dependencies.accountFlowService.discoverEmail({
      email: body.email,
    });

    return reply.send({
      data: discovered,
      meta: successMeta(correlationId),
    });
    },
  );

  app.post("/v1/auth/password-reset/request-code", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const body = parseBodyOrReply(requestResetCodeBodySchema, request, reply);
    if (!body) return;

    const result = await dependencies.accountFlowService.requestPasswordResetCode({
      email: body.email,
      correlationId,
    });

    return reply.send({
      data: result,
      meta: successMeta(correlationId),
    });
  });

  app.post(
    "/v1/auth/password-reset/verify-code",
    {
      config: {
        rateLimit: {
          max: Math.min(env.rateLimitLoginMaxRequests, 5),
          timeWindow: `${env.rateLimitWindowSeconds} second`,
          keyGenerator: (request) => buildEmailRateLimitKey(request, "reset-code"),
        },
      },
    },
    async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const body = parseBodyOrReply(verifyResetCodeBodySchema, request, reply);
    if (!body) return;

    const valid = await dependencies.accountFlowService.verifyPasswordResetCode({
      email: body.email,
      code: body.code,
    });

    return reply.send({
      data: {
        valid,
      },
      meta: successMeta(correlationId),
    });
    },
  );

  app.post("/v1/auth/password-reset/complete-code", async (request, reply) => {
    const correlationId = getCorrelationId(reply);
    const body = parseBodyOrReply(completeResetCodeBodySchema, request, reply);
    if (!body) return;
    const clientMeta = getClientMeta(request);

    const compromised = await isPasswordCompromised(body.newPassword, {
      enabled: env.authPwnedPasswordCheckEnabled ?? env.nodeEnv !== "test",
      timeoutMs: env.authPwnedPasswordCheckTimeoutMs ?? DEFAULT_PWNED_PASSWORD_TIMEOUT_MS,
    });

    if (compromised) {
      return reply
        .status(422)
        .send(authError("INVALID_CREDENTIALS", PASSWORD_COMPROMISED_MESSAGE, correlationId));
    }

    const updated = await dependencies.accountFlowService.completePasswordResetWithCode({
      email: body.email,
      code: body.code,
      newPassword: body.newPassword,
      correlationId,
      ...clientMeta,
    });

    return reply.send({
      data: {
        updated,
      },
      meta: successMeta(correlationId),
    });
  });

  return app;
}

async function createDefaultDependencies(env: AppEnv): Promise<AppDependencies> {
  const prisma = getPrismaClient();
  const auditService = new PrismaAuditService(prisma);
  const identityService = new PrismaIdentityService(prisma, env.betterAuthSecret);
  const sessionService = new PrismaSessionService(prisma, {
    refreshTokenTtlSeconds: env.refreshTokenTtlSeconds,
    refreshTokenPepper: env.betterAuthSecret,
  });
  const emailProvider = createEmailProvider(env);
  const tokenService = await JwtTokenService.create({
    issuer: env.jwtIssuer,
    audience: env.jwtAudience,
    kid: env.jwtKid,
    accessTokenTtlSeconds: env.accessTokenTtlSeconds,
    ...(env.jwtPrivateKeyPem ? { privateKeyPem: env.jwtPrivateKeyPem } : {}),
    ...(env.jwtPublicKeyPem ? { publicKeyPem: env.jwtPublicKeyPem } : {}),
    requireStaticKeys: env.nodeEnv === "production",
  });
  const authGateway = createBetterAuthGateway({
    env,
    prisma,
    identityService,
    auditService,
    emailProvider,
  });
  const accountFlowService = new PrismaAccountFlowService(prisma, emailProvider, auditService, {
    tokenPepper: env.betterAuthSecret,
    resetCodeTtlSeconds: env.authResetCodeTtlSeconds,
    resendCooldownSeconds: env.authResendCooldownSeconds,
  });

  return {
    authGateway,
    identityService,
    sessionService,
    tokenService,
    auditService,
    accountFlowService,
  };
}

async function issueTokenPairFromSession(
  dependencies: AppDependencies,
  session: IssuedSession | Extract<RotateSessionResult, { kind: "ok" }>,
  sessionId: string,
  correlationId: string,
) {
  const snapshot = await dependencies.identityService.getSnapshot(session.userId);
  if (!snapshot) {
    throw new Error(`Identity snapshot not found for ${session.userId}`);
  }

  const access = await dependencies.tokenService.issueAccessToken({
    sub: snapshot.userId,
    sid: sessionId,
    amr: session.amr,
    email: snapshot.email,
    emailVerified: snapshot.emailVerified,
    globalStatus: snapshot.globalStatus,
    apps: snapshot.apps,
    ver: 1,
  });

  const payload: RefreshSuccess = {
    data: {
      accessToken: access.token,
      refreshToken: session.refreshToken,
      expiresInSeconds: access.expiresInSeconds,
      tokenType: "Bearer",
    },
    meta: successMeta(correlationId),
  };

  return RefreshSuccessSchema.parse(payload);
}

async function resolveAuthenticatedSnapshot(
  request: FastifyRequest,
  dependencies: AppDependencies,
): Promise<UserSnapshot | null> {
  const claims = await readAccessClaims(request, dependencies.tokenService);
  if (claims) {
    const activeSession = await dependencies.sessionService.getActiveSession(claims.sid);
    if (activeSession && activeSession.userId === claims.sub) {
      return dependencies.identityService.getSnapshot(claims.sub);
    }
  }

  const externalSession = await dependencies.authGateway.getSession(toHeaders(request.headers));
  if (!externalSession) return null;

  await dependencies.identityService.ensureFromAuthUser(externalSession.user);
  return dependencies.identityService.getSnapshot(externalSession.user.id);
}

async function readAccessClaims(
  request: FastifyRequest,
  tokenService: TokenService,
): Promise<AccessTokenClaims | null> {
  const token = readBearerToken(request.headers.authorization);
  if (!token) return null;
  try {
    return await tokenService.verifyAccessToken(token);
  } catch {
    return null;
  }
}

function getClientMeta(request: FastifyRequest): { ip?: string; userAgent?: string } {
  const forwardedFor = request.headers["x-forwarded-for"];
  const ip =
    typeof forwardedFor === "string"
      ? forwardedFor.split(",")[0]?.trim()
      : request.ip || undefined;
  const userAgent =
    typeof request.headers["user-agent"] === "string"
      ? request.headers["user-agent"]
      : undefined;
  return {
    ...(ip ? { ip } : {}),
    ...(userAgent ? { userAgent } : {}),
  };
}

function readBearerToken(rawAuthorization: string | undefined): string | null {
  if (!rawAuthorization) return null;
  const [scheme, token] = rawAuthorization.split(" ");
  if (scheme?.toLowerCase() !== "bearer" || !token) return null;
  return token;
}

function parseBodyOrReply<TSchema extends z.ZodTypeAny>(
  schema: TSchema,
  request: FastifyRequest,
  reply: { status(code: number): { send(payload: unknown): unknown }; getHeader(name: string): unknown },
): z.infer<TSchema> | null {
  const parsed = schema.safeParse(request.body);
  if (parsed.success) return parsed.data;
  const correlationId = getCorrelationId(reply);
  reply.status(400).send(
    authError("INVALID_CREDENTIALS", "Dados de requisicao invalidos", correlationId, {
      issues: parsed.error.issues,
    }),
  );
  return null;
}

function successMeta(correlationId: string) {
  return {
    contractVersion: CONTRACT_VERSION,
    correlationId,
  } as const;
}

function resolveCorrelationId(rawValue: unknown): string {
  if (typeof rawValue === "string" && rawValue.length > 0) return rawValue;
  if (Array.isArray(rawValue) && rawValue.length > 0 && typeof rawValue[0] === "string") {
    return rawValue[0];
  }
  return crypto.randomUUID();
}

function getCorrelationId(reply: { getHeader(name: string): unknown }): string {
  return resolveCorrelationId(reply.getHeader("x-correlation-id"));
}

function authError(
  code: AuthErrorCode,
  message: string,
  correlationId: string,
  details?: unknown,
) {
  return ErrorEnvelopeSchema.parse({
    error: {
      code,
      message,
      ...(details !== undefined ? { details } : {}),
    },
    meta: successMeta(correlationId),
  });
}

function toHeaders(rawHeaders: FastifyRequest["headers"]): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(rawHeaders)) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, item);
      continue;
    }
    if (typeof value === "string") headers.set(key, value);
  }
  return headers;
}

function buildTrustedOriginSet(env: AppEnv): Set<string> {
  const allowed = new Set<string>();
  const baseOrigin = normalizeOriginValue(env.betterAuthBaseUrl);
  if (baseOrigin) {
    allowed.add(baseOrigin);
  }
  for (const origin of env.betterAuthTrustedOrigins) {
    const normalized = normalizeOriginValue(origin);
    if (normalized) {
      allowed.add(normalized);
    }
  }
  return allowed;
}

function normalizeOriginValue(value: string | undefined): string | null {
  if (!value) return null;
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function isTrustedOrigin(origin: string | undefined, trustedOriginSet: Set<string>): boolean {
  const normalized = normalizeOriginValue(origin);
  if (!normalized) return false;
  return trustedOriginSet.has(normalized);
}

function buildEmailRateLimitKey(request: FastifyRequest, marker: string): string {
  const payload =
    request.body && typeof request.body === "object"
      ? (request.body as { email?: unknown })
      : undefined;
  const email =
    typeof payload?.email === "string" && payload.email.trim().length > 0
      ? payload.email.trim().toLowerCase()
      : "unknown";
  const ip = request.ip || "unknown";
  return `${ip}|${marker}|${email}`;
}

if (process.env.NODE_ENV !== "test" && isMainModule(import.meta.url)) {
  buildServer()
    .then((app) =>
      app.listen({
        port: Number(process.env.PORT ?? 3000),
        host: "0.0.0.0",
      }),
    )
    .catch((error) => {
      // eslint-disable-next-line no-console
      console.error(error);
      process.exit(1);
    });
}

function isMainModule(moduleUrl: string): boolean {
  const entryArg = process.argv[1];
  if (!entryArg) return false;
  return moduleUrl === pathToFileURL(entryArg).href;
}
