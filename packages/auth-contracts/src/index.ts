import { z } from "zod";

export const CONTRACT_VERSION = "v1" as const;

export const AuthStatusSchema = z.enum(["pending", "active", "disabled"]);
export const AuthMethodSchema = z.enum(["entra", "password"]);

export const SuccessMetaSchema = z.object({
  contractVersion: z.literal(CONTRACT_VERSION),
  correlationId: z.string().min(1),
});

export const AuthErrorCodeSchema = z.enum([
  "UNAUTHORIZED",
  "FORBIDDEN",
  "EMAIL_NOT_VERIFIED",
  "ACCOUNT_DISABLED",
  "MFA_REQUIRED",
  "TOKEN_EXPIRED",
  "RATE_LIMIT",
  "INVALID_CREDENTIALS",
]);

export const ErrorEnvelopeSchema = z.object({
  error: z.object({
    code: AuthErrorCodeSchema,
    message: z.string().min(1),
    details: z.unknown().optional(),
  }),
  meta: SuccessMetaSchema,
});

export const SessionDataSchema = z.object({
  sessionId: z.string().min(1),
  userId: z.string().uuid(),
  amr: AuthMethodSchema,
  globalStatus: AuthStatusSchema,
  issuedAt: z.string().datetime({ offset: true }),
  expiresAt: z.string().datetime({ offset: true }),
});

export const SessionSuccessSchema = z.object({
  data: SessionDataSchema,
  meta: SuccessMetaSchema,
});

export const AppAccessSchema = z.object({
  appKey: z.string().min(1),
  roles: z.array(z.string().min(1)).default([]),
});

export const MeDataSchema = z.object({
  userId: z.string().uuid(),
  email: z.string().email(),
  emailVerified: z.boolean(),
  displayName: z.string().min(1).nullable(),
  globalStatus: AuthStatusSchema,
  apps: z.array(AppAccessSchema),
});

export const MeSuccessSchema = z.object({
  data: MeDataSchema,
  meta: SuccessMetaSchema,
});

export const LogoutSuccessSchema = z.object({
  data: z.object({
    revoked: z.boolean(),
  }),
  meta: SuccessMetaSchema,
});

export const RefreshDataSchema = z.object({
  accessToken: z.string().min(1),
  refreshToken: z.string().min(1),
  expiresInSeconds: z.number().int().positive(),
  tokenType: z.literal("Bearer"),
});

export const RefreshSuccessSchema = z.object({
  data: RefreshDataSchema,
  meta: SuccessMetaSchema,
});

export type AuthStatus = z.infer<typeof AuthStatusSchema>;
export type AuthMethod = z.infer<typeof AuthMethodSchema>;
export type AuthErrorCode = z.infer<typeof AuthErrorCodeSchema>;
export type ErrorEnvelope = z.infer<typeof ErrorEnvelopeSchema>;
export type SessionSuccess = z.infer<typeof SessionSuccessSchema>;
export type MeSuccess = z.infer<typeof MeSuccessSchema>;
export type LogoutSuccess = z.infer<typeof LogoutSuccessSchema>;
export type RefreshSuccess = z.infer<typeof RefreshSuccessSchema>;
