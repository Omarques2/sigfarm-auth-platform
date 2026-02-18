import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Prisma, type PrismaClient } from "@prisma/client";
import type { AuthMethod } from "@sigfarm/auth-contracts";

export type SessionIssueInput = {
  userId: string;
  amr: AuthMethod;
  ip?: string;
  userAgent?: string;
};

export type IssuedSession = {
  sessionId: string;
  userId: string;
  amr: AuthMethod;
  refreshToken: string;
  issuedAt: Date;
  expiresAt: Date;
};

export type RotateSessionInput = {
  refreshToken: string;
  ip?: string;
  userAgent?: string;
};

export type RotateSessionResult =
  | {
      kind: "ok";
      sessionId: string;
      userId: string;
      amr: AuthMethod;
      refreshToken: string;
      issuedAt: Date;
      expiresAt: Date;
    }
  | { kind: "invalid" }
  | { kind: "reuse"; sessionId: string };

export type ActiveSession = {
  sessionId: string;
  userId: string;
  amr: AuthMethod;
  issuedAt: Date;
  expiresAt: Date;
};

export interface SessionService {
  issueSession(input: SessionIssueInput): Promise<IssuedSession>;
  rotateSession(input: RotateSessionInput): Promise<RotateSessionResult>;
  getActiveSession(sessionId: string): Promise<ActiveSession | null>;
  revokeBySessionId(sessionId: string): Promise<boolean>;
  revokeByRefreshToken(refreshToken: string): Promise<boolean>;
}

type PrismaSessionServiceConfig = {
  refreshTokenTtlSeconds: number;
  refreshTokenPepper: string;
};

export class PrismaSessionService implements SessionService {
  private readonly prisma: PrismaClient;
  private readonly refreshTokenTtlSeconds: number;
  private readonly refreshTokenPepper: string;

  constructor(prisma: PrismaClient, config: PrismaSessionServiceConfig) {
    this.prisma = prisma;
    this.refreshTokenTtlSeconds = config.refreshTokenTtlSeconds;
    this.refreshTokenPepper = config.refreshTokenPepper;
  }

  async issueSession(input: SessionIssueInput): Promise<IssuedSession> {
    const sessionId = randomUUID();
    const refreshToken = generateRefreshToken();
    const refreshTokenHash = hashOpaqueToken(refreshToken, this.refreshTokenPepper);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.refreshTokenTtlSeconds * 1000);

    await this.prisma.$transaction(async (tx) => {
      await tx.identitySession.create({
        data: {
          sessionId,
          userId: input.userId,
          authMethod: input.amr,
          refreshTokenHash,
          ip: input.ip ?? null,
          userAgent: input.userAgent ?? null,
          expiresAt,
        },
      });
      await tx.identitySessionRefreshToken.create({
        data: {
          sessionId,
          tokenHash: refreshTokenHash,
        },
      });
    });

    return {
      sessionId,
      userId: input.userId,
      amr: input.amr,
      refreshToken,
      issuedAt: now,
      expiresAt,
    };
  }

  async rotateSession(input: RotateSessionInput): Promise<RotateSessionResult> {
    const now = new Date();
    const refreshTokenHash = hashOpaqueToken(input.refreshToken, this.refreshTokenPepper);

    return this.prisma.$transaction(async (tx) => {
      const tokenRecord = await tx.identitySessionRefreshToken.findUnique({
        where: { tokenHash: refreshTokenHash },
        include: { session: true },
      });

      if (!tokenRecord) return { kind: "invalid" };

      const session = tokenRecord.session;
      const shouldTreatAsReuse =
        Boolean(tokenRecord.usedAt) ||
        Boolean(tokenRecord.revokedAt) ||
        Boolean(session.revokedAt) ||
        session.expiresAt <= now;

      if (shouldTreatAsReuse) {
        await revokeSessionInternal(tx, session.sessionId, "refresh_token_reuse_or_invalid");
        return { kind: "reuse", sessionId: session.sessionId };
      }

      const newRefreshToken = generateRefreshToken();
      const nextHash = hashOpaqueToken(newRefreshToken, this.refreshTokenPepper);
      const nextExpiresAt = new Date(now.getTime() + this.refreshTokenTtlSeconds * 1000);

      await tx.identitySessionRefreshToken.update({
        where: { id: tokenRecord.id },
        data: {
          usedAt: now,
        },
      });

      await tx.identitySession.update({
        where: { sessionId: session.sessionId },
        data: {
          refreshTokenHash: nextHash,
          ip: input.ip ?? session.ip,
          userAgent: input.userAgent ?? session.userAgent,
          lastSeenAt: now,
          expiresAt: nextExpiresAt,
        },
      });

      await tx.identitySessionRefreshToken.create({
        data: {
          sessionId: session.sessionId,
          tokenHash: nextHash,
        },
      });

      return {
        kind: "ok",
        sessionId: session.sessionId,
        userId: session.userId,
        amr: session.authMethod,
        refreshToken: newRefreshToken,
        issuedAt: session.createdAt,
        expiresAt: nextExpiresAt,
      };
    });
  }

  async getActiveSession(sessionId: string): Promise<ActiveSession | null> {
    const now = new Date();
    const session = await this.prisma.identitySession.findFirst({
      where: {
        sessionId,
        revokedAt: null,
        expiresAt: { gt: now },
      },
      select: {
        sessionId: true,
        userId: true,
        authMethod: true,
        createdAt: true,
        expiresAt: true,
      },
    });

    if (!session) return null;
    return {
      sessionId: session.sessionId,
      userId: session.userId,
      amr: session.authMethod,
      issuedAt: session.createdAt,
      expiresAt: session.expiresAt,
    };
  }

  async revokeBySessionId(sessionId: string): Promise<boolean> {
    const result = await this.prisma.$transaction(async (tx) => {
      const existing = await tx.identitySession.findUnique({
        where: { sessionId },
      });
      if (!existing) return false;
      await revokeSessionInternal(tx, sessionId, "logout");
      return true;
    });
    return result;
  }

  async revokeByRefreshToken(refreshToken: string): Promise<boolean> {
    const refreshTokenHash = hashOpaqueToken(refreshToken, this.refreshTokenPepper);
    const tokenRecord = await this.prisma.identitySessionRefreshToken.findUnique({
      where: { tokenHash: refreshTokenHash },
      select: { sessionId: true },
    });
    if (!tokenRecord) return false;
    return this.revokeBySessionId(tokenRecord.sessionId);
  }
}

function generateRefreshToken(): string {
  return `rt_${randomBytes(48).toString("base64url")}`;
}

export function hashOpaqueToken(token: string, pepper: string): string {
  return createHash("sha256").update(`${pepper}:${token}`).digest("hex");
}

async function revokeSessionInternal(tx: Prisma.TransactionClient, sessionId: string, reason: string) {
  const now = new Date();
  await tx.identitySession.updateMany({
    where: {
      sessionId,
      revokedAt: null,
    },
    data: {
      revokedAt: now,
      revokedReason: reason,
      lastSeenAt: now,
    },
  });
  await tx.identitySessionRefreshToken.updateMany({
    where: {
      sessionId,
      revokedAt: null,
    },
    data: {
      revokedAt: now,
    },
  });
}
