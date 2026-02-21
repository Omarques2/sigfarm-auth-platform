import { randomInt } from "node:crypto";
import { hash } from "@node-rs/argon2";
import type { PrismaClient } from "@prisma/client";
import type { EmailProvider } from "../email/email.provider.js";
import type { AuditService } from "./audit.service.js";
import { hashOpaqueToken } from "./session.service.js";

export type DiscoverEmailInput = {
  email: string;
};

export type DiscoverEmailResult = {
  accountState: "missing" | "pending_verification" | "active";
  retryAfterSeconds: number;
};

export type PasswordResetRequestInput = {
  email: string;
  correlationId: string;
};

export type PasswordResetRequestResult = {
  status: "sent" | "cooldown";
  retryAfterSeconds: number;
};

export type VerifyPasswordResetCodeInput = {
  email: string;
  code: string;
};

export type CompletePasswordResetInput = {
  email: string;
  code: string;
  newPassword: string;
  correlationId: string;
  ip?: string;
  userAgent?: string;
};

export type UpdateAccountProfileInput = {
  userId: string;
  name: string | null;
};

export type UpdateAccountProfileResult = {
  displayName: string | null;
};

export type RequestEmailChangeCodeInput = {
  userId: string;
  currentEmail: string;
  newEmail: string;
  correlationId: string;
};

export type RequestEmailChangeCodeResult = {
  status: "sent" | "cooldown" | "same_as_current" | "already_in_use";
  retryAfterSeconds: number;
};

export type ConfirmEmailChangeCodeInput = {
  userId: string;
  currentEmail: string;
  newEmail: string;
  code: string;
  ip?: string;
  userAgent?: string;
};

export type ConfirmEmailChangeCodeResult = {
  updated: boolean;
  reason?: "invalid_or_expired" | "same_as_current" | "already_in_use";
};

export interface AccountFlowService {
  discoverEmail(input: DiscoverEmailInput): Promise<DiscoverEmailResult>;
  requestPasswordResetCode(input: PasswordResetRequestInput): Promise<PasswordResetRequestResult>;
  verifyPasswordResetCode(input: VerifyPasswordResetCodeInput): Promise<boolean>;
  completePasswordResetWithCode(input: CompletePasswordResetInput): Promise<boolean>;
  updateAccountProfile(input: UpdateAccountProfileInput): Promise<UpdateAccountProfileResult>;
  requestEmailChangeCode(input: RequestEmailChangeCodeInput): Promise<RequestEmailChangeCodeResult>;
  confirmEmailChangeCode(input: ConfirmEmailChangeCodeInput): Promise<ConfirmEmailChangeCodeResult>;
}

type PrismaAccountFlowServiceConfig = {
  tokenPepper: string;
  resetCodeTtlSeconds: number;
  resendCooldownSeconds: number;
};

export class PrismaAccountFlowService implements AccountFlowService {
  private readonly prisma: PrismaClient;
  private readonly emailProvider: EmailProvider;
  private readonly auditService: AuditService;
  private readonly tokenPepper: string;
  private readonly resetCodeTtlSeconds: number;
  private readonly resendCooldownSeconds: number;

  constructor(
    prisma: PrismaClient,
    emailProvider: EmailProvider,
    auditService: AuditService,
    config: PrismaAccountFlowServiceConfig,
  ) {
    this.prisma = prisma;
    this.emailProvider = emailProvider;
    this.auditService = auditService;
    this.tokenPepper = config.tokenPepper;
    this.resetCodeTtlSeconds = config.resetCodeTtlSeconds;
    this.resendCooldownSeconds = config.resendCooldownSeconds;
  }

  async discoverEmail(input: DiscoverEmailInput): Promise<DiscoverEmailResult> {
    const email = normalizeEmail(input.email);
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        emailVerified: true,
      },
    });

    if (!user) {
      return {
        accountState: "missing",
        retryAfterSeconds: 0,
      };
    }

    if (!user.emailVerified) {
      const retryAfterSeconds = await this.calculateCooldownSeconds(user.id, "verify");
      return {
        accountState: "pending_verification",
        retryAfterSeconds,
      };
    }

    return {
      accountState: "active",
      retryAfterSeconds: 0,
    };
  }

  async requestPasswordResetCode(
    input: PasswordResetRequestInput,
  ): Promise<PasswordResetRequestResult> {
    const email = normalizeEmail(input.email);
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
      },
    });

    if (!user) {
      return {
        // Anti-enumeration: return accepted-like response even when account does not exist.
        status: "sent",
        retryAfterSeconds: this.resendCooldownSeconds,
      };
    }

    const retryAfterSeconds = await this.calculateCooldownSeconds(user.id, "reset");
    if (retryAfterSeconds > 0) {
      return {
        status: "cooldown",
        retryAfterSeconds,
      };
    }

    const code = generateSixDigitCode();
    const tokenHash = hashOpaqueToken(code, this.tokenPepper);
    const expiresAt = new Date(Date.now() + this.resetCodeTtlSeconds * 1000);

    await this.prisma.identityEmailToken.create({
      data: {
        userId: user.id,
        tokenType: "reset",
        tokenHash,
        expiresAt,
      },
    });

    await this.emailProvider.sendResetPasswordEmail({
      to: user.email,
      token: code,
      correlationId: input.correlationId,
    });

    await this.auditService.record({
      eventType: "auth.password_reset.code_sent",
      actorUserId: user.id,
      payload: {
        email: user.email,
      },
    });

    return {
      status: "sent",
      retryAfterSeconds: this.resendCooldownSeconds,
    };
  }

  async verifyPasswordResetCode(input: VerifyPasswordResetCodeInput): Promise<boolean> {
    const user = await this.findUserByEmail(input.email);
    if (!user) return false;

    const token = await this.findActiveResetCodeToken({
      userId: user.id,
      code: input.code,
    });
    return Boolean(token);
  }

  async completePasswordResetWithCode(input: CompletePasswordResetInput): Promise<boolean> {
    const user = await this.findUserByEmail(input.email);
    if (!user) return false;

    const activeToken = await this.findActiveResetCodeToken({
      userId: user.id,
      code: input.code,
    });
    if (!activeToken) return false;

    const passwordHash = await hash(input.newPassword, {
      algorithm: 2,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
      outputLen: 32,
    });
    const now = new Date();

    const updatedCredentialCount = await this.prisma.$transaction(async (tx) => {
      const updatedCredential = await tx.account.updateMany({
        where: {
          userId: user.id,
          providerId: "credential",
        },
        data: {
          password: passwordHash,
          updatedAt: now,
        },
      });

      if (updatedCredential.count < 1) {
        return 0;
      }

      await tx.identityCredential.upsert({
        where: { userId: user.id },
        create: {
          userId: user.id,
          passwordHashArgon2id: passwordHash,
          passwordUpdatedAt: now,
          requiresReset: false,
        },
        update: {
          passwordHashArgon2id: passwordHash,
          passwordUpdatedAt: now,
          requiresReset: false,
        },
      });

      await tx.identityEmailToken.updateMany({
        where: {
          userId: user.id,
          tokenType: "reset",
          usedAt: null,
        },
        data: {
          usedAt: now,
        },
      });

      await tx.session.deleteMany({
        where: { userId: user.id },
      });

      await tx.identitySession.updateMany({
        where: {
          userId: user.id,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
          revokedReason: "password_reset_code",
          lastSeenAt: now,
        },
      });

      await tx.identitySessionRefreshToken.updateMany({
        where: {
          session: {
            userId: user.id,
          },
          revokedAt: null,
        },
        data: {
          revokedAt: now,
        },
      });

      return updatedCredential.count;
    });

    if (updatedCredentialCount < 1) return false;

    await this.auditService.record({
      eventType: "auth.password_reset.completed_with_code",
      actorUserId: user.id,
      payload: {
        email: user.email,
      },
      ...(input.ip ? { ip: input.ip } : {}),
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
    });

    void this.emailProvider
      .sendPasswordChangedAlert({
        to: user.email,
        correlationId: input.correlationId,
      })
      .catch(() => {
        return;
      });

    return true;
  }

  async updateAccountProfile(input: UpdateAccountProfileInput): Promise<UpdateAccountProfileResult> {
    const normalizedName = normalizeDisplayName(input.name);
    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: input.userId },
        data: {
          name: normalizedName ?? "Usuario Sigfarm",
        },
      });
      await tx.identityUser.updateMany({
        where: { id: input.userId },
        data: {
          displayName: normalizedName,
        },
      });
    });

    await this.auditService.record({
      eventType: "auth.account.profile.updated",
      actorUserId: input.userId,
      payload: {
        hasDisplayName: Boolean(normalizedName),
      },
    });

    return {
      displayName: normalizedName,
    };
  }

  async requestEmailChangeCode(
    input: RequestEmailChangeCodeInput,
  ): Promise<RequestEmailChangeCodeResult> {
    const currentEmail = normalizeEmail(input.currentEmail);
    const newEmail = normalizeEmail(input.newEmail);

    if (currentEmail === newEmail) {
      return {
        status: "same_as_current",
        retryAfterSeconds: 0,
      };
    }

    const emailAlreadyInUse = await this.prisma.user.findFirst({
      where: {
        email: newEmail,
        id: { not: input.userId },
      },
      select: { id: true },
    });
    if (emailAlreadyInUse) {
      return {
        status: "already_in_use",
        retryAfterSeconds: 0,
      };
    }

    const retryAfterSeconds = await this.calculateCooldownSeconds(input.userId, "email_change");
    if (retryAfterSeconds > 0) {
      return {
        status: "cooldown",
        retryAfterSeconds,
      };
    }

    const code = generateSixDigitCode();
    const tokenHash = hashEmailChangeCode({
      email: newEmail,
      code,
      pepper: this.tokenPepper,
    });
    const expiresAt = new Date(Date.now() + this.resetCodeTtlSeconds * 1000);

    await this.prisma.identityEmailToken.create({
      data: {
        userId: input.userId,
        tokenType: "email_change",
        tokenHash,
        expiresAt,
      },
    });

    await this.emailProvider.sendEmailChangeCode({
      to: newEmail,
      token: code,
      correlationId: input.correlationId,
    });

    await this.auditService.record({
      eventType: "auth.email_change.code_sent",
      actorUserId: input.userId,
      payload: {
        to: newEmail,
      },
    });

    return {
      status: "sent",
      retryAfterSeconds: this.resendCooldownSeconds,
    };
  }

  async confirmEmailChangeCode(
    input: ConfirmEmailChangeCodeInput,
  ): Promise<ConfirmEmailChangeCodeResult> {
    const currentEmail = normalizeEmail(input.currentEmail);
    const newEmail = normalizeEmail(input.newEmail);

    if (currentEmail === newEmail) {
      return {
        updated: false,
        reason: "same_as_current",
      };
    }

    const emailAlreadyInUse = await this.prisma.user.findFirst({
      where: {
        email: newEmail,
        id: { not: input.userId },
      },
      select: { id: true },
    });
    if (emailAlreadyInUse) {
      return {
        updated: false,
        reason: "already_in_use",
      };
    }

    const tokenHash = hashEmailChangeCode({
      email: newEmail,
      code: input.code,
      pepper: this.tokenPepper,
    });
    const activeToken = await this.prisma.identityEmailToken.findFirst({
      where: {
        userId: input.userId,
        tokenType: "email_change",
        tokenHash,
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: "desc" },
      select: { id: true },
    });
    if (!activeToken) {
      return {
        updated: false,
        reason: "invalid_or_expired",
      };
    }

    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: input.userId },
        data: {
          email: newEmail,
          emailVerified: true,
        },
      });

      await tx.identityUser.updateMany({
        where: { id: input.userId },
        data: {
          email: newEmail,
          emailNormalized: newEmail,
          emailVerifiedAt: now,
        },
      });

      await tx.identityProviderAccount.updateMany({
        where: {
          userId: input.userId,
          provider: "password",
        },
        data: {
          providerEmail: newEmail,
        },
      });

      await tx.identityEmailToken.updateMany({
        where: {
          userId: input.userId,
          tokenType: "email_change",
          usedAt: null,
        },
        data: {
          usedAt: now,
        },
      });
    });

    await this.auditService.record({
      eventType: "auth.email_change.completed",
      actorUserId: input.userId,
      payload: {
        from: currentEmail,
        to: newEmail,
      },
      ...(input.ip ? { ip: input.ip } : {}),
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
    });

    return {
      updated: true,
    };
  }

  private async calculateCooldownSeconds(
    userId: string,
    tokenType: "verify" | "reset" | "email_change",
  ): Promise<number> {
    const latest = await this.prisma.identityEmailToken.findFirst({
      where: {
        userId,
        tokenType,
      },
      orderBy: { createdAt: "desc" },
      select: { createdAt: true },
    });
    if (!latest) return 0;

    const cooldownUntil = latest.createdAt.getTime() + this.resendCooldownSeconds * 1000;
    const remainingMs = cooldownUntil - Date.now();
    if (remainingMs <= 0) return 0;

    return Math.ceil(remainingMs / 1000);
  }

  private async findUserByEmail(email: string): Promise<{ id: string; email: string } | null> {
    return this.prisma.user.findUnique({
      where: {
        email: normalizeEmail(email),
      },
      select: {
        id: true,
        email: true,
      },
    });
  }

  private async findActiveResetCodeToken(input: {
    userId: string;
    code: string;
  }): Promise<{ id: string } | null> {
    const tokenHash = hashOpaqueToken(input.code, this.tokenPepper);
    return this.prisma.identityEmailToken.findFirst({
      where: {
        userId: input.userId,
        tokenType: "reset",
        tokenHash,
        usedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
      orderBy: {
        createdAt: "desc",
      },
      select: {
        id: true,
      },
    });
  }
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function generateSixDigitCode(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, "0");
}

function normalizeDisplayName(value: string | null): string | null {
  if (value === null) return null;
  const normalized = value.trim().replace(/\s+/g, " ");
  if (!normalized) return null;
  return normalized.slice(0, 120);
}

function hashEmailChangeCode(input: { email: string; code: string; pepper: string }): string {
  return hashOpaqueToken(`email_change:${input.email}:${input.code}`, input.pepper);
}
