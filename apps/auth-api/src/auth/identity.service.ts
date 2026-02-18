import type { IdentityProvider, PrismaClient } from "@prisma/client";
import type { AuthMethod, AuthStatus } from "@sigfarm/auth-contracts";
import { APIError } from "better-auth";
import { hashOpaqueToken } from "./session.service.js";

export type AuthUser = {
  id: string;
  email: string;
  emailVerified: boolean;
  name?: string | null;
};

export type UserSnapshot = {
  userId: string;
  email: string;
  emailVerified: boolean;
  displayName: string | null;
  globalStatus: AuthStatus;
  apps: Array<{ appKey: string; roles: string[] }>;
};

export interface IdentityService {
  ensureFromAuthUser(user: AuthUser): Promise<void>;
  getSnapshot(userId: string): Promise<UserSnapshot | null>;
  resolveAuthMethod(userId: string): Promise<AuthMethod>;
  syncProviderAccount(input: {
    userId: string;
    providerId: string;
    accountId: string;
    providerEmail?: string | null;
    passwordHash?: string | null;
  }): Promise<void>;
  registerEmailToken(input: {
    userId: string;
    token: string;
    tokenType: "verify" | "reset";
    expiresAt: Date;
  }): Promise<void>;
  validateUnusedEmailToken(input: {
    userId: string;
    token: string;
    tokenType: "verify" | "reset";
  }): Promise<void>;
  consumeEmailToken(input: {
    userId: string;
    token: string;
    tokenType: "verify" | "reset";
  }): Promise<void>;
  consumeLatestResetToken(userId: string): Promise<void>;
  markEmailVerified(userId: string): Promise<void>;
}

export class PrismaIdentityService implements IdentityService {
  private readonly prisma: PrismaClient;
  private readonly tokenPepper: string;

  constructor(prisma: PrismaClient, tokenPepper: string) {
    this.prisma = prisma;
    this.tokenPepper = tokenPepper;
  }

  async ensureFromAuthUser(user: AuthUser): Promise<void> {
    await this.prisma.identityUser.upsert({
      where: { id: user.id },
      create: {
        id: user.id,
        email: user.email,
        emailNormalized: user.email.trim().toLowerCase(),
        emailVerifiedAt: user.emailVerified ? new Date() : null,
        displayName: user.name ?? null,
        status: "pending",
      },
      update: {
        email: user.email,
        emailNormalized: user.email.trim().toLowerCase(),
        displayName: user.name ?? null,
        ...(user.emailVerified ? { emailVerifiedAt: new Date() } : {}),
      },
    });
  }

  async getSnapshot(userId: string): Promise<UserSnapshot | null> {
    const user = await this.prisma.identityUser.findUnique({
      where: { id: userId },
      include: {
        memberships: {
          include: {
            application: true,
            roles: {
              include: {
                role: true,
              },
            },
          },
        },
      },
    });

    if (!user || !user.email) return null;

    const apps = user.memberships.map((membership) => ({
      appKey: membership.application.appKey,
      roles: membership.roles.map((assignment) => assignment.role.roleKey),
    }));

    return {
      userId: user.id,
      email: user.email,
      emailVerified: Boolean(user.emailVerifiedAt),
      displayName: user.displayName,
      globalStatus: user.status,
      apps,
    };
  }

  async resolveAuthMethod(userId: string): Promise<AuthMethod> {
    const provider = await this.prisma.identityProviderAccount.findFirst({
      where: { userId },
      orderBy: [{ lastSignInAt: "desc" }, { linkedAt: "desc" }],
      select: { provider: true },
    });

    if (!provider) return "password";
    return provider.provider === "entra" ? "entra" : "password";
  }

  async syncProviderAccount(input: {
    userId: string;
    providerId: string;
    accountId: string;
    providerEmail?: string | null;
    passwordHash?: string | null;
  }): Promise<void> {
    const mappedProvider = mapProvider(input.providerId);
    if (!mappedProvider) return;

    await this.prisma.identityProviderAccount.upsert({
      where: {
        provider_providerSubject: {
          provider: mappedProvider,
          providerSubject: input.accountId,
        },
      },
      create: {
        userId: input.userId,
        provider: mappedProvider,
        providerSubject: input.accountId,
        providerEmail: input.providerEmail ?? null,
        lastSignInAt: new Date(),
      },
      update: {
        userId: input.userId,
        providerEmail: input.providerEmail ?? null,
        lastSignInAt: new Date(),
      },
    });

    if (mappedProvider === "password" && input.passwordHash) {
      await this.prisma.identityCredential.upsert({
        where: { userId: input.userId },
        create: {
          userId: input.userId,
          passwordHashArgon2id: input.passwordHash,
          passwordUpdatedAt: new Date(),
          requiresReset: false,
        },
        update: {
          passwordHashArgon2id: input.passwordHash,
          passwordUpdatedAt: new Date(),
          requiresReset: false,
        },
      });
    }
  }

  async registerEmailToken(input: {
    userId: string;
    token: string;
    tokenType: "verify" | "reset";
    expiresAt: Date;
  }): Promise<void> {
    const tokenHash = hashOpaqueToken(input.token, this.tokenPepper);
    await this.prisma.identityEmailToken.create({
      data: {
        userId: input.userId,
        tokenType: input.tokenType,
        tokenHash,
        expiresAt: input.expiresAt,
      },
    });
  }

  async validateUnusedEmailToken(input: {
    userId: string;
    token: string;
    tokenType: "verify" | "reset";
  }): Promise<void> {
    const now = new Date();
    const tokenHash = hashOpaqueToken(input.token, this.tokenPepper);
    const token = await this.prisma.identityEmailToken.findFirst({
      where: {
        userId: input.userId,
        tokenType: input.tokenType,
        tokenHash,
        usedAt: null,
        expiresAt: { gt: now },
      },
    });
    if (!token) {
      throw new APIError("BAD_REQUEST", { message: "INVALID_OR_USED_TOKEN" });
    }
  }

  async consumeEmailToken(input: {
    userId: string;
    token: string;
    tokenType: "verify" | "reset";
  }): Promise<void> {
    const now = new Date();
    const tokenHash = hashOpaqueToken(input.token, this.tokenPepper);
    await this.prisma.identityEmailToken.updateMany({
      where: {
        userId: input.userId,
        tokenType: input.tokenType,
        tokenHash,
        usedAt: null,
      },
      data: {
        usedAt: now,
      },
    });
  }

  async consumeLatestResetToken(userId: string): Promise<void> {
    const latest = await this.prisma.identityEmailToken.findFirst({
      where: {
        userId,
        tokenType: "reset",
        usedAt: null,
      },
      orderBy: { createdAt: "desc" },
      select: { id: true },
    });
    if (!latest) return;
    await this.prisma.identityEmailToken.update({
      where: { id: latest.id },
      data: { usedAt: new Date() },
    });
  }

  async markEmailVerified(userId: string): Promise<void> {
    await this.prisma.identityUser.updateMany({
      where: { id: userId, emailVerifiedAt: null },
      data: { emailVerifiedAt: new Date() },
    });
  }
}

function mapProvider(providerId: string): IdentityProvider | null {
  if (providerId === "credential") return "password";
  if (providerId === "microsoft") return "entra";
  return null;
}

