import { Prisma, type PrismaClient } from "@prisma/client";

export type AuditEventInput = {
  eventType: string;
  actorUserId?: string;
  sessionId?: string;
  payload?: unknown;
  ip?: string;
  userAgent?: string;
};

export interface AuditService {
  record(event: AuditEventInput): Promise<void>;
}

export class PrismaAuditService implements AuditService {
  private readonly prisma: PrismaClient;

  constructor(prisma: PrismaClient) {
    this.prisma = prisma;
  }

  async record(event: AuditEventInput): Promise<void> {
    const data: Prisma.IdentityAuditLogUncheckedCreateInput = {
      eventType: event.eventType,
    };
    if (event.actorUserId) data.actorUserId = event.actorUserId;
    if (event.sessionId) data.sessionId = event.sessionId;
    if (event.payload !== undefined) data.payload = event.payload as Prisma.InputJsonValue;
    if (event.ip) data.ip = event.ip;
    if (event.userAgent) data.userAgent = event.userAgent;

    await this.prisma.identityAuditLog.create({
      data,
    });
  }
}
