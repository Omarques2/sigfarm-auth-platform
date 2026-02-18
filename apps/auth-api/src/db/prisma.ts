import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";

declare global {
  // eslint-disable-next-line no-var
  var __sigfarmAuthPrisma__: PrismaClient | undefined;
}

function resolveDatabaseUrl(): string {
  const databaseUrl = process.env.DATABASE_URL?.trim();
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required to initialize Prisma client");
  }
  return databaseUrl;
}

function createPrismaClient(): PrismaClient {
  return new PrismaClient({
    adapter: new PrismaPg({
      connectionString: resolveDatabaseUrl(),
    }),
  });
}

export function getPrismaClient(): PrismaClient {
  if (process.env.NODE_ENV === "production") {
    return createPrismaClient();
  }

  if (!global.__sigfarmAuthPrisma__) {
    global.__sigfarmAuthPrisma__ = createPrismaClient();
  }
  return global.__sigfarmAuthPrisma__;
}
