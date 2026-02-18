import { afterEach, describe, expect, it } from "vitest";
import { getPrismaClient } from "../src/db/prisma.js";

const globalForPrisma = globalThis as typeof globalThis & {
  __sigfarmAuthPrisma__?: { $disconnect(): Promise<void> };
};

const originalNodeEnv = process.env.NODE_ENV;
const originalDatabaseUrl = process.env.DATABASE_URL;

afterEach(async () => {
  if (globalForPrisma.__sigfarmAuthPrisma__) {
    await globalForPrisma.__sigfarmAuthPrisma__.$disconnect();
    globalForPrisma.__sigfarmAuthPrisma__ = undefined;
  }
  process.env.NODE_ENV = originalNodeEnv;
  process.env.DATABASE_URL = originalDatabaseUrl;
});

describe("getPrismaClient", () => {
  it("initializes client when DATABASE_URL is defined", () => {
    process.env.NODE_ENV = "test";
    process.env.DATABASE_URL = "postgresql://test:test@localhost:5432/sigfarm_auth_test";

    expect(() => getPrismaClient()).not.toThrow();
  });
});
