import "dotenv/config";
import { getPrismaClient } from "../src/db/prisma.js";
import { seedInitialCatalog } from "../src/seed/catalog.js";

async function main() {
  const prisma = getPrismaClient();
  try {
    const result = await prisma.$transaction(async (tx) => seedInitialCatalog(tx));
    console.log(
      `[seed] catalog seeded successfully: applications=${result.applications}, roles=${result.roles}`,
    );
  } finally {
    await prisma.$disconnect();
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  console.error(`[seed] failed: ${message}`);
  process.exit(1);
});
