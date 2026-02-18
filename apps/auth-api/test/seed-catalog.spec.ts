import { describe, expect, it, vi } from "vitest";
import { seedInitialCatalog, type SeedCatalogClient } from "../src/seed/catalog.js";

function buildMockClient() {
  const appIds = new Map<string, string>();
  const roleIds = new Map<string, string>();

  const client: SeedCatalogClient = {
    identityApplication: {
      upsert: vi.fn(async (args) => {
        const appKey = args.where.appKey;
        const existing = appIds.get(appKey);
        if (existing) {
          return { id: existing, appKey };
        }
        const newId = `app-${appIds.size + 1}`;
        appIds.set(appKey, newId);
        return { id: newId, appKey };
      }),
    },
    identityRole: {
      upsert: vi.fn(async (args) => {
        const key = `${args.where.applicationId_roleKey.applicationId}:${args.where.applicationId_roleKey.roleKey}`;
        const existing = roleIds.get(key);
        if (existing) {
          return { id: existing };
        }
        const newId = `role-${roleIds.size + 1}`;
        roleIds.set(key, newId);
        return { id: newId };
      }),
    },
  };

  return { client, appIds, roleIds };
}

describe("seed catalog", () => {
  it("creates the expected app and role catalog", async () => {
    const { client } = buildMockClient();
    const result = await seedInitialCatalog(client);

    expect(result.applications).toBe(3);
    expect(result.roles).toBe(8);
  });

  it("is idempotent when executed twice", async () => {
    const { client, appIds, roleIds } = buildMockClient();

    const first = await seedInitialCatalog(client);
    const second = await seedInitialCatalog(client);

    expect(first).toEqual(second);
    expect(appIds.size).toBe(3);
    expect(roleIds.size).toBe(8);
  });
});

