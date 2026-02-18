const APPLICATIONS = [
  { appKey: "AUTH_PLATFORM", name: "Sigfarm Auth Platform" },
  { appKey: "LANDWATCH", name: "LandWatch" },
  { appKey: "PBI_EMBED", name: "Power BI Embed" },
] as const;

const ROLES_BY_APP: Record<string, Array<{ roleKey: string; name: string }>> = {
  AUTH_PLATFORM: [
    { roleKey: "platform_admin", name: "Platform Admin" },
    { roleKey: "security_auditor", name: "Security Auditor" },
    { roleKey: "support_operator", name: "Support Operator" },
  ],
  LANDWATCH: [
    { roleKey: "app_user", name: "Application User" },
    { roleKey: "app_admin", name: "Application Admin" },
  ],
  PBI_EMBED: [
    { roleKey: "app_user", name: "Application User" },
    { roleKey: "app_admin", name: "Application Admin" },
    { roleKey: "platform_admin", name: "Platform Admin" },
  ],
};

type IdentityApplicationResult = {
  id: string;
  appKey: string;
};

type IdentityRoleResult = {
  id: string;
};

export type SeedCatalogClient = {
  identityApplication: {
    upsert(args: {
      where: { appKey: string };
      create: { appKey: string; name: string; isActive: boolean };
      update: { name: string; isActive: boolean };
      select: { id: true; appKey: true };
    }): Promise<IdentityApplicationResult>;
  };
  identityRole: {
    upsert(args: {
      where: { applicationId_roleKey: { applicationId: string; roleKey: string } };
      create: { applicationId: string; roleKey: string; name: string; isSystem: boolean };
      update: { name: string; isSystem: boolean };
      select: { id: true };
    }): Promise<IdentityRoleResult>;
  };
};

export type SeedCatalogResult = {
  applications: number;
  roles: number;
};

export async function seedInitialCatalog(client: SeedCatalogClient): Promise<SeedCatalogResult> {
  const appMap = new Map<string, string>();

  for (const app of APPLICATIONS) {
    const record = await client.identityApplication.upsert({
      where: { appKey: app.appKey },
      create: {
        appKey: app.appKey,
        name: app.name,
        isActive: true,
      },
      update: {
        name: app.name,
        isActive: true,
      },
      select: { id: true, appKey: true },
    });
    appMap.set(record.appKey, record.id);
  }

  let roleCount = 0;
  for (const [appKey, roles] of Object.entries(ROLES_BY_APP)) {
    const applicationId = appMap.get(appKey);
    if (!applicationId) {
      throw new Error(`Application not found in seed map: ${appKey}`);
    }
    for (const role of roles) {
      await client.identityRole.upsert({
        where: {
          applicationId_roleKey: {
            applicationId,
            roleKey: role.roleKey,
          },
        },
        create: {
          applicationId,
          roleKey: role.roleKey,
          name: role.name,
          isSystem: true,
        },
        update: {
          name: role.name,
          isSystem: true,
        },
        select: { id: true },
      });
      roleCount += 1;
    }
  }

  return {
    applications: APPLICATIONS.length,
    roles: roleCount,
  };
}

