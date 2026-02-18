import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const migrationPath = resolve(
  process.cwd(),
  "prisma/migrations/20260216161000_init_identity_schema/migration.sql",
);
const epic02MigrationPath = resolve(
  process.cwd(),
  "prisma/migrations/20260216203000_epic02_auth_core/migration.sql",
);
const rateLimitFixMigrationPath = resolve(
  process.cwd(),
  "prisma/migrations/20260217160000_fix_rate_limit_id/migration.sql",
);
const rateLimitBigintFixMigrationPath = resolve(
  process.cwd(),
  "prisma/migrations/20260217163000_fix_rate_limit_last_request_bigint/migration.sql",
);
const rateLimitIdDefaultMigrationPath = resolve(
  process.cwd(),
  "prisma/migrations/20260218003000_rate_limit_id_default/migration.sql",
);
const emailChangeTokenTypeMigrationPath = resolve(
  process.cwd(),
  "prisma/migrations/20260218101500_add_email_change_token_type/migration.sql",
);

describe("initial identity migration", () => {
  it("contains required extensions and tables", () => {
    const sql = readFileSync(migrationPath, "utf8");

    expect(sql).toContain("CREATE EXTENSION IF NOT EXISTS pgcrypto;");
    expect(sql).toContain("CREATE EXTENSION IF NOT EXISTS citext;");
    expect(sql).toContain("CREATE TABLE \"identity_user\"");
    expect(sql).toContain("CREATE TABLE \"identity_provider_account\"");
    expect(sql).toContain("CREATE TABLE \"identity_credential\"");
    expect(sql).toContain("CREATE TABLE \"identity_session\"");
    expect(sql).toContain("CREATE TABLE \"identity_email_token\"");
    expect(sql).toContain("CREATE TABLE \"identity_audit_log\"");
    expect(sql).toContain("CREATE TABLE \"identity_application\"");
    expect(sql).toContain("CREATE TABLE \"identity_role\"");
    expect(sql).toContain("CREATE TABLE \"identity_app_membership\"");
  });

  it("contains critical uniqueness and indexing rules", () => {
    const sql = readFileSync(migrationPath, "utf8");

    expect(sql).toContain("identity_user_email_normalized_key");
    expect(sql).toContain("identity_provider_provider_subject_key");
    expect(sql).toContain("identity_app_membership_user_application_key");
    expect(sql).toContain("identity_session_user_expires_idx");
    expect(sql).toContain("identity_audit_event_created_idx");
  });

  it("contains epic-02 auth core structures", () => {
    const sql = readFileSync(epic02MigrationPath, "utf8");

    expect(sql).toContain("ALTER TABLE \"identity_session\"");
    expect(sql).toContain("ADD COLUMN \"auth_method\"");
    expect(sql).toContain("CREATE TABLE \"identity_session_refresh_token\"");
    expect(sql).toContain("CREATE TABLE \"auth_user\"");
    expect(sql).toContain("CREATE TABLE \"auth_session\"");
    expect(sql).toContain("CREATE TABLE \"auth_account\"");
    expect(sql).toContain("CREATE TABLE \"auth_verification\"");
    expect(sql).toContain("CREATE TABLE \"auth_rate_limit\"");
  });

  it("contains rate-limit compatibility fix for better-auth id field", () => {
    const sql = readFileSync(rateLimitFixMigrationPath, "utf8");

    expect(sql).toContain("ADD COLUMN IF NOT EXISTS \"id\" TEXT");
    expect(sql).toContain("SET \"id\" = \"key\"");
    expect(sql).toContain("PRIMARY KEY (\"id\")");
    expect(sql).toContain("\"auth_rate_limit_key_key\"");
  });

  it("contains rate-limit bigint fix for last_request timestamp", () => {
    const sql = readFileSync(rateLimitBigintFixMigrationPath, "utf8");

    expect(sql).toContain("ALTER COLUMN \"last_request\" TYPE BIGINT");
    expect(sql).toContain("USING \"last_request\"::BIGINT");
  });

  it("contains rate-limit id default to support better-auth inserts without id", () => {
    const sql = readFileSync(rateLimitIdDefaultMigrationPath, "utf8");

    expect(sql).toContain("ALTER COLUMN \"id\" SET DEFAULT gen_random_uuid()::text");
  });

  it("contains enum extension for email change verification code flow", () => {
    const sql = readFileSync(emailChangeTokenTypeMigrationPath, "utf8");

    expect(sql).toContain("ADD VALUE IF NOT EXISTS 'email_change'");
  });
});
