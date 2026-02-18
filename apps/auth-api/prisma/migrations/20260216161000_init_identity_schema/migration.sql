-- Required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- Enums
CREATE TYPE "IdentityUserStatus" AS ENUM ('pending', 'active', 'disabled');
CREATE TYPE "IdentityProvider" AS ENUM ('entra', 'password');
CREATE TYPE "IdentityEmailTokenType" AS ENUM ('verify', 'reset');

-- Core identity tables
CREATE TABLE "identity_user" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "email" CITEXT,
    "email_normalized" TEXT,
    "email_verified_at" TIMESTAMPTZ(6),
    "display_name" TEXT,
    "status" "IdentityUserStatus" NOT NULL DEFAULT 'pending',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_user_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "identity_provider_account" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "provider" "IdentityProvider" NOT NULL,
    "provider_subject" TEXT NOT NULL,
    "provider_email" CITEXT,
    "linked_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_sign_in_at" TIMESTAMPTZ(6),
    CONSTRAINT "identity_provider_account_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "identity_credential" (
    "user_id" UUID NOT NULL,
    "password_hash_argon2id" TEXT NOT NULL,
    "password_updated_at" TIMESTAMPTZ(6),
    "requires_reset" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_credential_pkey" PRIMARY KEY ("user_id")
);

CREATE TABLE "identity_session" (
    "session_id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "refresh_token_hash" TEXT NOT NULL,
    "ip" TEXT,
    "user_agent" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "revoked_at" TIMESTAMPTZ(6),
    "revoked_reason" TEXT,
    "last_seen_at" TIMESTAMPTZ(6),
    CONSTRAINT "identity_session_pkey" PRIMARY KEY ("session_id")
);

CREATE TABLE "identity_email_token" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "token_type" "IdentityEmailTokenType" NOT NULL,
    "token_hash" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "used_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_email_token_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "identity_audit_log" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "event_type" TEXT NOT NULL,
    "actor_user_id" UUID,
    "session_id" UUID,
    "payload" JSONB,
    "ip" TEXT,
    "user_agent" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_audit_log_pkey" PRIMARY KEY ("id")
);

-- Application and role catalog
CREATE TABLE "identity_application" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "app_key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_application_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "identity_role" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "application_id" UUID NOT NULL,
    "role_key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "is_system" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_role_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "identity_app_membership" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "application_id" UUID NOT NULL,
    "global_status" "IdentityUserStatus" NOT NULL DEFAULT 'pending',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_app_membership_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "identity_app_role_assignment" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "membership_id" UUID NOT NULL,
    "role_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_app_role_assignment_pkey" PRIMARY KEY ("id")
);

-- Unique constraints
CREATE UNIQUE INDEX "identity_user_email_normalized_key"
ON "identity_user"("email_normalized");

CREATE UNIQUE INDEX "identity_provider_provider_subject_key"
ON "identity_provider_account"("provider", "provider_subject");

CREATE UNIQUE INDEX "identity_session_refresh_token_hash_key"
ON "identity_session"("refresh_token_hash");

CREATE UNIQUE INDEX "identity_email_token_type_hash_key"
ON "identity_email_token"("token_type", "token_hash");

CREATE UNIQUE INDEX "identity_application_app_key_key"
ON "identity_application"("app_key");

CREATE UNIQUE INDEX "identity_role_application_role_key"
ON "identity_role"("application_id", "role_key");

CREATE UNIQUE INDEX "identity_app_membership_user_application_key"
ON "identity_app_membership"("user_id", "application_id");

CREATE UNIQUE INDEX "identity_app_role_assignment_membership_role_key"
ON "identity_app_role_assignment"("membership_id", "role_id");

-- Performance indexes
CREATE INDEX "identity_user_status_idx"
ON "identity_user"("status");

CREATE INDEX "identity_provider_user_idx"
ON "identity_provider_account"("user_id");

CREATE INDEX "identity_provider_provider_email_idx"
ON "identity_provider_account"("provider", "provider_email");

CREATE INDEX "identity_session_user_expires_idx"
ON "identity_session"("user_id", "expires_at");

CREATE INDEX "identity_session_expires_idx"
ON "identity_session"("expires_at");

CREATE INDEX "identity_email_token_user_type_idx"
ON "identity_email_token"("user_id", "token_type");

CREATE INDEX "identity_email_token_expires_idx"
ON "identity_email_token"("expires_at");

CREATE INDEX "identity_audit_event_created_idx"
ON "identity_audit_log"("event_type", "created_at");

CREATE INDEX "identity_audit_actor_created_idx"
ON "identity_audit_log"("actor_user_id", "created_at");

CREATE INDEX "identity_audit_session_idx"
ON "identity_audit_log"("session_id");

CREATE INDEX "identity_role_application_idx"
ON "identity_role"("application_id");

CREATE INDEX "identity_app_membership_application_idx"
ON "identity_app_membership"("application_id");

CREATE INDEX "identity_app_membership_user_idx"
ON "identity_app_membership"("user_id");

CREATE INDEX "identity_app_membership_app_status_idx"
ON "identity_app_membership"("application_id", "global_status");

CREATE INDEX "identity_app_role_assignment_role_idx"
ON "identity_app_role_assignment"("role_id");

-- Foreign keys
ALTER TABLE "identity_provider_account"
ADD CONSTRAINT "identity_provider_account_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "identity_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_credential"
ADD CONSTRAINT "identity_credential_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "identity_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_session"
ADD CONSTRAINT "identity_session_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "identity_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_email_token"
ADD CONSTRAINT "identity_email_token_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "identity_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_audit_log"
ADD CONSTRAINT "identity_audit_log_actor_user_id_fkey"
FOREIGN KEY ("actor_user_id") REFERENCES "identity_user"("id")
ON DELETE SET NULL ON UPDATE NO ACTION;

ALTER TABLE "identity_audit_log"
ADD CONSTRAINT "identity_audit_log_session_id_fkey"
FOREIGN KEY ("session_id") REFERENCES "identity_session"("session_id")
ON DELETE SET NULL ON UPDATE NO ACTION;

ALTER TABLE "identity_role"
ADD CONSTRAINT "identity_role_application_id_fkey"
FOREIGN KEY ("application_id") REFERENCES "identity_application"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_app_membership"
ADD CONSTRAINT "identity_app_membership_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "identity_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_app_membership"
ADD CONSTRAINT "identity_app_membership_application_id_fkey"
FOREIGN KEY ("application_id") REFERENCES "identity_application"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_app_role_assignment"
ADD CONSTRAINT "identity_app_role_assignment_membership_id_fkey"
FOREIGN KEY ("membership_id") REFERENCES "identity_app_membership"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_app_role_assignment"
ADD CONSTRAINT "identity_app_role_assignment_role_id_fkey"
FOREIGN KEY ("role_id") REFERENCES "identity_role"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

