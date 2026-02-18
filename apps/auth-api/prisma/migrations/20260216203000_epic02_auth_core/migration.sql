-- EPIC-02 auth core tables and session hardening

ALTER TABLE "identity_session"
ADD COLUMN "auth_method" "IdentityProvider" NOT NULL DEFAULT 'password';

CREATE INDEX "identity_session_auth_method_idx"
ON "identity_session"("auth_method");

CREATE TABLE "identity_session_refresh_token" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "session_id" UUID NOT NULL,
    "token_hash" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "used_at" TIMESTAMPTZ(6),
    "revoked_at" TIMESTAMPTZ(6),
    CONSTRAINT "identity_session_refresh_token_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "identity_session_refresh_token_token_hash_key"
ON "identity_session_refresh_token"("token_hash");

CREATE INDEX "identity_session_refresh_session_idx"
ON "identity_session_refresh_token"("session_id");

CREATE INDEX "identity_session_refresh_used_idx"
ON "identity_session_refresh_token"("used_at");

ALTER TABLE "identity_session_refresh_token"
ADD CONSTRAINT "identity_session_refresh_token_session_id_fkey"
FOREIGN KEY ("session_id") REFERENCES "identity_session"("session_id")
ON DELETE CASCADE ON UPDATE NO ACTION;

CREATE TABLE "auth_user" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL,
    "email" CITEXT NOT NULL,
    "email_verified" BOOLEAN NOT NULL DEFAULT false,
    "image" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "auth_user_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_user_email_key"
ON "auth_user"("email");

CREATE TABLE "auth_session" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "token" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ip_address" TEXT,
    "user_agent" TEXT,
    "user_id" UUID NOT NULL,
    CONSTRAINT "auth_session_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_session_token_key"
ON "auth_session"("token");

CREATE INDEX "auth_session_user_idx"
ON "auth_session"("user_id");

CREATE TABLE "auth_account" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "account_id" TEXT NOT NULL,
    "provider_id" TEXT NOT NULL,
    "user_id" UUID NOT NULL,
    "access_token" TEXT,
    "refresh_token" TEXT,
    "id_token" TEXT,
    "access_token_expires_at" TIMESTAMPTZ(6),
    "refresh_token_expires_at" TIMESTAMPTZ(6),
    "scope" TEXT,
    "password" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "auth_account_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "auth_account_user_idx"
ON "auth_account"("user_id");

CREATE INDEX "auth_account_provider_subject_idx"
ON "auth_account"("provider_id", "account_id");

CREATE TABLE "auth_verification" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "identifier" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "auth_verification_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "auth_verification_identifier_idx"
ON "auth_verification"("identifier");

CREATE TABLE "auth_rate_limit" (
    "key" TEXT NOT NULL,
    "count" INTEGER NOT NULL,
    "last_request" INTEGER NOT NULL,
    CONSTRAINT "auth_rate_limit_pkey" PRIMARY KEY ("key")
);

ALTER TABLE "auth_session"
ADD CONSTRAINT "auth_session_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "auth_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "auth_account"
ADD CONSTRAINT "auth_account_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "auth_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;
