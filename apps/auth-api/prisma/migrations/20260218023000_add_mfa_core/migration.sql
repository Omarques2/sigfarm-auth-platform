-- MFA core tables: TOTP enrollment, recovery codes and login challenges.

CREATE TABLE "identity_mfa_totp" (
    "user_id" UUID NOT NULL,
    "secret_ciphertext" TEXT NOT NULL,
    "secret_iv" TEXT NOT NULL,
    "secret_tag" TEXT NOT NULL,
    "enabled_at" TIMESTAMPTZ(6),
    "last_verified_at" TIMESTAMPTZ(6),
    "disabled_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_mfa_totp_pkey" PRIMARY KEY ("user_id")
);

CREATE INDEX "identity_mfa_totp_enabled_idx"
ON "identity_mfa_totp"("enabled_at");

CREATE TABLE "identity_mfa_recovery_code" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "code_hash" TEXT NOT NULL,
    "used_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_mfa_recovery_code_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "identity_mfa_recovery_code_code_hash_key"
ON "identity_mfa_recovery_code"("code_hash");

CREATE INDEX "identity_mfa_recovery_user_used_idx"
ON "identity_mfa_recovery_code"("user_id", "used_at");

CREATE TABLE "identity_mfa_challenge" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "challenge_hash" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "verified_at" TIMESTAMPTZ(6),
    "method_used" TEXT,
    "ip" TEXT,
    "user_agent" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "identity_mfa_challenge_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "identity_mfa_challenge_challenge_hash_key"
ON "identity_mfa_challenge"("challenge_hash");

CREATE INDEX "identity_mfa_challenge_user_expires_idx"
ON "identity_mfa_challenge"("user_id", "expires_at");

CREATE INDEX "identity_mfa_challenge_expires_idx"
ON "identity_mfa_challenge"("expires_at");

ALTER TABLE "identity_mfa_totp"
ADD CONSTRAINT "identity_mfa_totp_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "identity_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_mfa_recovery_code"
ADD CONSTRAINT "identity_mfa_recovery_code_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "identity_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;

ALTER TABLE "identity_mfa_challenge"
ADD CONSTRAINT "identity_mfa_challenge_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "identity_user"("id")
ON DELETE CASCADE ON UPDATE NO ACTION;
