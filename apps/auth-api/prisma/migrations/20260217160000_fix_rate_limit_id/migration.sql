-- Better Auth >=1.4 writes `id` into rate limit records.
-- Previous schema used key as PK; this migration aligns table shape.

ALTER TABLE "auth_rate_limit"
ADD COLUMN IF NOT EXISTS "id" TEXT;

UPDATE "auth_rate_limit"
SET "id" = "key"
WHERE "id" IS NULL;

ALTER TABLE "auth_rate_limit"
ALTER COLUMN "id" SET NOT NULL;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'auth_rate_limit_pkey'
  ) THEN
    ALTER TABLE "auth_rate_limit"
    DROP CONSTRAINT "auth_rate_limit_pkey";
  END IF;
END $$;

ALTER TABLE "auth_rate_limit"
ADD CONSTRAINT "auth_rate_limit_pkey" PRIMARY KEY ("id");

CREATE UNIQUE INDEX IF NOT EXISTS "auth_rate_limit_key_key"
ON "auth_rate_limit"("key");
