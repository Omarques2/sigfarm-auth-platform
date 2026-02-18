-- Better Auth database rate limiter may omit id when DB is configured for generated IDs.
-- Ensure auth_rate_limit.id is generated server-side.

ALTER TABLE "auth_rate_limit"
ALTER COLUMN "id" SET DEFAULT gen_random_uuid()::text;
