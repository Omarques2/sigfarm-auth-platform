-- Better Auth rate limiter writes unix time in milliseconds.
-- INT overflows; use BIGINT for compatibility and future-proofing.

ALTER TABLE "auth_rate_limit"
ALTER COLUMN "last_request" TYPE BIGINT
USING "last_request"::BIGINT;
