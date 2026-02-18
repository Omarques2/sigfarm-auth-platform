-- Add token type for verified email change flow
ALTER TYPE "IdentityEmailTokenType" ADD VALUE IF NOT EXISTS 'email_change';
