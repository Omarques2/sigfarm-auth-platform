import type { AuthErrorCode, ErrorEnvelope } from "@sigfarm/auth-contracts";

export class AuthApiError extends Error {
  readonly status: number;
  readonly correlationId: string;
  readonly code: AuthErrorCode | null;
  readonly details: unknown;

  constructor(input: {
    message: string;
    status: number;
    correlationId: string;
    code?: AuthErrorCode | null;
    details?: unknown;
  }) {
    super(input.message);
    this.name = "AuthApiError";
    this.status = input.status;
    this.correlationId = input.correlationId;
    this.code = input.code ?? null;
    this.details = input.details ?? null;
  }
}

export class AuthContractError extends Error {
  readonly endpoint: string;
  readonly details: unknown;

  constructor(input: { endpoint: string; message: string; details?: unknown }) {
    super(input.message);
    this.name = "AuthContractError";
    this.endpoint = input.endpoint;
    this.details = input.details ?? null;
  }
}

export function readAuthErrorCode(details: unknown): AuthErrorCode | null {
  if (!details || typeof details !== "object") return null;

  const directCode = (details as { code?: unknown }).code;
  if (typeof directCode === "string") return directCode as AuthErrorCode;

  const nestedCode = (details as { error?: { code?: unknown } }).error?.code;
  if (typeof nestedCode === "string") return nestedCode as AuthErrorCode;

  return null;
}

export function readAuthErrorMessage(details: unknown): string | null {
  if (typeof details === "string" && details.length > 0) return details;
  if (!details || typeof details !== "object") return null;

  const fromEnvelope = (details as ErrorEnvelope).error?.message;
  if (typeof fromEnvelope === "string" && fromEnvelope.length > 0) return fromEnvelope;

  const fromRoot = (details as { message?: unknown }).message;
  if (typeof fromRoot === "string" && fromRoot.length > 0) return fromRoot;

  return null;
}