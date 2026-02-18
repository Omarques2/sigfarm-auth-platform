export type ResolveReturnToInput = {
  returnTo: string | null | undefined;
  appBaseUrl: string;
  authPortalBaseUrl?: string;
  defaultReturnTo: string;
  allowedOrigins: string[];
  referrer?: string;
};

const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
const AUTH_PORTAL_PATHS = new Set(["/", "/login", "/auth/callback", "/verify-email", "/reset-password"]);

export function resolveSafeReturnTo(input: ResolveReturnToInput): string {
  const fromQuery = resolveCandidate(input.returnTo, input);
  if (fromQuery) return fromQuery;

  const fromReferrer = resolveCandidate(input.referrer, input);
  if (fromReferrer) return fromReferrer;

  return input.defaultReturnTo;
}

function resolveCandidate(rawCandidate: string | null | undefined, input: ResolveReturnToInput): string | null {
  if (!rawCandidate) return null;

  const candidate = safelyDecode(rawCandidate);
  if (!candidate) return null;

  if (candidate.startsWith("/")) {
    const resolved = new URL(candidate, input.appBaseUrl);
    if (isBlockedTarget(resolved, input)) return null;
    return resolved.toString();
  }

  try {
    const resolved = new URL(candidate);
    if (!ALLOWED_PROTOCOLS.has(resolved.protocol)) return null;
    if (!input.allowedOrigins.includes(resolved.origin)) return null;
    if (isBlockedTarget(resolved, input)) return null;
    return resolved.toString();
  } catch {
    return null;
  }
}

function isBlockedTarget(candidate: URL, input: ResolveReturnToInput): boolean {
  const normalizedPath = normalizePath(candidate.pathname);

  const appOrigin = new URL(input.appBaseUrl).origin;
  if (candidate.origin === appOrigin && AUTH_PORTAL_PATHS.has(normalizedPath)) {
    return true;
  }

  if (!input.authPortalBaseUrl) return false;

  const authPortalOrigin = new URL(input.authPortalBaseUrl).origin;
  if (candidate.origin === authPortalOrigin && AUTH_PORTAL_PATHS.has(normalizedPath)) {
    return true;
  }

  return false;
}

function normalizePath(path: string): string {
  const lowered = path.toLowerCase();
  if (lowered === "/") return lowered;
  return lowered.endsWith("/") ? lowered.slice(0, -1) : lowered;
}

function safelyDecode(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}