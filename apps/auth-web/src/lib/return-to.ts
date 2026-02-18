type ResolveReturnToInput = {
  returnTo: string | null | undefined;
  appBaseUrl: string;
  defaultReturnTo: string;
  allowedOrigins: string[];
  referrer?: string;
};

const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
const AUTH_PORTAL_PATHS = new Set(["/", "/login", "/auth/callback", "/verify-email", "/reset-password"]);

export function resolveSafeReturnTo(input: ResolveReturnToInput): string {
  const byQuery = resolveCandidate(input.returnTo, input);
  if (byQuery) return byQuery;

  const byReferrer = resolveCandidate(input.referrer, input);
  if (byReferrer) return byReferrer;

  return input.defaultReturnTo;
}

function resolveCandidate(
  rawCandidate: string | null | undefined,
  input: ResolveReturnToInput,
): string | null {
  if (!rawCandidate) return null;
  const candidate = safelyDecode(rawCandidate);
  if (!candidate) return null;

  if (candidate.startsWith("/")) {
    const parsed = new URL(candidate, input.appBaseUrl);
    if (isBlockedAuthPortalTarget(parsed, input.appBaseUrl)) return null;
    return parsed.toString();
  }

  try {
    const parsed = new URL(candidate);
    if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) return null;
    if (!input.allowedOrigins.includes(parsed.origin)) return null;
    if (isBlockedAuthPortalTarget(parsed, input.appBaseUrl)) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

function isBlockedAuthPortalTarget(candidate: URL, appBaseUrl: string): boolean {
  const appOrigin = new URL(appBaseUrl).origin;
  if (candidate.origin !== appOrigin) return false;
  const normalizedPath = normalizePath(candidate.pathname);
  return AUTH_PORTAL_PATHS.has(normalizedPath);
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
