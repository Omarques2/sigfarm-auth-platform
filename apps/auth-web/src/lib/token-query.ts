export function readTokenFromQuery(query: Record<string, unknown>): string | undefined {
  const raw = firstQueryValue(query.token) ?? firstQueryValue(query.Token);
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  return decodeTokenOnce(normalizeOpaqueToken(trimmed));
}

export function readTokenFromLocation(
  query: Record<string, unknown>,
  locationSearch?: string,
): string | undefined {
  const raw = firstTokenFromSearch(resolveLocationSearch(locationSearch));
  if (raw) {
    const trimmed = raw.trim();
    if (trimmed) {
      return decodeTokenOnce(normalizeOpaqueToken(trimmed));
    }
  }
  return readTokenFromQuery(query);
}

function firstQueryValue(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return undefined;
}

function firstTokenFromSearch(search: string): string | undefined {
  const query = search.startsWith("?") ? search.slice(1) : search;
  if (!query) return undefined;

  for (const entry of query.split("&")) {
    if (!entry) continue;
    const separatorIndex = entry.indexOf("=");
    const rawKey = separatorIndex >= 0 ? entry.slice(0, separatorIndex) : entry;
    const rawValue = separatorIndex >= 0 ? entry.slice(separatorIndex + 1) : "";
    const key = decodeTokenOnce(rawKey);
    if (key !== "token" && key !== "Token") continue;
    return decodeTokenOnce(rawValue);
  }

  return undefined;
}

function resolveLocationSearch(override?: string): string {
  if (typeof override === "string") return override;
  if (typeof window === "undefined") return "";
  return window.location.search;
}

function normalizeOpaqueToken(value: string): string {
  if (!value.includes(" ")) return value;
  return value.replaceAll(" ", "+");
}

function decodeTokenOnce(value: string): string {
  if (!value.includes("%")) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
