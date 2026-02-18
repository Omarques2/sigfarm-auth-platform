export type AuthWebEnv = {
  authApiBaseUrl: string;
  authWebBaseUrl: string;
  allowedReturnOrigins: string[];
  defaultReturnTo: string;
};

function normalizeUrl(value: string, key: string): string {
  try {
    return new URL(value).toString();
  } catch {
    throw new Error(`Invalid URL for ${key}: ${value}`);
  }
}

function normalizeOrigins(csv: string): string[] {
  return csv
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
    .map((item) => {
      try {
        return new URL(item).origin;
      } catch {
        throw new Error(`Invalid origin in VITE_AUTH_ALLOWED_RETURN_ORIGINS: ${item}`);
      }
    });
}

export function loadAuthWebEnv(rawEnv: ImportMetaEnv = import.meta.env): AuthWebEnv {
  const defaultWebBaseUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:5173";

  const authApiBaseUrl = normalizeUrl(
    rawEnv.VITE_AUTH_API_BASE_URL ?? "http://localhost:3000",
    "VITE_AUTH_API_BASE_URL",
  );
  const authWebBaseUrl = normalizeUrl(
    rawEnv.VITE_AUTH_WEB_BASE_URL ?? defaultWebBaseUrl,
    "VITE_AUTH_WEB_BASE_URL",
  );
  const fallbackReturnTo = new URL("/my-account", authWebBaseUrl).toString();
  const allowedReturnOrigins = normalizeOrigins(
    rawEnv.VITE_AUTH_ALLOWED_RETURN_ORIGINS ?? authWebBaseUrl,
  );
  const defaultReturnTo = normalizeUrl(
    rawEnv.VITE_AUTH_DEFAULT_RETURN_TO ?? fallbackReturnTo,
    "VITE_AUTH_DEFAULT_RETURN_TO",
  );

  return {
    authApiBaseUrl,
    authWebBaseUrl,
    allowedReturnOrigins,
    defaultReturnTo,
  };
}

export const authWebEnv = loadAuthWebEnv();
