import { createHash } from "node:crypto";

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;
export const DEFAULT_PWNED_PASSWORD_TIMEOUT_MS = 1_800;

export const PASSWORD_POLICY_MESSAGE =
  "A senha deve ter entre 12 e 128 caracteres.";

export const PASSWORD_COMPROMISED_MESSAGE =
  "Essa senha já apareceu em vazamentos conhecidos. Escolha outra.";

const PWNED_PASSWORDS_RANGE_URL = "https://api.pwnedpasswords.com/range";
const DEFAULT_PWNED_USER_AGENT = "sigfarm-auth-platform/1.0";

type Rule = {
  test: (password: string) => boolean;
};

export type PasswordCompromiseCheckOptions = {
  enabled?: boolean;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
};

const RULES: Rule[] = [
  { test: (password) => password.length >= PASSWORD_MIN_LENGTH },
  { test: (password) => password.length <= PASSWORD_MAX_LENGTH },
];

export function isPasswordPolicyCompliant(password: string): boolean {
  return RULES.every((rule) => rule.test(password));
}

export async function getPwnedPasswordReuseCount(
  password: string,
  options?: PasswordCompromiseCheckOptions,
): Promise<number | null> {
  if (!options?.enabled || password.length === 0) {
    return null;
  }

  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    return null;
  }

  const digest = createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
  const prefix = digest.slice(0, 5);
  const suffix = digest.slice(5);

  const timeoutMs = Math.max(500, options.timeoutMs ?? DEFAULT_PWNED_PASSWORD_TIMEOUT_MS);
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchImpl(`${PWNED_PASSWORDS_RANGE_URL}/${prefix}`, {
      headers: {
        "Add-Padding": "true",
        "User-Agent": DEFAULT_PWNED_USER_AGENT,
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      return null;
    }

    const body = await response.text();
    return parsePwnedPasswordRangeResponse(body, suffix);
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutHandle);
  }
}

export async function isPasswordCompromised(
  password: string,
  options?: PasswordCompromiseCheckOptions,
): Promise<boolean> {
  const reuseCount = await getPwnedPasswordReuseCount(password, options);
  return typeof reuseCount === "number" && reuseCount > 0;
}

function parsePwnedPasswordRangeResponse(body: string, suffix: string): number {
  const expectedSuffix = suffix.toUpperCase();

  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;

    const [lineSuffix, rawCount] = line.split(":");
    if (!lineSuffix || !rawCount) continue;
    if (lineSuffix.toUpperCase() !== expectedSuffix) continue;

    const parsedCount = Number.parseInt(rawCount, 10);
    if (Number.isFinite(parsedCount) && parsedCount >= 0) {
      return parsedCount;
    }
  }

  return 0;
}
