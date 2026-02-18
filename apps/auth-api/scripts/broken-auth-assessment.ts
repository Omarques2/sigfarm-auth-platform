import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildServer } from "../src/index.js";
import { loadEnv } from "../src/config/env.js";
import { getPrismaClient } from "../src/db/prisma.js";
import { hashOpaqueToken } from "../src/auth/session.service.js";

type TestStatus = "pass" | "fail" | "warn";

type TestResult = {
  id: string;
  category: string;
  title: string;
  status: TestStatus;
  severity: "low" | "medium" | "high" | "critical";
  evidence: string;
  recommendation?: string;
};

type CookieJar = {
  update(setCookieHeader: string[] | string | undefined): void;
  toHeader(): string | undefined;
};

function createCookieJar(): CookieJar {
  const store = new Map<string, string>();
  return {
    update(setCookieHeader) {
      if (!setCookieHeader) return;
      const lines = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
      for (const line of lines) {
        const pair = line.split(";", 1)[0]?.trim();
        if (!pair) continue;
        const separator = pair.indexOf("=");
        if (separator < 1) continue;
        const name = pair.slice(0, separator).trim();
        const value = pair.slice(separator + 1).trim();
        store.set(name, value);
      }
    },
    toHeader() {
      if (store.size < 1) return undefined;
      return [...store.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    },
  };
}

async function request(
  app: Awaited<ReturnType<typeof buildServer>>,
  input: {
    method: "GET" | "POST" | "OPTIONS";
    url: string;
    payload?: unknown;
    headers?: Record<string, string>;
    jar?: CookieJar;
  },
) {
  const headers = { ...(input.headers ?? {}) };
  const cookieHeader = input.jar?.toHeader();
  if (cookieHeader) headers.cookie = cookieHeader;

  const response = await app.inject({
    method: input.method,
    url: input.url,
    payload: input.payload,
    headers,
  });
  input.jar?.update(response.headers["set-cookie"]);
  return response;
}

function addResult(results: TestResult[], result: TestResult): void {
  results.push(result);
}

async function clearRateLimitState(prisma: ReturnType<typeof getPrismaClient>): Promise<void> {
  await prisma.rateLimit.deleteMany();
}

async function activateTestUser(
  prisma: ReturnType<typeof getPrismaClient>,
  email: string,
): Promise<{ userId: string } | null> {
  const user = await prisma.user.findUnique({
    where: { email },
  });
  if (!user) return null;

  await prisma.user.update({
    where: { id: user.id },
    data: { emailVerified: true },
  });

  await prisma.identityUser.updateMany({
    where: { id: user.id },
    data: {
      emailVerifiedAt: new Date(),
      status: "active",
    },
  });

  return { userId: user.id };
}

async function run(): Promise<void> {
  const rawEnv = loadEnv();
  const env = {
    ...rawEnv,
    emailProvider: "console" as const,
  };

  const app = await buildServer({ env });
  const prisma = getPrismaClient();
  const results: TestResult[] = [];

  const baselineJar = createCookieJar();
  const testEmail = `security-${Date.now()}@sigfarm.test`;
  const testPassword = "S3curityStrong!2026";
  const callbackUrl = "http://localhost:5173/auth/callback";

  try {
    await clearRateLimitState(prisma);

    const health = await request(app, { method: "GET", url: "/health" });
    addResult(results, {
      id: "AUTH-001",
      category: "surface",
      title: "Health endpoint available",
      status: health.statusCode === 200 ? "pass" : "fail",
      severity: "low",
      evidence: `GET /health => ${health.statusCode}`,
    });

    const jwks = await request(app, { method: "GET", url: "/.well-known/jwks.json" });
    const jwksBody = jwks.json() as { keys?: Array<Record<string, unknown>> };
    const keyHasPrivateMaterial = Boolean(
      jwksBody.keys?.some((k) => "d" in k || "p" in k || "q" in k),
    );
    addResult(results, {
      id: "AUTH-002",
      category: "token",
      title: "JWKS does not leak private key material",
      status: jwks.statusCode === 200 && !keyHasPrivateMaterial ? "pass" : "fail",
      severity: "high",
      evidence: `GET /.well-known/jwks.json => ${jwks.statusCode}; privateFields=${keyHasPrivateMaterial}`,
      recommendation: keyHasPrivateMaterial
        ? "Expose only public JWK components."
        : undefined,
    });

    const unauthAccount = await request(app, { method: "GET", url: "/v1/auth/account" });
    addResult(results, {
      id: "AUTH-003",
      category: "authorization",
      title: "Protected account endpoint blocks unauthenticated access",
      status: unauthAccount.statusCode === 401 ? "pass" : "fail",
      severity: "high",
      evidence: `GET /v1/auth/account without auth => ${unauthAccount.statusCode}`,
      recommendation:
        unauthAccount.statusCode !== 401
          ? "Require active authenticated session/JWT for account endpoints."
          : undefined,
    });

    const forgedJwt = [
      Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" }), "utf8").toString("base64url"),
      Buffer.from(
        JSON.stringify({
          sub: "00000000-0000-0000-0000-000000000000",
          sid: "forged",
          amr: "password",
        }),
        "utf8",
      ).toString("base64url"),
      "",
    ].join(".");
    const forgedSession = await request(app, {
      method: "GET",
      url: "/v1/auth/session",
      headers: {
        authorization: `Bearer ${forgedJwt}`,
      },
    });
    addResult(results, {
      id: "AUTH-004",
      category: "token",
      title: "Forged JWT (alg=none) rejected",
      status: forgedSession.statusCode === 401 ? "pass" : "fail",
      severity: "critical",
      evidence: `GET /v1/auth/session with forged JWT => ${forgedSession.statusCode}`,
      recommendation:
        forgedSession.statusCode !== 401
          ? "Enforce strict signature validation and accepted algorithms."
          : undefined,
    });

    const weakSignUp = await request(app, {
      method: "POST",
      url: "/api/auth/sign-up/email",
      payload: {
        email: `weak-${Date.now()}@sigfarm.test`,
        name: "Weak Password",
        password: "weakpass",
        callbackURL: callbackUrl,
      },
      headers: {
        origin: "http://localhost:5173",
      },
    });
    const weakSignUpBody = weakSignUp.json() as { error?: { code?: string } };
    addResult(results, {
      id: "AUTH-005",
      category: "password-policy",
      title: "Weak password blocked at sign-up",
      status:
        weakSignUp.statusCode === 422 &&
        weakSignUpBody.error?.code === "PASSWORD_POLICY_VIOLATION"
          ? "pass"
          : "fail",
      severity: "high",
      evidence: `POST /api/auth/sign-up/email weak password => ${weakSignUp.statusCode}, code=${weakSignUpBody.error?.code ?? "n/a"}`,
      recommendation:
        weakSignUp.statusCode !== 422
          ? "Enforce strong password policy server-side."
          : undefined,
    });

    const weakReset = await request(app, {
      method: "POST",
      url: "/api/auth/reset-password",
      payload: {
        token: "dummy-token",
        newPassword: "weakpass",
      },
      headers: {
        origin: "http://localhost:5173",
      },
    });
    const weakResetBody = weakReset.json() as { error?: { code?: string } };
    addResult(results, {
      id: "AUTH-006",
      category: "password-policy",
      title: "Weak password blocked at reset-password endpoint",
      status:
        weakReset.statusCode === 422 &&
        weakResetBody.error?.code === "PASSWORD_POLICY_VIOLATION"
          ? "pass"
          : "fail",
      severity: "high",
      evidence: `POST /api/auth/reset-password weak password => ${weakReset.statusCode}, code=${weakResetBody.error?.code ?? "n/a"}`,
    });

    const signUp = await request(app, {
      method: "POST",
      url: "/api/auth/sign-up/email",
      payload: {
        email: testEmail,
        name: "Security Test User",
        password: testPassword,
        callbackURL: callbackUrl,
      },
      headers: {
        origin: "http://localhost:5173",
      },
    });
    addResult(results, {
      id: "AUTH-007",
      category: "baseline",
      title: "Create dedicated security test account",
      status: signUp.statusCode === 200 ? "pass" : "warn",
      severity: "low",
      evidence: `POST /api/auth/sign-up/email => ${signUp.statusCode}`,
      recommendation:
        signUp.statusCode !== 200
          ? "If already exists, cleanup test account between executions."
          : undefined,
    });

    const signInBeforeVerification = await request(app, {
      method: "POST",
      url: "/api/auth/sign-in/email",
      payload: {
        email: testEmail,
        password: testPassword,
        callbackURL: callbackUrl,
      },
      headers: {
        origin: "http://localhost:5173",
      },
    });
    addResult(results, {
      id: "AUTH-008",
      category: "baseline",
      title: "Unverified account is blocked from email/password sign-in",
      status:
        env.requireEmailVerification && signInBeforeVerification.statusCode === 403
          ? "pass"
          : env.requireEmailVerification
            ? "fail"
            : "warn",
      severity: "medium",
      evidence: `requireEmailVerification=${env.requireEmailVerification}; signInStatus=${signInBeforeVerification.statusCode}`,
      recommendation:
        env.requireEmailVerification && signInBeforeVerification.statusCode !== 403
          ? "Block sign-in until email ownership is verified."
          : undefined,
    });

    const activation = await activateTestUser(prisma, testEmail);
    if (!activation) {
      throw new Error(`Could not activate test user: ${testEmail}`);
    }

    const preLoginFake = createCookieJar();
    preLoginFake.update("better-auth.session_token=attacker-fixed; Path=/; HttpOnly");
    const preSession = await request(app, {
      method: "GET",
      url: "/api/auth/get-session",
      jar: preLoginFake,
      headers: {
        origin: "http://localhost:5173",
      },
    });
    const preSessionBody = preSession.json() as unknown;
    addResult(results, {
      id: "AUTH-009",
      category: "session",
      title: "Arbitrary pre-auth session cookie does not grant session",
      status:
        preSession.statusCode === 200 &&
        preSessionBody &&
        typeof preSessionBody === "object" &&
        "session" in (preSessionBody as Record<string, unknown>) === false
          ? "pass"
          : "warn",
      severity: "high",
      evidence: `GET /api/auth/get-session with forged cookie => ${preSession.statusCode}`,
      recommendation:
        "Manually review session fixation protections with browser-level test if needed.",
    });

    const login = await request(app, {
      method: "POST",
      url: "/api/auth/sign-in/email",
      payload: {
        email: testEmail,
        password: testPassword,
        callbackURL: callbackUrl,
      },
      jar: baselineJar,
      headers: {
        origin: "http://localhost:5173",
      },
    });
    const loginSetCookies = login.headers["set-cookie"];
    const loginCookieLines = Array.isArray(loginSetCookies) ? loginSetCookies : loginSetCookies ? [loginSetCookies] : [];
    const hasHttpOnly = loginCookieLines.some((line) => /httponly/i.test(line));
    const hasSameSite = loginCookieLines.some((line) => /samesite/i.test(line));
    const hasSecure = loginCookieLines.some((line) => /;\s*secure/i.test(line));
    addResult(results, {
      id: "AUTH-010",
      category: "session",
      title: "Login succeeds and sets cookie with HttpOnly/SameSite flags",
      status: login.statusCode === 200 && hasHttpOnly && hasSameSite ? "pass" : "fail",
      severity: "high",
      evidence: `POST /api/auth/sign-in/email => ${login.statusCode}; httpOnly=${hasHttpOnly}; sameSite=${hasSameSite}; secure=${hasSecure}`,
      recommendation:
        !hasHttpOnly || !hasSameSite
          ? "Set HttpOnly and SameSite on all session cookies."
          : undefined,
    });
    if (!hasSecure) {
      addResult(results, {
        id: "AUTH-011",
        category: "session",
        title: "Secure cookie flag not present",
        status: env.nodeEnv === "production" ? "fail" : "warn",
        severity: "medium",
        evidence: `secureFlag=${hasSecure}; nodeEnv=${env.nodeEnv}`,
        recommendation:
          "Ensure cookies are Secure in staging/production (HTTPS only).",
      });
    }

    const account = await request(app, {
      method: "GET",
      url: "/v1/auth/account",
      jar: baselineJar,
    });
    const accountBody = account.json() as { data?: { userId?: string; email?: string } };
    const userId = accountBody.data?.userId ?? "";
    addResult(results, {
      id: "AUTH-012",
      category: "authorization",
      title: "Authenticated session can read own account profile",
      status: account.statusCode === 200 && accountBody.data?.email === testEmail.toLowerCase() ? "pass" : "fail",
      severity: "medium",
      evidence: `GET /v1/auth/account => ${account.statusCode}; email=${accountBody.data?.email ?? "n/a"}`,
    });

    const refreshExchange = await request(app, {
      method: "POST",
      url: "/v1/auth/refresh",
      payload: {},
      jar: baselineJar,
    });
    const refreshExchangeBody = refreshExchange.json() as {
      data?: { accessToken?: string; refreshToken?: string };
    };
    const accessToken = refreshExchangeBody.data?.accessToken ?? "";
    const refreshToken = refreshExchangeBody.data?.refreshToken ?? "";
    addResult(results, {
      id: "AUTH-013",
      category: "token",
      title: "Session exchange issues access and refresh tokens",
      status:
        refreshExchange.statusCode === 200 &&
        accessToken.length > 40 &&
        refreshToken.length > 30
          ? "pass"
          : "fail",
      severity: "high",
      evidence: `POST /v1/auth/refresh (cookie) => ${refreshExchange.statusCode}; accessLen=${accessToken.length}; refreshLen=${refreshToken.length}`,
    });

    if (refreshToken) {
      const rotated = await request(app, {
        method: "POST",
        url: "/v1/auth/refresh",
        payload: { refreshToken },
      });
      const rotatedBody = rotated.json() as { data?: { refreshToken?: string } };
      const rotatedToken = rotatedBody.data?.refreshToken ?? "";

      const reusedOld = await request(app, {
        method: "POST",
        url: "/v1/auth/refresh",
        payload: { refreshToken },
      });
      const reusedNewAfterReuse = rotatedToken
        ? await request(app, {
            method: "POST",
            url: "/v1/auth/refresh",
            payload: { refreshToken: rotatedToken },
          })
        : null;

      addResult(results, {
        id: "AUTH-014",
        category: "token",
        title: "Refresh rotation works and reuse invalidates session chain",
        status:
          rotated.statusCode === 200 &&
          reusedOld.statusCode === 401 &&
          reusedNewAfterReuse?.statusCode === 401
            ? "pass"
            : "fail",
        severity: "critical",
        evidence: `rotate=${rotated.statusCode}; reuseOld=${reusedOld.statusCode}; reuseNewAfterReuse=${reusedNewAfterReuse?.statusCode ?? "n/a"}`,
        recommendation:
          reusedOld.statusCode !== 401
            ? "Enable refresh-token reuse detection and family revocation."
            : undefined,
      });
    }

    const relogin = await request(app, {
      method: "POST",
      url: "/api/auth/sign-in/email",
      payload: {
        email: testEmail,
        password: testPassword,
        callbackURL: callbackUrl,
      },
      jar: baselineJar,
      headers: {
        origin: "http://localhost:5173",
      },
    });
    const reloginExchange = await request(app, {
      method: "POST",
      url: "/v1/auth/refresh",
      payload: {},
      jar: baselineJar,
    });
    const reloginExchangeBody = reloginExchange.json() as {
      data?: { accessToken?: string };
    };
    const accessTokenForLogout = reloginExchangeBody.data?.accessToken ?? "";
    const protectedWithAccess = accessTokenForLogout
      ? await request(app, {
          method: "GET",
          url: "/v1/auth/session",
          headers: { authorization: `Bearer ${accessTokenForLogout}` },
        })
      : null;
    const logoutByAccess = accessTokenForLogout
      ? await request(app, {
          method: "POST",
          url: "/v1/auth/logout",
          headers: { authorization: `Bearer ${accessTokenForLogout}` },
        })
      : null;
    const protectedAfterLogout = accessTokenForLogout
      ? await request(app, {
          method: "GET",
          url: "/v1/auth/session",
          headers: { authorization: `Bearer ${accessTokenForLogout}` },
        })
      : null;
    addResult(results, {
      id: "AUTH-015",
      category: "session",
      title: "Bearer access is revoked after logout",
      status:
        relogin.statusCode === 200 &&
        reloginExchange.statusCode === 200 &&
        protectedWithAccess?.statusCode === 200 &&
        logoutByAccess?.statusCode === 200 &&
        protectedAfterLogout?.statusCode === 401
          ? "pass"
          : "fail",
      severity: "high",
      evidence: `relogin=${relogin.statusCode}; exchange=${reloginExchange.statusCode}; before=${protectedWithAccess?.statusCode ?? "n/a"}; logout=${logoutByAccess?.statusCode ?? "n/a"}; after=${protectedAfterLogout?.statusCode ?? "n/a"}`,
    });

    const knownDiscovery = await request(app, {
      method: "POST",
      url: "/v1/auth/email/discover",
      payload: { email: testEmail },
    });
    const unknownDiscovery = await request(app, {
      method: "POST",
      url: "/v1/auth/email/discover",
      payload: { email: `nope-${Date.now()}@sigfarm.test` },
    });
    const knownState = (knownDiscovery.json() as { data?: { accountState?: string } }).data
      ?.accountState;
    const unknownState = (unknownDiscovery.json() as { data?: { accountState?: string } }).data
      ?.accountState;
    addResult(results, {
      id: "AUTH-016",
      category: "enumeration",
      title: "Email discovery endpoint leaks account existence/state",
      status: knownState !== unknownState ? "fail" : "pass",
      severity: "medium",
      evidence: `known=${knownState ?? "n/a"}; unknown=${unknownState ?? "n/a"}`,
      recommendation:
        knownState !== unknownState
          ? "Return generic state for unauthenticated discovery to reduce enumeration risk."
          : undefined,
    });

    const invalidResetCodeAttempts: number[] = [];
    await request(app, {
      method: "POST",
      url: "/v1/auth/password-reset/request-code",
      payload: { email: testEmail },
    });
    for (let i = 0; i < 20; i += 1) {
      const code = String(100000 + i);
      const response = await request(app, {
        method: "POST",
        url: "/v1/auth/password-reset/verify-code",
        payload: { email: testEmail, code },
      });
      invalidResetCodeAttempts.push(response.statusCode);
    }
    const hasOtpRateLimit = invalidResetCodeAttempts.some((code) => code === 429);
    addResult(results, {
      id: "AUTH-017",
      category: "brute-force",
      title: "Password reset code verification has anti-bruteforce throttling",
      status: hasOtpRateLimit ? "pass" : "fail",
      severity: "high",
      evidence: `verify-code status sequence=${invalidResetCodeAttempts.join(",")}`,
      recommendation:
        !hasOtpRateLimit
          ? "Add per-user/per-IP rate limiting and lockout on reset-code verification."
          : undefined,
    });

    const emailSame = await request(app, {
      method: "POST",
      url: "/v1/auth/account/email-change/request-code",
      payload: { newEmail: testEmail },
      jar: baselineJar,
    });
    const emailSameBody = emailSame.json() as { data?: { status?: string } };
    addResult(results, {
      id: "AUTH-018",
      category: "account-change",
      title: "Email change rejects same email as current",
      status:
        emailSame.statusCode === 200 && emailSameBody.data?.status === "same_as_current"
          ? "pass"
          : "fail",
      severity: "medium",
      evidence: `same email request => ${emailSame.statusCode}; status=${emailSameBody.data?.status ?? "n/a"}`,
    });

    const emailConfirmWithoutValidCode = await request(app, {
      method: "POST",
      url: "/v1/auth/account/email-change/confirm-code",
      payload: { newEmail: `new-${Date.now()}@sigfarm.test`, code: "000000" },
      jar: baselineJar,
    });
    const emailConfirmWithoutValidCodeBody = emailConfirmWithoutValidCode.json() as {
      data?: { updated?: boolean };
    };
    addResult(results, {
      id: "AUTH-019",
      category: "account-change",
      title: "Email change confirmation rejects invalid code",
      status:
        emailConfirmWithoutValidCode.statusCode === 200 &&
        emailConfirmWithoutValidCodeBody.data?.updated === false
          ? "pass"
          : "fail",
      severity: "high",
      evidence: `confirm invalid code => ${emailConfirmWithoutValidCode.statusCode}; updated=${emailConfirmWithoutValidCodeBody.data?.updated}`,
    });

    if (userId) {
      try {
        const code = "654321";
        const newEmail = `validated-${Date.now()}@sigfarm.test`;
        const tokenHash = hashOpaqueToken(`email_change:${newEmail}:${code}`, env.betterAuthSecret);
        await prisma.identityEmailToken.create({
          data: {
            userId,
            tokenType: "email_change",
            tokenHash,
            expiresAt: new Date(Date.now() + 10 * 60 * 1000),
          },
        });
        const confirmValid = await request(app, {
          method: "POST",
          url: "/v1/auth/account/email-change/confirm-code",
          payload: {
            newEmail,
            code,
          },
          jar: baselineJar,
        });
        const confirmValidBody = confirmValid.json() as { data?: { updated?: boolean } };
        const updatedProfile = await request(app, {
          method: "GET",
          url: "/v1/auth/account",
          jar: baselineJar,
        });
        const updatedProfileBody = updatedProfile.json() as {
          data?: { email?: string; emailVerified?: boolean };
        };
        addResult(results, {
          id: "AUTH-020",
          category: "account-change",
          title: "Email change updates account only after valid code",
          status:
            confirmValid.statusCode === 200 &&
            confirmValidBody.data?.updated === true &&
            updatedProfileBody.data?.email === newEmail &&
            updatedProfileBody.data?.emailVerified === true
              ? "pass"
              : "fail",
          severity: "high",
          evidence: `confirm=${confirmValid.statusCode}; updated=${confirmValidBody.data?.updated}; accountEmail=${updatedProfileBody.data?.email ?? "n/a"}`,
        });
      } catch (error) {
        addResult(results, {
          id: "AUTH-020",
          category: "account-change",
          title: "Email change updates account only after valid code",
          status: "fail",
          severity: "high",
          evidence: `Unexpected error when validating email-change flow: ${error instanceof Error ? error.message : String(error)}`,
          recommendation:
            "Fix IdentityEmailToken enum compatibility between Prisma schema and database migration.",
        });
      }
    }

    const externalRedirectReset = await request(app, {
      method: "POST",
      url: "/api/auth/request-password-reset",
      payload: {
        email: testEmail,
        redirectTo: "https://evil.local/reset",
      },
      headers: {
        origin: "http://localhost:5173",
      },
    });
    addResult(results, {
      id: "AUTH-021",
      category: "open-redirect",
      title: "Password reset rejects untrusted redirect host",
      status: externalRedirectReset.statusCode >= 400 ? "pass" : "fail",
      severity: "high",
      evidence: `POST /api/auth/request-password-reset redirectTo=evil => ${externalRedirectReset.statusCode}`,
      recommendation:
        externalRedirectReset.statusCode < 400
          ? "Allowlist callback/redirect origins for password reset links."
          : undefined,
    });

    await clearRateLimitState(prisma);
    const bruteForceStatuses: number[] = [];
    for (let i = 0; i < 14; i += 1) {
      const response = await request(app, {
        method: "POST",
        url: "/api/auth/sign-in/email",
        payload: {
          email: `no-user-${Date.now()}@sigfarm.test`,
          password: "InvalidPassword!123",
          callbackURL: callbackUrl,
        },
        headers: { origin: "http://localhost:5173" },
      });
      bruteForceStatuses.push(response.statusCode);
    }
    const bruteForceBlocked = bruteForceStatuses.includes(429);
    addResult(results, {
      id: "AUTH-022",
      category: "brute-force",
      title: "Sign-in endpoint triggers lockout/rate-limit under repeated failures",
      status: bruteForceBlocked ? "pass" : "fail",
      severity: "high",
      evidence: `status sequence=${bruteForceStatuses.join(",")}`,
      recommendation:
        !bruteForceBlocked ? "Lower threshold and enforce IP/user-based login throttling." : undefined,
    });

    await clearRateLimitState(prisma);
    const bypassStatuses: number[] = [];
    for (let i = 0; i < 12; i += 1) {
      const response = await request(app, {
        method: "POST",
        url: "/api/auth/sign-in/email",
        payload: {
          email: `no-user-${Date.now()}@sigfarm.test`,
          password: "InvalidPassword!123",
          callbackURL: callbackUrl,
        },
        headers: {
          origin: "http://localhost:5173",
          "x-forwarded-for": `10.10.10.${i + 1}`,
        },
      });
      bypassStatuses.push(response.statusCode);
    }
    const bypassSucceeded = !bypassStatuses.includes(429);
    addResult(results, {
      id: "AUTH-023",
      category: "brute-force",
      title: "Rate limit resistant to X-Forwarded-For spoofing",
      status: bypassSucceeded ? "fail" : "pass",
      severity: "high",
      evidence: `spoofed XFF status sequence=${bypassStatuses.join(",")}`,
      recommendation:
        bypassSucceeded
          ? "Use trusted proxy configuration and server-derived client IP in limiter keys."
          : undefined,
    });

    const untrustedCors = await request(app, {
      method: "OPTIONS",
      url: "/api/auth/sign-in/email",
      headers: {
        origin: "http://evil.local",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      },
    });
    const trustedCors = await request(app, {
      method: "OPTIONS",
      url: "/api/auth/sign-in/email",
      headers: {
        origin: "http://localhost:5173",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type,x-correlation-id",
      },
    });
    const untrustedAllowed = Boolean(untrustedCors.headers["access-control-allow-origin"]);
    const trustedAllowedOrigin = trustedCors.headers["access-control-allow-origin"];
    addResult(results, {
      id: "AUTH-024",
      category: "cors-csrf",
      title: "CORS denies untrusted origins and allows trusted origin only",
      status:
        !untrustedAllowed && trustedCors.statusCode === 204 && trustedAllowedOrigin === "http://localhost:5173"
          ? "pass"
          : "fail",
      severity: "medium",
      evidence: `untrustedAcaOrigin=${String(untrustedCors.headers["access-control-allow-origin"])}; trustedAcaOrigin=${String(trustedAllowedOrigin)}; trustedStatus=${trustedCors.statusCode}`,
      recommendation:
        untrustedAllowed
          ? "Restrict CORS strictly to trusted origins and credentials-aware policy."
          : undefined,
    });

    const resultsPath = fileURLToPath(
      new URL("../../../docs/security/auth-broken-auth-results.json", import.meta.url),
    );
    await mkdir(dirname(resultsPath), { recursive: true });
    await writeFile(
      resultsPath,
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          totals: {
            pass: results.filter((r) => r.status === "pass").length,
            fail: results.filter((r) => r.status === "fail").length,
            warn: results.filter((r) => r.status === "warn").length,
          },
          results,
        },
        null,
        2,
      ),
      "utf8",
    );
    console.log(`Security auth assessment saved: ${resultsPath}`);
  } finally {
    await app.close();
    await prisma.$disconnect();
  }
}

void run().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error);
  process.exit(1);
});
