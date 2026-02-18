import { generateKeyPairSync } from "node:crypto";
import { SignJWT, exportJWK } from "jose";
import { ForbiddenException, UnauthorizedException } from "@nestjs/common";
import { describe, expect, it, vi } from "vitest";
import {
  AUTH_CLAIMS_REQUEST_KEY,
  SigfarmAuthGuard,
  type AuthenticatedRequest,
  type AuthGuardPublicResolver,
} from "../src/index.js";

type MockExecutionContext = {
  getHandler: () => unknown;
  getClass: () => unknown;
  switchToHttp: () => { getRequest: () => AuthenticatedRequest };
};

function createExecutionContext(request: AuthenticatedRequest): MockExecutionContext {
  return {
    getHandler: () => "handler",
    getClass: () => "class",
    switchToHttp: () => ({
      getRequest: () => request,
    }),
  };
}

describe("SigfarmAuthGuard", () => {
  it("rejects requests without bearer token", async () => {
    const guard = new SigfarmAuthGuard({
      issuer: "https://auth.sigfarmintelligence.com",
      audience: "sigfarm-apps",
      jwksUrl: "https://auth.sigfarmintelligence.com/.well-known/jwks.json",
    });

    const context = createExecutionContext({ headers: {} });

    await expect(guard.canActivate(context as never)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it("accepts valid JWT and attaches typed claims to request", async () => {
    const pair = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const publicJwk = await exportJWK(pair.publicKey);
    publicJwk.use = "sig";
    publicJwk.alg = "RS256";
    publicJwk.kid = "test-kid";

    const token = await new SignJWT({
      sid: "sid-123",
      amr: "password",
      email: "user@sigfarm.com",
      emailVerified: true,
      globalStatus: "active",
      apps: [{ appKey: "PBI_EMBED", roles: ["user"] }],
      ver: 1,
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
      .setSubject("11111111-1111-4111-8111-111111111111")
      .setIssuer("https://auth.sigfarmintelligence.com")
      .setAudience("sigfarm-apps")
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(pair.privateKey);

    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ keys: [publicJwk] }), {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      }),
    );
    globalThis.fetch = fetchMock;

    const request: AuthenticatedRequest = {
      headers: {
        authorization: `Bearer ${token}`,
      },
    };
    const context = createExecutionContext(request);

    const guard = new SigfarmAuthGuard({
      issuer: "https://auth.sigfarmintelligence.com",
      audience: "sigfarm-apps",
      jwksUrl: "https://auth.sigfarmintelligence.com/.well-known/jwks.json",
    });

    const allowed = await guard.canActivate(context as never);

    expect(allowed).toBe(true);
    expect(request[AUTH_CLAIMS_REQUEST_KEY]?.sub).toBe("11111111-1111-4111-8111-111111111111");
  });

  it("blocks disabled accounts when active status is required", async () => {
    const pair = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const publicJwk = await exportJWK(pair.publicKey);
    publicJwk.use = "sig";
    publicJwk.alg = "RS256";
    publicJwk.kid = "test-kid";

    const token = await new SignJWT({
      sid: "sid-123",
      amr: "password",
      email: "user@sigfarm.com",
      emailVerified: true,
      globalStatus: "disabled",
      apps: [{ appKey: "PBI_EMBED", roles: ["user"] }],
      ver: 1,
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
      .setSubject("11111111-1111-4111-8111-111111111111")
      .setIssuer("https://auth.sigfarmintelligence.com")
      .setAudience("sigfarm-apps")
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(pair.privateKey);

    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ keys: [publicJwk] }), {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      }),
    );
    globalThis.fetch = fetchMock;

    const request: AuthenticatedRequest = {
      headers: {
        authorization: `Bearer ${token}`,
      },
    };

    const guard = new SigfarmAuthGuard({
      issuer: "https://auth.sigfarmintelligence.com",
      audience: "sigfarm-apps",
      jwksUrl: "https://auth.sigfarmintelligence.com/.well-known/jwks.json",
      requireActiveStatus: true,
    });

    await expect(guard.canActivate(createExecutionContext(request) as never)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it("bypasses auth when route is marked public", async () => {
    const publicResolver: AuthGuardPublicResolver = {
      isPublic: vi.fn().mockReturnValue(true),
    };

    const guard = new SigfarmAuthGuard(
      {
        issuer: "https://auth.sigfarmintelligence.com",
        audience: "sigfarm-apps",
        jwksUrl: "https://auth.sigfarmintelligence.com/.well-known/jwks.json",
      },
      publicResolver,
    );

    const context = createExecutionContext({ headers: {} });
    await expect(guard.canActivate(context as never)).resolves.toBe(true);
    expect(publicResolver.isPublic).toHaveBeenCalled();
  });
});