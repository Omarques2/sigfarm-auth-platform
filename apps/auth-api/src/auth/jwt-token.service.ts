import { randomBytes } from "node:crypto";
import {
  SignJWT,
  exportJWK,
  generateKeyPair,
  importPKCS8,
  importSPKI,
  jwtVerify,
  type JWK,
  type JWTPayload,
} from "jose";
import type { AuthMethod, AuthStatus } from "@sigfarm/auth-contracts";
import { z } from "zod";

const tokenClaimsSchema = z.object({
  sub: z.string().uuid(),
  sid: z.string(),
  amr: z.enum(["entra", "password"]),
  email: z.string().email(),
  emailVerified: z.boolean(),
  globalStatus: z.enum(["pending", "active", "disabled"]),
  apps: z.array(
    z.object({
      appKey: z.string().min(1),
      roles: z.array(z.string().min(1)),
    }),
  ),
  ver: z.number().int().positive(),
  iat: z.number().int().optional(),
  exp: z.number().int().optional(),
});

export type AccessTokenClaims = {
  sub: string;
  sid: string;
  amr: AuthMethod;
  email: string;
  emailVerified: boolean;
  globalStatus: AuthStatus;
  apps: Array<{ appKey: string; roles: string[] }>;
  ver: number;
};

export type IssuedAccessToken = {
  token: string;
  issuedAt: Date;
  expiresAt: Date;
  expiresInSeconds: number;
};

type JwtTokenServiceConfig = {
  issuer: string;
  audience: string;
  kid: string;
  accessTokenTtlSeconds: number;
  privateKeyPem?: string;
  publicKeyPem?: string;
  requireStaticKeys: boolean;
};

export class JwtTokenService {
  private readonly issuer: string;
  private readonly audience: string;
  private readonly kid: string;
  private readonly accessTokenTtlSeconds: number;
  private readonly privateKey: CryptoKey;
  private readonly publicKey: CryptoKey;
  private readonly publicJwk: JWK;

  private constructor(config: {
    issuer: string;
    audience: string;
    kid: string;
    accessTokenTtlSeconds: number;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicJwk: JWK;
  }) {
    this.issuer = config.issuer;
    this.audience = config.audience;
    this.kid = config.kid;
    this.accessTokenTtlSeconds = config.accessTokenTtlSeconds;
    this.privateKey = config.privateKey;
    this.publicKey = config.publicKey;
    this.publicJwk = config.publicJwk;
  }

  static async create(config: JwtTokenServiceConfig): Promise<JwtTokenService> {
    const hasPemPair = Boolean(config.privateKeyPem && config.publicKeyPem);
    if (!hasPemPair && config.requireStaticKeys) {
      throw new Error(
        "AUTH_JWT_PRIVATE_KEY_PEM and AUTH_JWT_PUBLIC_KEY_PEM are required in production",
      );
    }

    let privateKey: CryptoKey;
    let publicKey: CryptoKey;

    if (hasPemPair) {
      privateKey = await importPKCS8(config.privateKeyPem!, "RS256");
      publicKey = await importSPKI(config.publicKeyPem!, "RS256");
    } else {
      const pair = await generateKeyPair("RS256", {
        extractable: true,
        modulusLength: 2048,
      });
      privateKey = pair.privateKey;
      publicKey = pair.publicKey;
    }

    const exportedPublicJwk = await exportJWK(publicKey);
    exportedPublicJwk.alg = "RS256";
    exportedPublicJwk.use = "sig";
    exportedPublicJwk.kid = config.kid;

    return new JwtTokenService({
      issuer: config.issuer,
      audience: config.audience,
      kid: config.kid,
      accessTokenTtlSeconds: config.accessTokenTtlSeconds,
      privateKey,
      publicKey,
      publicJwk: exportedPublicJwk,
    });
  }

  async issueAccessToken(input: AccessTokenClaims): Promise<IssuedAccessToken> {
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + this.accessTokenTtlSeconds * 1000);
    const jwt = await new SignJWT({
      sid: input.sid,
      amr: input.amr,
      email: input.email,
      emailVerified: input.emailVerified,
      globalStatus: input.globalStatus,
      apps: input.apps,
      ver: input.ver,
      jti: randomBytes(12).toString("base64url"),
    })
      .setProtectedHeader({ alg: "RS256", kid: this.kid, typ: "JWT" })
      .setSubject(input.sub)
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setIssuedAt(Math.floor(issuedAt.getTime() / 1000))
      .setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
      .sign(this.privateKey);

    return {
      token: jwt,
      issuedAt,
      expiresAt,
      expiresInSeconds: this.accessTokenTtlSeconds,
    };
  }

  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    const verification = await jwtVerify(token, this.publicKey, {
      algorithms: ["RS256"],
      issuer: this.issuer,
      audience: this.audience,
    });
    return parseClaims(verification.payload);
  }

  getJwks(): { keys: JWK[] } {
    return {
      keys: [this.publicJwk],
    };
  }
}

function parseClaims(payload: JWTPayload): AccessTokenClaims {
  return tokenClaimsSchema.parse({
    sub: payload.sub,
    sid: payload.sid,
    amr: payload.amr,
    email: payload.email,
    emailVerified: payload.emailVerified,
    globalStatus: payload.globalStatus,
    apps: payload.apps ?? [],
    ver: payload.ver ?? 1,
    iat: payload.iat,
    exp: payload.exp,
  });
}

