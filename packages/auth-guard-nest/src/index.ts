import {
  createParamDecorator,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
  UnauthorizedException,
  type CanActivate,
} from "@nestjs/common";
import { AccessTokenClaimsSchema, type AccessTokenClaims } from "@sigfarm/auth-contracts";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export const IS_PUBLIC_AUTH_KEY = "sigfarm:auth:public";
export const AUTH_CLAIMS_REQUEST_KEY = "sigfarmAuthClaims" as const;

export type AuthenticatedRequest = {
  headers?: {
    authorization?: string | undefined;
  };
  [AUTH_CLAIMS_REQUEST_KEY]?: AccessTokenClaims;
};

export type AuthGuardOptions = {
  issuer: string;
  audience: string;
  jwksUrl: string;
  requireActiveStatus?: boolean;
  clockToleranceSeconds?: number;
};

export type AuthGuardPublicResolver = {
  isPublic(context: ExecutionContext): boolean;
};

export type JwtVerifier = {
  verify(token: string): Promise<AccessTokenClaims>;
};

@Injectable()
export class SigfarmAuthGuard implements CanActivate {
  private readonly verifier: JwtVerifier;

  constructor(
    private readonly options: AuthGuardOptions,
    private readonly publicResolver?: AuthGuardPublicResolver,
    verifier?: JwtVerifier,
  ) {
    this.verifier = verifier ?? createJwtVerifier(options);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.publicResolver?.isPublic(context)) {
      return true;
    }

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const token = extractBearerToken(request.headers?.authorization);
    if (!token) {
      throw new UnauthorizedException("Missing bearer token");
    }

    const claims = await this.verifier.verify(token);
    if (this.options.requireActiveStatus && claims.globalStatus !== "active") {
      throw new ForbiddenException("Account is not active");
    }

    request[AUTH_CLAIMS_REQUEST_KEY] = claims;
    return true;
  }
}

export const Public = (): MethodDecorator & ClassDecorator => SetMetadata(IS_PUBLIC_AUTH_KEY, true);

export function createMetadataPublicResolver(reflector: {
  getAllAndOverride<T>(metadataKey: string, targets: unknown[]): T | undefined;
}): AuthGuardPublicResolver {
  return {
    isPublic(context: ExecutionContext): boolean {
      return (
        reflector.getAllAndOverride<boolean>(IS_PUBLIC_AUTH_KEY, [
          context.getHandler(),
          context.getClass(),
        ]) === true
      );
    },
  };
}

export function getAuthClaimsFromRequest(request: AuthenticatedRequest): AccessTokenClaims | null {
  return request[AUTH_CLAIMS_REQUEST_KEY] ?? null;
}

export const CurrentAuthClaims = createParamDecorator((_: unknown, context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
  return getAuthClaimsFromRequest(request);
});

export const CurrentAuthUserId = createParamDecorator((_: unknown, context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
  return getAuthClaimsFromRequest(request)?.sub ?? null;
});

export const CurrentAuthSessionId = createParamDecorator((_: unknown, context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
  return getAuthClaimsFromRequest(request)?.sid ?? null;
});

export function assertClaims(claims: unknown): AccessTokenClaims {
  return AccessTokenClaimsSchema.parse(claims);
}

export function createJwtVerifier(options: AuthGuardOptions): JwtVerifier {
  const jwks = createRemoteJWKSet(new URL(options.jwksUrl));

  return {
    async verify(token: string): Promise<AccessTokenClaims> {
      try {
        const verification = await jwtVerify(token, jwks, {
          algorithms: ["RS256"],
          issuer: options.issuer,
          audience: options.audience,
          clockTolerance: options.clockToleranceSeconds ?? 5,
        });

        return mapPayloadToClaims(verification.payload);
      } catch (error) {
        throw new UnauthorizedException(
          error instanceof Error ? error.message : "Invalid authentication token",
        );
      }
    },
  };
}

export function extractBearerToken(headerValue?: string): string | null {
  if (!headerValue) return null;
  const [scheme, token] = headerValue.split(" ");
  if (!scheme || !token) return null;
  if (scheme.toLowerCase() !== "bearer") return null;
  return token.trim() || null;
}

function mapPayloadToClaims(payload: JWTPayload): AccessTokenClaims {
  return AccessTokenClaimsSchema.parse({
    sub: payload.sub,
    sid: payload.sid,
    amr: payload.amr,
    email: payload.email,
    emailVerified: payload.emailVerified,
    globalStatus: payload.globalStatus,
    apps: payload.apps,
    ver: payload.ver,
    iat: payload.iat,
    exp: payload.exp,
    iss: payload.iss,
    aud: payload.aud,
  });
}