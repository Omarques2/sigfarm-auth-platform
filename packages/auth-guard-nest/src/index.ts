export type AuthClaims = {
  sub: string;
  sid: string;
  ver: number;
};

export function assertClaims(claims: AuthClaims): AuthClaims {
  return claims;
}

