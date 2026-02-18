# Secrets e Env

## Regras
- Nao commitar segredos em `.env`.
- Usar `.env.example` apenas com placeholders.
- Em CI/producao, usar secret manager do provedor.

## Variaveis previstas para auth
- `DATABASE_URL`
- `SHADOW_DATABASE_URL`
- `BETTER_AUTH_SECRET`
- `BETTER_AUTH_BASE_URL`
- `BETTER_AUTH_TRUSTED_ORIGINS`
- `ENTRA_CLIENT_ID`
- `ENTRA_CLIENT_SECRET`
- `ENTRA_TENANT_ID`
- `AUTH_ACCESS_TOKEN_TTL_SECONDS`
- `AUTH_REFRESH_TOKEN_TTL_SECONDS`
- `AUTH_JWT_ISSUER`
- `AUTH_JWT_AUDIENCE`
- `AUTH_JWT_KID`
- `AUTH_JWT_PRIVATE_KEY_PEM`
- `AUTH_JWT_PUBLIC_KEY_PEM`
- `AUTH_RATE_LIMIT_WINDOW_SECONDS`
- `AUTH_RATE_LIMIT_MAX_REQUESTS`
- `AUTH_RATE_LIMIT_LOGIN_MAX_REQUESTS`
- `AUTH_REQUIRE_EMAIL_VERIFICATION`

## Auditoria minima
- Validar PRs para evitar segredos hardcoded.
- Nao logar token, senha ou segredo em texto puro.
