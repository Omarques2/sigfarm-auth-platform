# Playbook de Integracao com Sigfarm Auth Platform

Este documento consolida a integracao canônica de um sistema consumidor com o `sigfarm-auth-platform`, com foco em:

- autenticacao centralizada (SSO),
- sessao/token (exchange + refresh),
- validacao JWT no backend consumidor,
- seguranca e operacao em `local`, `staging` e `production`.

Objetivo: permitir que outro LLM (ou dev) replique a integracao com baixo risco e sem tentativas cegas.

## 1. Arquitetura Canonica

Componentes:

1. `auth-web` (portal): tela de login/conta.
2. `auth-api`: emite JWT proprio, expõe JWKS e endpoints de sessao.
3. `app-web` (consumidor): redireciona para login central e troca sessao.
4. `app-api` (consumidor): valida JWT do auth platform via JWKS.

Fluxo canonical:

1. Usuario acessa rota privada no `app-web`.
2. `app-web` redireciona para `auth-web/login?returnTo=...`.
3. Usuario autentica no portal.
4. Portal retorna para `app-web/auth/callback?returnTo=...`.
5. Callback executa `exchangeSession` (`POST /v1/auth/refresh` com cookie do auth).
6. `app-web` passa a obter `accessToken` e chama `app-api` com `Authorization: Bearer`.
7. `app-api` valida assinatura/issuer/audience via JWKS do `auth-api`.

Fontes de contrato no LandWatch:

- Frontend auth client: `apps/web/src/auth/sigfarm-auth.ts`
- Token lifecycle: `apps/web/src/auth/auth.ts`
- Guard de navegacao: `apps/web/src/router/auth-guard.ts`
- Interceptor HTTP: `apps/web/src/api/http.ts`
- Guard JWT backend: `apps/api/src/auth/auth.guard.ts`
- Guard global backend: `apps/api/src/auth/global-auth.guard.ts`
- Variaveis backend obrigatorias: `apps/api/src/config/config.schema.ts`

## 2. Invariantes de Seguranca (nao negociar)

1. Produto consumidor nao autentica direto em Entra/Google.
2. Backend consumidor valida JWT somente da auth platform:
- `SIGFARM_AUTH_ISSUER`
- `SIGFARM_AUTH_AUDIENCE`
- `SIGFARM_AUTH_JWKS_URL`
3. `SIGFARM_AUTH_JWKS_URL` sempre aponta para `api-auth`/`api-testauth`, nunca para `auth-web`.
4. `returnTo` sempre sanitizado por allowlist de origens.
5. Login/callback/logout nao podem entrar em loop.
6. Sem token bearer, endpoint privado deve retornar `401`.

## 3. Variaveis de Ambiente

## 3.1 Frontend consumidor

Obrigatorias:

1. `VITE_SIGFARM_AUTH_API_BASE_URL`
2. `VITE_SIGFARM_AUTH_PORTAL_BASE_URL`
3. `VITE_SIGFARM_APP_BASE_URL`
4. `VITE_SIGFARM_AUTH_ALLOWED_RETURN_ORIGINS`
5. `VITE_SIGFARM_AUTH_DEFAULT_RETURN_TO`
6. `VITE_API_BASE_URL` (API do proprio produto)

Exemplo validado no LandWatch CI/CD:

- Staging:
  - `VITE_SIGFARM_AUTH_API_BASE_URL=https://api-testauth.sigfarmintelligence.com`
  - `VITE_SIGFARM_AUTH_PORTAL_BASE_URL=https://testauth.sigfarmintelligence.com`
  - `VITE_SIGFARM_APP_BASE_URL=https://testlandwatch.sigfarmintelligence.com`
  - `VITE_SIGFARM_AUTH_ALLOWED_RETURN_ORIGINS=https://testlandwatch.sigfarmintelligence.com,https://testauth.sigfarmintelligence.com,https://testbi.sigfarmintelligence.com`
  - `VITE_SIGFARM_AUTH_DEFAULT_RETURN_TO=https://testlandwatch.sigfarmintelligence.com/`
- Production:
  - `VITE_SIGFARM_AUTH_API_BASE_URL=https://api-auth.sigfarmintelligence.com`
  - `VITE_SIGFARM_AUTH_PORTAL_BASE_URL=https://auth.sigfarmintelligence.com`
  - `VITE_SIGFARM_APP_BASE_URL=https://landwatch.sigfarmintelligence.com`
  - `VITE_SIGFARM_AUTH_ALLOWED_RETURN_ORIGINS=https://landwatch.sigfarmintelligence.com,https://auth.sigfarmintelligence.com,https://bi.sigfarmintelligence.com`
  - `VITE_SIGFARM_AUTH_DEFAULT_RETURN_TO=https://landwatch.sigfarmintelligence.com/`

Referencia: `.github/workflows/cd-main.yml`.

## 3.2 Backend consumidor

Obrigatorias:

1. `SIGFARM_AUTH_ISSUER`
2. `SIGFARM_AUTH_AUDIENCE`
3. `SIGFARM_AUTH_JWKS_URL`

Valores recomendados:

- Staging:
  - `SIGFARM_AUTH_ISSUER=https://testauth.sigfarmintelligence.com`
  - `SIGFARM_AUTH_AUDIENCE=sigfarm-apps`
  - `SIGFARM_AUTH_JWKS_URL=https://api-testauth.sigfarmintelligence.com/.well-known/jwks.json`
- Production:
  - `SIGFARM_AUTH_ISSUER=https://auth.sigfarmintelligence.com`
  - `SIGFARM_AUTH_AUDIENCE=sigfarm-apps`
  - `SIGFARM_AUTH_JWKS_URL=https://api-auth.sigfarmintelligence.com/.well-known/jwks.json`

## 3.3 Auth platform (lado central)

Para aceitar o sistema consumidor:

1. `BETTER_AUTH_TRUSTED_ORIGINS` deve conter todos os origins dos apps consumidores.
2. `AUTH_JWT_ISSUER` deve casar com `SIGFARM_AUTH_ISSUER` dos consumidores.
3. `AUTH_JWT_AUDIENCE` deve casar com `SIGFARM_AUTH_AUDIENCE`.
4. `AUTH_JWT_PRIVATE_KEY_PEM` e `AUTH_JWT_PUBLIC_KEY_PEM` devem estar consistentes com JWKS publicado.
5. `VITE_AUTH_ALLOWED_RETURN_ORIGINS` (auth-web) deve incluir os apps que recebem `returnTo`.

## 4. Passo a Passo de Implementacao (Consumidor)

## 4.1 Frontend

1. Instalar SDKs:
- `@sigfarm/auth-client-vue`
- `@sigfarm/auth-contracts`

2. Criar modulo unico de auth (`src/auth/sigfarm-auth.ts`) com:
- `createAuthClient(...)`
- parse de env
- `resolveReturnTo(...)`
- `buildAuthCallbackReturnTo(...)`
- `buildAuthPortalLoginUrl(...)`

3. `LoginView`:
- botao "Entrar" deve redirecionar para `auth-web/login` com `returnTo` seguro.
- opcional: tentativa de `exchangeSession` para auto-resume quando voltar do portal.

4. `CallbackView`:
- tela de loading.
- chamar `exchangeSession()`.
- chamar `/v1/users/me` local (bootstrap/autorizacao local).
- redirecionar para `returnTo` seguro.

5. Guard de rotas:
- rota publica passa.
- rota privada exige `ensureSession + getMeCached`.
- sem sessao: redirecionar para `/login?returnTo=...`.

6. Interceptor HTTP:
- anexa bearer automaticamente.
- em `401`, tenta 1 refresh forçado e reenvia 1 vez.
- se continuar `401`, limpa sessao local e redireciona login.

7. Logout:
- revogar sessao no auth-api (`/v1/auth/logout`) com cookie + bearer quando houver.
- chamar tambem `/api/auth/sign-out` (Better Auth).
- limpar estado local e voltar para `/login`.

8. Evitar HTML stale em auth routes:
- configurar `Cache-Control: no-store` em `/`, `/login`, `/auth/callback`, rotas protegidas principais.
- no LandWatch, isso esta em `apps/web/staticwebapp.config.json`.

## 4.2 Backend

1. Instalar:
- `@sigfarm/auth-guard-nest`
- `@sigfarm/auth-contracts`

2. Configurar `AuthGuard` com:
- `issuer`
- `audience`
- `jwksUrl`

3. Aplicar guard global (com bypass explicito via decorator `@Public()` apenas quando necessario).

4. Manter endpoint `GET /v1/users/me` para bootstrap de usuario local e estado (`active|pending|disabled`).

5. Garantir CORS correto para o frontend do proprio produto.

## 5. Checklist de Validacao (Manual + Tecnica)

## 5.1 Browser / Network

1. Fluxo login:
- deve navegar `app -> auth-web/login -> app/auth/callback`.
2. Callback deve disparar `POST /v1/auth/refresh` no auth-api.
3. Chamadas ao `app-api` protegido devem conter header `Authorization: Bearer ...`.
4. `GET /v1/users/me` no `app-api` deve retornar `200` para sessao valida.
5. Logout deve invalidar sessao central e impedir novo acesso sem login.

## 5.2 Console snippet de diagnostico

Use no dominio do app:

```js
await (async () => {
  const out = {};

  const refreshResp = await fetch("https://api-testauth.sigfarmintelligence.com/v1/auth/refresh", {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  const refreshText = await refreshResp.text();
  out.refreshStatus = refreshResp.status;
  out.refreshBody = refreshText;

  let refreshJson = null;
  try { refreshJson = JSON.parse(refreshText); } catch {}
  const token = refreshJson?.data?.accessToken;
  out.tokenFound = !!token;

  const meResp = await fetch("https://<app-api>/v1/users/me", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  out.meStatus = meResp.status;
  out.meBody = await meResp.text();

  return out;
})();
```

Se `refreshStatus=200` e `meStatus=200`, a base auth/session/backend esta correta. Se a UI ainda falhar, o problema esta no frontend (guard/interceptor/callback).

## 6. Troubleshooting Rapido (Sintoma -> Causa Provavel)

1. Login volta para `/login` em loop:
- `returnTo` invalido/não permitido.
- callback nao executa `exchangeSession`.
- token nao sendo anexado no interceptor.

2. `POST /v1/auth/refresh` retorna `401 No active session`:
- cookie de sessao central ausente/bloqueado.
- origem do app ausente em `BETTER_AUTH_TRUSTED_ORIGINS`.
- mismatch `auth` vs `testauth`.

3. CORS preflight bloqueado no refresh:
- origem do app nao autorizada no auth-api.
- mistura de dominios errada (ex.: app staging chamando api-auth prod).

4. `/v1/users/me` retorna `401 Missing bearer token`:
- frontend não conseguiu obter token apos exchange.
- interceptor sem injeção de `Authorization`.
- chamada manual sem header.

5. Logout nao desloga de verdade:
- limpando apenas sessao local.
- faltando chamar endpoint central de logout/sign-out.

## 7. Testes Minimos que o Repositorio Consumidor Deve Ter

Frontend:

1. `buildLoginUrl`/`returnTo` bloqueia open redirect.
2. guard redireciona corretamente:
- sem sessao -> `/login`
- sessao + sem perfil -> `/pending` (ou politica definida)
- sessao valida -> rota protegida.
3. callback:
- sucesso -> vai para destino
- erro -> volta para login sem loop.

Backend:

1. token malformado -> `401`.
2. issuer errado -> `401`.
3. audience errada -> `401`.
4. assinatura fora do JWKS -> `401`.
5. sem bearer em rota privada -> `401`.

No LandWatch, referencias:

- `apps/web/src/router/__tests__/auth-guard.test.ts`
- `apps/web/src/views/__tests__/CallbackView.test.ts`
- `apps/api/test/auth-guard.e2e-spec.ts`
- `apps/api/test/active-user-guard.e2e-spec.ts`

## 8. Politica de Acesso (decisao obrigatoria por produto)

Cada sistema deve decidir explicitamente:

1. Quem entra no app?
- apenas `active`, ou
- `pending` tambem pode entrar em parte do sistema.
2. Onde bloquear?
- frontend apenas,
- backend apenas,
- ou ambos (recomendado para consistencia).

Sem essa decisao documentada, surgem loops e comportamento inconsistente.

## 9. Roteiro para Outro LLM (Execucao Segura)

Use este roteiro ao integrar um novo sistema:

1. Confirmar dominios por ambiente (`auth-web`, `auth-api`, `app-web`, `app-api`).
2. Confirmar matriz de env front/back + env do auth platform.
3. Implementar modulo auth unico no frontend.
4. Implementar login/callback/guard/interceptor/logout conforme Secao 4.1.
5. Implementar guard JWT backend com issuer/audience/jwks conforme Secao 4.2.
6. Executar checklist de rede da Secao 5.1.
7. Executar snippet de diagnostico da Secao 5.2.
8. Corrigir primeiro erros de contrato (CORS/origins/issuer/audience), depois UX.
9. Validar testes minimos da Secao 7.
10. Registrar no PR:
- variaveis usadas por ambiente,
- endpoints testados,
- evidencias de sucesso (`refresh 200`, `me 200`, logout ok).

## 10. Anti-Patterns Comuns

1. Apontar `JWKS` para dominio errado (auth-web).
2. Misturar staging com prod em `VITE_*`/secrets.
3. Permitir fallback silencioso para prod em staging/local sem intencao.
4. Tentar corrigir loop de login com hard refresh sem validar token bearer no `/v1/users/me`.
5. Resolver apenas no frontend quando o backend ainda rejeita token por issuer/audience.

## 11. Referencias Primarias

No LandWatch:

1. `.github/workflows/cd-main.yml`
2. `apps/web/src/auth/sigfarm-auth.ts`
3. `apps/web/src/auth/auth.ts`
4. `apps/web/src/api/http.ts`
5. `apps/web/src/router/auth-guard.ts`
6. `apps/api/src/auth/auth.guard.ts`
7. `apps/api/src/config/config.schema.ts`

No sigfarm-auth-platform:

1. `docs/plans/2026-02-18-epic-04-05-integracao-landwatch-pbi-embed.md`
2. `docs/secrets-and-env.md`
3. `packages/auth-client-vue/README.md`
4. `apps/auth-api/src/index.ts`
5. `apps/auth-api/src/config/env.ts`
