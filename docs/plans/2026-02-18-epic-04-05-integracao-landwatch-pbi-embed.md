# EPIC-04 e EPIC-05 - Integracao LandWatch + pbi-embed (Playbook Executavel)

> **Para Codex/Engenharia:** execute task-by-task, sem pular ordem, sem mudar contrato `v1`.

**Goal:** integrar LandWatch e pbi-embed ao `sigfarm-auth-platform` usando os SDKs compartilhados (`@sigfarm/auth-client-vue` e `@sigfarm/auth-guard-nest`) com foco em seguranca, sem retrabalho e com cutover rapido.

**Architecture:** os produtos deixam de autenticar diretamente nos IdPs (Microsoft/Google). O login passa pelo auth portal (`auth-web`) e pela auth API (`auth-api`), que emitem sessao centralizada + token proprio (JWT RS256). Cada produto continua com autorizacao local (membership, customer, admin), mas com identidade canonica `identity_user_id` em vez de `entra_sub`.

**Tech Stack:** Vue 3 + Vite (frontends), NestJS + Prisma (backends), Better Auth, jose, PostgreSQL.

---

## 0. Como usar este documento

Este documento foi escrito para execucao direta por agent (Codex) ou por dev humano, com:

1. ordem obrigatoria;
2. arquivos exatos para tocar;
3. comandos de validacao;
4. criterios de aceite por task;
5. estrategia de rollback.

Se for executar com Codex:

1. Abra o chat no repo alvo (`LandWatch` ou `pbi-embed`) para ter contexto local completo.
2. Use este playbook como input principal.
3. Mantenha `sigfarm-auth-platform` aberto em paralelo apenas para referencia de contrato/SDK.

Tambem funciona a partir do repo atual com caminhos absolutos, mas nao e recomendado para mudancas grandes em outro repositorio.

---

## 0.1 Estado atual validado (2026-02-20)

1. Auth web e auth API operam em hosts separados no staging/prod (ex.: `testauth...` e `api-testauth...`).
2. Login central suporta email/senha, Microsoft e Google no auth portal.
3. Produtos consumidores nao devem implementar OAuth local; apenas redirecionar para o auth portal.
4. Fluxo canonicamente suportado continua: `login -> callback -> exchangeSession -> me`.
5. 2FA esta fora do escopo atual.

---

## 1. Escopo fechado

Inclui:

1. EPIC-04 completo no LandWatch.
2. EPIC-05 completo no pbi-embed.
3. Ajuste de bancos locais para `identity_user_id`.
4. Testes de regressao de autenticacao e autorizacao.

Nao inclui nesta rodada:

1. Novos fatores de autenticacao (2FA).
2. Novos fluxos de convites complexos.
3. Rework de RBAC de dominio de cada produto (somente adaptar para identidade central).

---

## 2. Contratos e invariantes obrigatorios

## 2.1 Contrato de token (nao quebrar)

Fonte canonica: `packages/auth-contracts/src/index.ts`.

Claims esperadas (access token):

1. `sub` (UUID): `identity_user_id`.
2. `sid`: session id.
3. `amr`: `entra` ou `password`.
4. `email`, `emailVerified`.
5. `globalStatus`: `pending|active|disabled`.
6. `apps[]`.
7. `ver`.

Nota importante:

1. consumidores nao devem inferir provedor social diretamente pelo `amr` para regras de negocio;
2. regras de autorizacao devem depender de `sub`, `globalStatus`, `apps` e dados locais do produto.

## 2.2 Fluxo de sessao

Fonte canonica: `packages/auth-client-vue/src/auth-client.ts`.

Fluxo obrigatorio:

1. app redireciona para `/login` do auth portal com `returnTo`.
2. auth portal autentica usuario (email/senha, Microsoft ou Google).
3. callback do produto executa `exchangeSession` (`POST /v1/auth/refresh` com cookie) e recebe access+refresh.
4. frontend usa `authFetch`/`getAccessToken` para chamadas autenticadas.
5. backend do produto valida JWT via JWKS da auth platform.

## 2.3 Nao voltar para OAuth direto nos produtos

Depois da migracao:

1. frontend do produto nao depende de `@azure/msal-browser`.
2. frontend do produto nao implementa OAuth Google local.
3. backend do produto nao valida issuer/audience direto do Entra/Google.
4. validacao sempre contra `AUTH_JWT_ISSUER`, `AUTH_JWT_AUDIENCE`, `/.well-known/jwks.json` da auth platform.

---

## 3. Pre-requisitos

## 3.1 Ambiente

1. Node >= 22.
2. npm >= 11.
3. auth platform rodando e funcional:
   - `apps/auth-api` (`/health`, `/v1/auth/refresh`, `/.well-known/jwks.json`).
   - `apps/auth-web` (`/login`, `/verify-email`, `/reset-password`, `/my-account`).
4. Banco auth com migrations aplicadas e seed executado.
5. Staging/prod com custom domains configurados para evitar problema de sessao/cookie cross-site:
   - auth web: `testauth.sigfarmintelligence.com` / `auth.sigfarmintelligence.com`
   - auth api: `api-testauth.sigfarmintelligence.com` / `api-auth.sigfarmintelligence.com`
6. Redirect URIs dos provedores sociais apontando para callback da auth API (`/api/auth/callback/<provider>`).

## 3.2 Variaveis de referencia (auth platform)

1. `AUTH_JWT_ISSUER`.
2. `AUTH_JWT_AUDIENCE`.
3. `AUTH_JWT_KID`.
4. `BETTER_AUTH_BASE_URL`.
5. `BETTER_AUTH_TRUSTED_ORIGINS`.
6. `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_TENANT_ID`.
7. `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`.

## 3.3 Gate de seguranca antes de integrar apps

Rodar no `sigfarm-auth-platform`:

```bash
npm run lint
npm run test
npm run build
npm run security:test-auth --workspace @sigfarm/auth-api
```

Esperado:

1. tudo verde;
2. sem regressao no `auth-broken-auth-results.json`.

---

## 4. Distribuicao dos SDKs para consumo

Objetivo: garantir que LandWatch/pbi-embed consumam exatamente a versao de SDK testada.

## 4.1 Opcao recomendada (staging/prod): registry privado

1. Publicar `@sigfarm/auth-contracts`.
2. Publicar `@sigfarm/auth-client-vue`.
3. Publicar `@sigfarm/auth-guard-nest`.

Vantagem: CI reproduzivel e lockfile estavel.

## 4.2 Opcao rapida (dev local): pacote `.tgz`

No `sigfarm-auth-platform`:

```bash
npm run build --workspace @sigfarm/auth-contracts
npm run build --workspace @sigfarm/auth-client-vue
npm run build --workspace @sigfarm/auth-guard-nest

npm pack --workspace @sigfarm/auth-contracts
npm pack --workspace @sigfarm/auth-client-vue
npm pack --workspace @sigfarm/auth-guard-nest
```

Instalar nos produtos apontando para os `.tgz` gerados.

---

## 5. Task list EPIC-04 - LandWatch

### Task 04.01 - Migrar frontend LandWatch para `@sigfarm/auth-client-vue`

**Repo:** `C:\Users\Sigfarm\Desktop\Github\LandWatch`

**Files (minimo):**

1. `apps/web/package.json`
2. `apps/web/src/main.ts`
3. `apps/web/src/router/index.ts`
4. `apps/web/src/router/auth-guard.ts`
5. `apps/web/src/api/http.ts`
6. `apps/web/src/auth/auth.ts` (remover/aposentar)
7. `apps/web/src/auth/me.ts` (adaptar consumo de `/v1/users/me`)
8. `apps/web/src/views/LoginView.vue`
9. `apps/web/src/views/CallbackView.vue`
10. `apps/web/.env*`

**Step-by-step:**

1. Remover dependencia direta de MSAL:
   - tirar `@azure/msal-browser` do `apps/web/package.json`.
2. Adicionar SDK:
   - instalar `@sigfarm/auth-client-vue` e `@sigfarm/auth-contracts`.
3. Criar modulo unico de auth client (ex.: `apps/web/src/auth/sigfarm-auth.ts`) com:
   - `createAuthClient`.
   - `authApiBaseUrl` = `https://api-auth.sigfarmintelligence.com` (ou dev/staging equivalente).
   - `authPortalBaseUrl` = `https://auth.sigfarmintelligence.com` (ou dev/staging equivalente).
   - `appBaseUrl` = origem do LandWatch.
   - `allowedReturnOrigins`.
   - `defaultReturnTo` = `https://landwatch.../`.
4. Trocar `LoginView`:
   - botao chama `window.location.assign(authClient.buildLoginUrl({ returnTo }))`.
   - sem fluxo Entra local.
5. Trocar `CallbackView`:
   - manter tela minima de loading.
   - chamar `authClient.exchangeSession()`.
   - chamar endpoint local `/v1/users/me` para bootstrap local.
   - redirecionar para `returnTo` seguro.
6. Trocar guard de rota:
   - se rota publica: passa.
   - se privada: `ensureSession` e `getMeCached`.
   - `status !== active` vai para `/pending`.
7. Trocar interceptor HTTP:
   - usar `authClient.authFetch` para renovacao automatica e retry de 401.
   - se ficar sem sessao, redirecionar para `/login` do produto (que redireciona para auth portal).
8. Remover funcoes legadas:
   - `loginRedirect`, `acquireTokenSilent`, `hardResetAuthState` baseados em MSAL.
9. Ajustar envs frontend:
   - `VITE_SIGFARM_AUTH_API_BASE_URL`.
   - `VITE_SIGFARM_AUTH_PORTAL_BASE_URL`.
   - `VITE_SIGFARM_APP_BASE_URL`.
   - `VITE_SIGFARM_AUTH_ALLOWED_RETURN_ORIGINS`.
   - `VITE_SIGFARM_AUTH_DEFAULT_RETURN_TO`.

**Criterios de aceite:**

1. nenhum import de `@azure/msal-browser` em `apps/web/src`.
2. login/callback/logout funcionam.
3. refresh automatico funciona apos expirar access token.
4. rota privada bloqueia usuario anonimo.
5. `returnTo` nao permite open redirect.

**Comandos de validacao:**

```bash
npm run lint --prefix apps/web
npm run typecheck --prefix apps/web
npm run test --prefix apps/web
npm run build --prefix apps/web
```

---

### Task 04.02 - Migrar backend LandWatch para `@sigfarm/auth-guard-nest`

**Repo:** `C:\Users\Sigfarm\Desktop\Github\LandWatch`

**Files (minimo):**

1. `apps/api/package.json`
2. `apps/api/src/auth/auth.guard.ts`
3. `apps/api/src/auth/claims.type.ts`
4. `apps/api/src/auth/authed-request.type.ts`
5. `apps/api/src/auth/entra-jwt.service.ts` (remover)
6. `apps/api/src/auth/auth.module.ts`
7. `apps/api/src/auth/global-auth.guard.ts`
8. `apps/api/src/config/config.schema.ts`
9. `apps/api/src/users/users.controller.ts`
10. `apps/api/src/users/users.service.ts`

**Step-by-step:**

1. Adicionar dependencias:
   - `@sigfarm/auth-guard-nest`.
   - `@sigfarm/auth-contracts`.
2. Substituir validacao Entra por guard central:
   - reimplementar `AuthGuard` usando `SigfarmAuthGuard`.
   - `issuer`, `audience`, `jwksUrl` por env.
   - preservar suporte a `@Public()` via `createMetadataPublicResolver`.
3. Atualizar tipo de claims:
   - usar `AccessTokenClaims` do contrato central.
   - remover campos Entra-only (`oid`, `upn`, etc.) como obrigatorios.
4. Ajustar `UsersController/UsersService`:
   - identidade principal vem de `claims.sub` (UUID global).
   - manter regras locais (`pending/active/disabled`), mas desacopladas de Entra.
5. Ajustar env schema:
   - adicionar `SIGFARM_AUTH_ISSUER` (url obrigatoria).
   - adicionar `SIGFARM_AUTH_AUDIENCE` (string obrigatoria).
   - adicionar `SIGFARM_AUTH_JWKS_URL` (url obrigatoria).
   - deprecar `ENTRA_*` no fluxo principal.
6. Preservar regras de negocio locais:
   - `GlobalAuthGuard` continua aplicando `AuthGuard + ActiveUserGuard`.

**Criterios de aceite:**

1. token invalido -> 401.
2. token assinado por chave fora do JWKS -> 401.
3. `globalStatus=disabled` bloqueado quando configurado.
4. endpoints publicos continuam publicos.

**Comandos de validacao:**

```bash
npm run lint:check --prefix apps/api
npm run test --prefix apps/api
npm run build --prefix apps/api
```

---

### Task 04.03 - Ajustar banco LandWatch para `identity_user_id`

**Repo:** `C:\Users\Sigfarm\Desktop\Github\LandWatch`

**Files (minimo):**

1. `apps/api/prisma/schema.prisma`
2. `apps/api/prisma/migrations/<timestamp>_identity_user_id/migration.sql`
3. `apps/api/src/users/users.service.ts`

**Step-by-step:**

1. Adicionar coluna:
   - tabela `app.app_user`.
   - coluna `identity_user_id UUID NULL`.
2. Adicionar indice unico parcial:
   - unico quando `identity_user_id IS NOT NULL`.
3. Atualizar modelo Prisma:
   - campo opcional `identityUserId`.
4. Alterar `upsertFromClaims`:
   - chave primaria logica passa a ser `identityUserId`.
   - fallback temporario por email case-insensitive para vincular legado.
5. Nao dropar `entra_sub` nesta task:
   - manter para rollback rapido.

**SQL de referencia:**

```sql
ALTER TABLE app.app_user
  ADD COLUMN IF NOT EXISTS identity_user_id UUID;

CREATE UNIQUE INDEX IF NOT EXISTS app_user_identity_user_id_key
  ON app.app_user(identity_user_id)
  WHERE identity_user_id IS NOT NULL;
```

**Criterios de aceite:**

1. primeiro login nao duplica usuario local.
2. usuario legado recebe `identity_user_id` corretamente.
3. query de `users/me` continua performatica.

**Comandos de validacao:**

```bash
npm run db:migrate:deploy --prefix apps/api
npm run test --prefix apps/api
```

---

## 6. Task list EPIC-05 - pbi-embed

### Task 05.01 - Migrar frontend pbi-embed para `@sigfarm/auth-client-vue`

**Repo:** `C:\Users\Sigfarm\Desktop\Github\pbi-embed`

**Files (minimo):**

1. `apps/web/package.json`
2. `apps/web/src/main.ts`
3. `apps/web/src/router/index.ts`
4. `apps/web/src/api/http.ts`
5. `apps/web/src/auth/auth.ts` (remover/aposentar)
6. `apps/web/src/auth/me.ts`
7. `apps/web/src/views/LoginView.vue`
8. `apps/web/src/views/CallbackView.vue`
9. `apps/web/.env*`

**Step-by-step:**

1. Remover `@azure/msal-browser`.
2. Adicionar `@sigfarm/auth-client-vue`.
3. Criar wrapper local `sigfarm-auth.ts` igual ao LandWatch.
4. Atualizar `/login`:
   - redireciona para auth portal.
5. Atualizar `/auth/callback`:
   - executar `exchangeSession`.
   - chamar `/users/me`.
   - redirecionar para `/app` (ou `returnTo` seguro).
6. Manter logica de `/pending` e `admin`:
   - `getMeCached` continua avaliando status efetivo local.
7. Atualizar interceptor HTTP:
   - token via auth client.
   - retry automatico de 401 com refresh.

**Criterios de aceite:**

1. sem dependencia MSAL no app final.
2. `/app` e `/admin` protegidas e estaveis.
3. callback nao exibe erro visual em condicao normal.

**Comandos de validacao:**

```bash
npm run lint --prefix apps/web
npm run typecheck --prefix apps/web
npm run test --prefix apps/web
npm run build --prefix apps/web
```

---

### Task 05.02 - Migrar backend pbi-embed para `@sigfarm/auth-guard-nest`

**Repo:** `C:\Users\Sigfarm\Desktop\Github\pbi-embed`

**Files (minimo):**

1. `apps/api/package.json`
2. `apps/api/src/auth/auth.guard.ts`
3. `apps/api/src/auth/active-user.guard.ts`
4. `apps/api/src/auth/claims.type.ts`
5. `apps/api/src/auth/authed-request.type.ts`
6. `apps/api/src/auth/entra-jwt.service.ts` (remover)
7. `apps/api/src/config/config.schema.ts`
8. `apps/api/src/users/users.controller.ts`
9. `apps/api/src/users/users.service.ts`
10. `apps/api/src/admin-users/**` (ajustes de filtro por usuario)

**Step-by-step:**

1. Substituir `AuthGuard` por `SigfarmAuthGuard`.
2. Migrar tipo de claims para contrato central.
3. Atualizar `ActiveUserGuard`:
   - ler usuario local por `identity_user_id`.
   - manter validacao de membership ativa/customer ativa.
   - manter excecao de `platform_admin`.
4. Ajustar `users/me`:
   - continuar retornando `status` efetivo (combina status local + membership + admin).
5. Atualizar env schema:
   - `SIGFARM_AUTH_ISSUER`, `SIGFARM_AUTH_AUDIENCE`, `SIGFARM_AUTH_JWKS_URL`.

**Criterios de aceite:**

1. usuario sem membership ativa permanece `pending`.
2. usuario `platform_admin` segue `active` sem customer.
3. usuario disabled bloqueado.
4. endpoints admin continuam com semantica atual.

**Comandos de validacao:**

```bash
npm run lint:check --prefix apps/api
npm run test --prefix apps/api
npm run build --prefix apps/api
```

---

### Task 05.03 - Ajustar banco pbi-embed para `identity_user_id`

**Repo:** `C:\Users\Sigfarm\Desktop\Github\pbi-embed`

**Files (minimo):**

1. `apps/api/prisma/schema.prisma`
2. `apps/api/prisma/migrations/<timestamp>_identity_user_id/migration.sql`
3. `apps/api/src/users/users.service.ts`
4. `apps/api/src/admin-users/repositories/user.repository.ts` (quando filtra por identidade)

**Step-by-step:**

1. Adicionar coluna `identity_user_id UUID NULL` em `users`.
2. Adicionar indice unico parcial.
3. Atualizar Prisma model `User`.
4. Trocar lookup principal por `identityUserId`.
5. Manter fallback por email para vinculo de legado.

**SQL de referencia:**

```sql
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS identity_user_id UUID;

CREATE UNIQUE INDEX IF NOT EXISTS users_identity_user_id_key
  ON users(identity_user_id)
  WHERE identity_user_id IS NOT NULL;
```

**Criterios de aceite:**

1. sem duplicidade de usuario.
2. RBAC local continua funcional.
3. `users/me` e `/admin/*` sem regressao de permissao.

**Comandos de validacao:**

```bash
npm run db:migrate:deploy --prefix apps/api
npm run test --prefix apps/api
```

---

## 7. Matriz de variaveis de ambiente por produto

## 7.1 Frontend (LandWatch e pbi-embed)

Adicionar:

1. `VITE_SIGFARM_AUTH_API_BASE_URL`
2. `VITE_SIGFARM_AUTH_PORTAL_BASE_URL`
3. `VITE_SIGFARM_APP_BASE_URL`
4. `VITE_SIGFARM_AUTH_ALLOWED_RETURN_ORIGINS`
5. `VITE_SIGFARM_AUTH_DEFAULT_RETURN_TO`

Valores recomendados:

1. `staging`:
   - `VITE_SIGFARM_AUTH_API_BASE_URL=https://api-testauth.sigfarmintelligence.com`
   - `VITE_SIGFARM_AUTH_PORTAL_BASE_URL=https://testauth.sigfarmintelligence.com`
   - `VITE_SIGFARM_APP_BASE_URL=https://<app-staging>.sigfarmintelligence.com`
   - `VITE_SIGFARM_AUTH_ALLOWED_RETURN_ORIGINS=https://<app-staging>.sigfarmintelligence.com,https://testauth.sigfarmintelligence.com`
   - `VITE_SIGFARM_AUTH_DEFAULT_RETURN_TO=https://<app-staging>.sigfarmintelligence.com/`
2. `production`:
   - `VITE_SIGFARM_AUTH_API_BASE_URL=https://api-auth.sigfarmintelligence.com`
   - `VITE_SIGFARM_AUTH_PORTAL_BASE_URL=https://auth.sigfarmintelligence.com`
   - `VITE_SIGFARM_APP_BASE_URL=https://<app>.sigfarmintelligence.com`
   - `VITE_SIGFARM_AUTH_ALLOWED_RETURN_ORIGINS=https://<app>.sigfarmintelligence.com,https://auth.sigfarmintelligence.com`
   - `VITE_SIGFARM_AUTH_DEFAULT_RETURN_TO=https://<app>.sigfarmintelligence.com/`

Regras:

1. sempre usar URL completa com protocolo (`https://`).
2. nao colocar espacos na lista CSV de `VITE_SIGFARM_AUTH_ALLOWED_RETURN_ORIGINS`.
3. `VITE_SIGFARM_AUTH_API_BASE_URL` deve apontar para a auth API (nao para auth web).

Remover/deprecar:

1. `VITE_ENTRA_SPA_CLIENT_ID`
2. `VITE_ENTRA_AUTHORITY`
3. `VITE_ENTRA_API_SCOPE`
4. `VITE_ENTRA_*`

## 7.2 Backend (LandWatch e pbi-embed)

Adicionar:

1. `SIGFARM_AUTH_ISSUER` (usar exatamente o valor de `AUTH_JWT_ISSUER` configurado na auth API)
2. `SIGFARM_AUTH_AUDIENCE` (igual ao `AUTH_JWT_AUDIENCE`, default `sigfarm-apps`)
3. `SIGFARM_AUTH_JWKS_URL` (endpoint JWKS da auth API)

Valores recomendados:

1. `staging`:
   - `SIGFARM_AUTH_ISSUER=https://testauth.sigfarmintelligence.com`
   - `SIGFARM_AUTH_AUDIENCE=sigfarm-apps`
   - `SIGFARM_AUTH_JWKS_URL=https://api-testauth.sigfarmintelligence.com/.well-known/jwks.json`
2. `production`:
   - `SIGFARM_AUTH_ISSUER=https://auth.sigfarmintelligence.com`
   - `SIGFARM_AUTH_AUDIENCE=sigfarm-apps`
   - `SIGFARM_AUTH_JWKS_URL=https://api-auth.sigfarmintelligence.com/.well-known/jwks.json`

Regra:

1. nao apontar `SIGFARM_AUTH_JWKS_URL` para o dominio do auth web.

Manter por enquanto (nao bloquear boot):

1. `ENTRA_*` como legado temporario durante branch de transicao.

---

## 8. Testes de aceite (checklist pass/fail)

## 8.1 Smoke LandWatch

1. sem sessao -> rota privada redireciona login central.
2. login email/senha -> callback -> `/v1/users/me` -> dashboard.
3. login Microsoft -> callback -> sessao ativa.
4. login Google -> callback -> sessao ativa.
5. logout -> volta para login sem loop.
6. refresh token funciona apos expirar access token.
7. usuario pending fica em `/pending`.
8. usuario disabled recebe bloqueio consistente.

## 8.2 Smoke pbi-embed

1. sem sessao -> `/app` redireciona para login central.
2. usuario ativo com membership -> `/app` abre.
3. login social (Microsoft ou Google) conclui callback sem erro.
4. usuario admin -> `/admin` abre.
5. usuario ativo sem membership e sem admin -> `/pending`.
6. logout encerra sessao e bloqueia acesso.

## 8.3 Seguranca minima

1. token `alg=none` rejeitado.
2. token assinado com chave invalida rejeitado.
3. audience errada rejeitada.
4. issuer errado rejeitado.
5. open redirect bloqueado em `returnTo`.
6. nenhuma rota privada acessivel sem bearer valido.
7. callback nao entra em loop de "sessao nao encontrada" em staging/prod.
8. email ja existente entre password/social realiza account linking (mesma identidade global).

---

## 9. Plano de cutover rapido (sem migracao longa)

1. Deploy auth platform atualizado (ja concluido no EPIC-03).
2. Deploy LandWatch (frontend + backend + migration).
3. Executar checklist 8.1.
4. Deploy pbi-embed (frontend + backend + migration).
5. Executar checklist 8.2.
6. Rodar regressao cruzada:
   - login no auth portal;
   - abrir LandWatch;
   - abrir pbi-embed;
   - validar SSO sem novo login.

---

## 10. Rollback

Se regressao critica:

1. Reverter frontend para commit anterior (MSAL).
2. Reverter backend para guard Entra anterior.
3. Nao remover coluna `identity_user_id` (rollback seguro com schema additive).
4. Manter auth platform ativa para nao perder fluxo de contas.

Regra:

1. rollback e por app, nao precisa derrubar os dois produtos ao mesmo tempo.

---

## 11. Definicao de pronto (DoD) para EPIC-04 e EPIC-05

1. LandWatch e pbi-embed sem dependencia de MSAL.
2. LandWatch e pbi-embed validando JWT da auth platform via JWKS.
3. tabelas locais com `identity_user_id`.
4. fluxos `login`, `callback`, `me`, `logout`, `pending` validados.
5. lint/test/build verdes nos dois produtos.
6. checklist de seguranca basica concluido.

---

## 12. Prompt pronto para execucao com Codex (copiar e colar)

## 12.1 Prompt base LandWatch

```text
Implementar EPIC-04 completo conforme docs/plans/2026-02-18-epic-04-05-integracao-landwatch-pbi-embed.md.
Regras:
- substituir MSAL por @sigfarm/auth-client-vue no frontend;
- substituir validacao Entra por @sigfarm/auth-guard-nest no backend;
- adicionar identity_user_id no banco local;
- manter regras locais pending/active/disabled;
- rodar lint/test/build e corrigir falhas;
- no final, entregar diff por arquivo + checklist de aceite pass/fail.
```

## 12.2 Prompt base pbi-embed

```text
Implementar EPIC-05 completo conforme docs/plans/2026-02-18-epic-04-05-integracao-landwatch-pbi-embed.md.
Regras:
- substituir MSAL por @sigfarm/auth-client-vue no frontend;
- substituir validacao Entra por @sigfarm/auth-guard-nest no backend;
- adicionar identity_user_id no banco local;
- preservar regras de membership/customer/platform_admin;
- rodar lint/test/build e corrigir falhas;
- no final, entregar diff por arquivo + checklist de aceite pass/fail.
```

---

## 13. Referencias deste repo

1. `planing.md`
2. `status_card.md`
3. `packages/auth-client-vue/src/auth-client.ts`
4. `packages/auth-client-vue/src/return-to.ts`
5. `packages/auth-guard-nest/src/index.ts`
6. `packages/auth-contracts/src/index.ts`
7. `docs/security/authentication-assessment-2026-02-18.md`
8. `docs/security/iso-27002-2022-auth-mapping-2026-02-18.md`
