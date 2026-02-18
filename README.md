# sigfarm-auth-platform

Plataforma central de autenticacao e sessao da Sigfarm, usada por multiplas aplicacoes (ex.: LandWatch e pbi-embed).

## Visao geral

Este repositorio concentra:

1. auth API central (`apps/auth-api`) com Better Auth, JWT proprio, JWKS, email/senha e login Microsoft.
2. auth web central (`apps/auth-web`) com `/login`, `/verify-email`, `/reset-password`, `/my-account`.
3. contratos de auth (`packages/auth-contracts`) para claims e envelopes padrao.
4. SDK frontend (`packages/auth-client-vue`) para login/callback/sessao/refresh/logout.
5. SDK backend (`packages/auth-guard-nest`) para validacao JWT e claims tipadas em Nest.

## Estrutura

1. `apps/auth-api`
2. `apps/auth-web`
3. `packages/auth-contracts`
4. `packages/auth-client-vue`
5. `packages/auth-guard-nest`
6. `docs/`

## Requisitos

1. Node `>=22`
2. npm `>=11`

## Setup rapido

1. Instalar dependencias:

```bash
npm install
```

2. Criar env local:

```bash
cp .env.example apps/auth-api/.env
```

3. Aplicar migrations e seed:

```bash
npm run db:migrate:deploy --workspace @sigfarm/auth-api
npm run db:seed --workspace @sigfarm/auth-api
```

4. Subir API e web em dev:

```bash
npm run dev --workspace @sigfarm/auth-api
npm run dev --workspace @sigfarm/auth-web
```

## Scripts principais

No monorepo:

1. `npm run lint`
2. `npm run test`
3. `npm run build`

No `auth-api`:

1. `npm run dev --workspace @sigfarm/auth-api`
2. `npm run start --workspace @sigfarm/auth-api`
3. `npm run security:test-auth --workspace @sigfarm/auth-api`
4. `npm run db:migrate:deploy --workspace @sigfarm/auth-api`
5. `npm run db:seed --workspace @sigfarm/auth-api`

No `auth-web`:

1. `npm run dev --workspace @sigfarm/auth-web`
2. `npm run build --workspace @sigfarm/auth-web`
3. `npm run test --workspace @sigfarm/auth-web`

## Documentacao importante

Planejamento e execucao:

1. `planing.md`
2. `status_card.md`
3. `docs/plans/2026-02-18-epic-04-05-integracao-landwatch-pbi-embed.md`

Seguranca:

1. `docs/security/authentication-assessment-2026-02-18.md`
2. `docs/security/iso-27002-2022-auth-mapping-2026-02-18.md`
3. `docs/security/auth-broken-auth-results.json`
4. `docs/nbr_iso_27002.pdf`

## Integracao com produtos

A estrategia recomendada para EPIC-04 e EPIC-05 esta no playbook:

`docs/plans/2026-02-18-epic-04-05-integracao-landwatch-pbi-embed.md`

Esse documento contem:

1. ordem de implementacao sem retrabalho;
2. arquivos exatos por repo;
3. passos de migracao frontend/backend/db;
4. checklist de aceite pass/fail;
5. plano de rollback.
