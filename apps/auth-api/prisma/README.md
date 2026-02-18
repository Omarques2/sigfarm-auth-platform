# Prisma - Auth API

## Pre-requisitos
- PostgreSQL com extensoes `pgcrypto` e `citext` habilitadas (migration ja cria automaticamente).
- Variaveis:
  - `DATABASE_URL`
  - `SHADOW_DATABASE_URL` (necessaria para `migrate dev`)

## Comandos
- Validar schema: `npm run prisma:validate --workspace @sigfarm/auth-api`
- Gerar client: `npm run prisma:generate --workspace @sigfarm/auth-api`
- Aplicar migrations (deploy): `npm run db:migrate:deploy --workspace @sigfarm/auth-api`
- Seed catalogo inicial: `npm run db:seed --workspace @sigfarm/auth-api`

## Observacoes
- O seed e idempotente: pode ser executado varias vezes sem duplicar apps/roles.
- A migration inicial cria tabelas centrais de identidade e indices criticos de autenticacao.

