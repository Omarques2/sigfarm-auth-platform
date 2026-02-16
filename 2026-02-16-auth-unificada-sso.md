# Plano de Autenticacao Unificada (LandWatch + pbi-embed)

Data: 2026-02-16  
Escopo: separar autenticacao dos projetos individuais, criar login/sessao unicos para todas as aplicacoes e preparar base para futura integracao com gateway de pagamentos.

Decisao oficial (2026-02-16): **Better Auth** como base da plataforma central de autenticacao da empresa.

## 1. Diagnostico atual dos repositorios

### 1.1 LandWatch (`C:\Users\Sigfarm\Desktop\Github\LandWatch`)
- Front usa `@azure/msal-browser` com redirect (`apps/web/src/auth/auth.ts`).
- Login atual e somente Microsoft/Entra (`apps/web/src/views/LoginView.vue`).
- API valida JWT Entra via JWKS (`apps/api/src/auth/entra-jwt.service.ts` + `apps/api/src/auth/auth.guard.ts`).
- Auth global via `GlobalAuthGuard` (`apps/api/src/auth/global-auth.guard.ts`), com bootstrap automatico de usuario ativo no primeiro acesso (`apps/api/src/auth/active-user.guard.ts` e `apps/api/src/users/users.service.ts`).
- Banco Prisma no schema `app` (`apps/api/prisma/schema.prisma`), com `app_user` baseado em `entra_sub`, sem senha local.

### 1.2 pbi-embed (`C:\Users\Sigfarm\Desktop\Github\pbi-embed`)
- Front tambem usa `@azure/msal-browser` (`apps/web/src/auth/auth.ts`).
- API valida JWT Entra com estrategia equivalente (`apps/api/src/auth/entra-jwt.service.ts`).
- Guardas por rota (`@UseGuards`) em vez de guard global.
- Fluxo de usuario mais restritivo: `pending`, exigencia de membership/role para ficar `active` (`apps/api/src/auth/active-user.guard.ts`, `apps/api/src/users/users.controller.ts`, `apps/api/src/users/users.service.ts`).
- Banco Prisma com foco em RBAC e permissoes Power BI (`apps/api/prisma/schema.prisma`), tambem sem senha local.

### 1.3 Conclusoes do estado atual
- Os dois projetos ja compartilham o mesmo paradigma tecnico de auth (MSAL no frontend + validacao JWT Entra no backend), mas com implementacoes duplicadas.
- Nao existe fonte unica de identidade/sessao; cada API faz bootstrap proprio.
- Nao existe fluxo nativo de email/senha (cadastro, verificacao de email, reset de senha).
- Diferencas de regra de status entre projetos (`active` imediato no LandWatch vs `pending`/membership no pbi-embed) precisam ser harmonizadas em uma politica central.

## 2. Objetivo alvo

Criar uma plataforma de identidade unica da empresa, separada dos produtos, com:
- login unico (SSO) para todos os sistemas;
- suporte simultaneo a Microsoft e email/senha;
- verificacao de email, recuperacao de senha e controle de sessao;
- modelo pronto para acoplamento com billing/planos (gateway futuro);
- SDK/pacote compartilhado para Vue e para NestJS, eliminando duplicacao.

## 3. Pesquisa de opcoes para email/senha + Vue + robustez

## 3.1 Candidatos avaliados

1. Better Auth (open source, TypeScript-first)
- Excelente DX para stack TS, com suporte Vue e plugins de email/password/social.
- Melhor equilibrio para o contexto atual: velocidade de implementacao + padronizacao de auth em apps Vue/Nest.
- Ponto de atencao: ecossistema mais novo que alternativas enterprise tradicionais.

2. SuperTokens (open source core + offerings comerciais)
- Bom DX para Node e frontend moderno, com receitas de email/senha e social login.
- Bom para time TypeScript que quer produtividade rapida.
- Ponto de atencao: alguns cenarios de SSO cross-domain e recursos enterprise sao planos pagos.

3. Entra External ID (nao open source, managed)
- Menor atrito para migrar do estado atual (ja usa Entra/MSAL).
- Suporta metodos de login com email+senha e social/enterprise no mesmo tenant.
- Ponto de atencao: lock-in e menor controle de plataforma propria.

### 3.2 Recomendacao tecnica

Para o seu contexto (multi-app, SSO corporativo, robustez e preparacao para billing), a recomendacao oficial e:

1. Adotar **Better Auth** como motor de autenticacao central no `sigfarm-auth-platform`, com:
- login por email/senha;
- login Microsoft/Entra via provider OAuth;
- fluxos de email verification/reset.

2. Criar um **Auth Core** separado (repositorio/plataforma), contendo:
- servico central de sessao/token e identidade;
- pacote compartilhado de validacao de token/claims para APIs Nest;
- pacote compartilhado de cliente auth para apps Vue;
- servico de identidade/entitlements (camada de negocio para status, memberships e no futuro planos).

3. Usar **Azure Communication Services Email** como provider SMTP/API para emails transacionais.

## 4. Arquitetura proposta (separada dos produtos)

## 4.1 Novo repositorio/plataforma sugerido

`C:\Users\Sigfarm\Desktop\Github\sigfarm-auth-platform` (novo)

Componentes:
- `apps/auth-api/` (Better Auth + API de perfil, memberships, entitlements e webhooks futuros de billing)
- `packages/auth-client-vue/` (SDK para Vue: login, callback, sessao, guardas)
- `packages/auth-guard-nest/` (SDK para Nest: validacao de token/sessao, claims, decorators e guards)
- `infra/` (IaC, secrets, deploy)

## 4.2 Fluxo de autenticacao alvo

1. Usuario acessa qualquer app (LandWatch, pbi-embed, futuros).
2. App usa o `sigfarm-auth-platform` (Better Auth) para iniciar login e sessao central.
3. Usuario autentica por:
- Microsoft/Entra (provider OAuth), ou
- email/senha local.
4. Plataforma central retorna sessao/tokens padronizados.
5. API do produto valida token/sessao emitidos pela plataforma central.
6. API resolve contexto de autorizacao (tenant, membership, plano/entitlements).

Resultado: sessao unica entre apps sem manter auth separado por produto.

## 5. Planejamento de banco de dados (auth e integracao com repos atuais)

## 5.1 Novo banco central de identidade (Auth DB)

Criar tabelas centrais (nomes de referencia):
- `identity_user` (id, email, email_verified_at, status, display_name, created_at, updated_at)
- `identity_provider_account` (identity_user_id, provider, provider_subject, provider_email, linked_at)
- `identity_credential` (identity_user_id, password_hash_argon2id, password_updated_at, requires_reset)
- `identity_session` (session_id, identity_user_id, created_at, expires_at, revoked_at, ip, user_agent)
- `identity_email_token` (identity_user_id, type[verify|reset], token_hash, expires_at, used_at)
- `identity_audit_log` (event_type, actor_user_id, payload, created_at)

Preparacao para billing (sem integrar gateway agora):
- `billing_customer` (identity_user_id ou tenant_id, external_customer_id, status)
- `billing_subscription` (plan_code, status, period_start, period_end, trial_end)
- `billing_entitlement` (feature_key, is_enabled, limits_json)

## 5.2 Ajustes nos bancos dos produtos

LandWatch (`app_user`) e pbi-embed (`users`) devem receber:
- `identity_user_id UUID NULL` + indice unico parcial;
- manter `entra_sub/entra_oid` durante migracao;
- migrar email para comparacao case-insensitive em ambos (LandWatch hoje nao usa `citext`).

Politica de transicao:
- primeiro aceitar tokens Entra legados e tokens da nova plataforma;
- depois desligar gradualmente Entra direto por app.

## 6. Roadmap de implementacao (fases)

### Fase 0 - Fundacao e decisoes (1 sprint)
- Definir ADR oficial: Better Auth como base da identidade central.
- Definir contratos de claims padrao entre apps.
- Definir politica unica de status (`pending`, `active`, `disabled`) e regras de ativacao.

### Fase 1 - Plataforma de identidade (1-2 sprints)
- Subir `sigfarm-auth-platform` em dev/staging com Better Auth.
- Configurar provider Microsoft/Entra, email/senha e politica de sessao.
- Habilitar email/senha, verificacao de email e reset.
- Integrar envio de email por Azure Communication Services (SMTP/API).

### Fase 2 - Shared packages (1 sprint)
- Criar `auth-client-vue` para substituir duplicacao de `apps/web/src/auth/*`.
- Criar `auth-guard-nest` para substituir duplicacao de `apps/api/src/auth/*`.
- Publicar pacotes internos versionados.

### Fase 3 - Integracao LandWatch (1 sprint)
- Migrar frontend de MSAL para `auth-client-vue` compartilhado (Better Auth).
- Migrar API para validacao de token/sessao do `sigfarm-auth-platform`.
- Adicionar `identity_user_id` e rotina de link.
- Validar regressao de `/v1/users/me` e guardas globais.

### Fase 4 - Integracao pbi-embed (1 sprint)
- Mesmo processo da Fase 3.
- Preservar regras de membership/customer/platform-admin no dominio local.
- Ajustar `users/me` para consumir identidade central e status efetivo.

### Fase 5 - Cutover e limpeza (1 sprint)
- Ativar login unico em producao para todos os apps.
- Congelar criacao de identidade local por projeto.
- Remover codigo legado duplicado de auth nos dois repositorios.
- Concluir runbooks de suporte/seguranca.

## 7. Regras de seguranca obrigatorias

- Hash de senha com Argon2id (nunca bcrypt baixo/custo fraco).
- Tokens curtos + refresh controlado.
- Cookies `httpOnly`, `secure`, `sameSite` quando usar sessao baseada em cookie.
- Rate limit forte em login, reset e verify email.
- Auditoria de eventos criticos: login, falha, reset, troca de senha, link de identidade.
- Bloqueio de acesso em email nao verificado (com excecoes explicitamente definidas).

## 8. Preparacao para gateway de pagamentos (fora do escopo imediato)

Mesmo sem integrar agora, ja deixar pronto:
- modelo de `subscription` e `entitlement`;
- eventos de dominio (`USER_REGISTERED`, `SUBSCRIPTION_CHANGED`, `SUBSCRIPTION_CANCELED`);
- ponto unico de decisao de acesso por plano (middleware/policy service), nao espalhar regra por endpoint.

## 9. Riscos e mitigacoes

1. Risco: migracao quebrar login atual de producao.
- Mitigacao: estrategia dual-issuer temporaria + rollout por app.

2. Risco: divergencia de status entre repos (`active` vs `pending`).
- Mitigacao: definir policy central de lifecycle antes da migracao.

3. Risco: duplicidade de contas por email/case.
- Mitigacao: normalizacao + `citext` + rotina de dedupe antes do cutover.

4. Risco: aumento de operacao da plataforma central de auth.
- Mitigacao: SRE runbook, backups, rotacao de chaves, monitoramento e ambiente staging espelho.

## 10. Entregaveis concretos esperados

- Documento ADR da arquitetura de identidade.
- Novo repositorio `sigfarm-auth-platform`.
- Pacote Vue de auth compartilhado.
- Pacote Nest de guard/shared claims.
- Migracoes Prisma nos dois produtos para `identity_user_id`.
- Fluxos funcionando: login Microsoft, cadastro email/senha, verify email, forgot/reset password.
- SSO funcional entre LandWatch e pbi-embed.

## 11. Fontes da pesquisa

- Better Auth docs (overview):  
  https://www.better-auth.com/docs
- Better Auth docs (email/password):  
  https://www.better-auth.com/docs/authentication/email-password
- Better Auth docs (Vue integration):  
  https://www.better-auth.com/docs/integrations/vue
- Better Auth docs (social providers):  
  https://www.better-auth.com/docs/authentication/social
- SuperTokens docs (quickstart e receitas de auth):  
  https://supertokens.com/docs/quickstart/integrations  
  https://supertokens.com/docs/authentication/email-password/introduction
- SuperTokens pricing (observacao sobre recursos enterprise/SSO):  
  https://supertokens.com/pricing
- Microsoft Entra External ID (metodos de sign-in):  
  https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-user-flow-sign-in-methods
- Azure Communication Services Email (quickstart e SMTP):  
  https://learn.microsoft.com/en-us/azure/communication-services/quickstarts/email/send-email  
  https://learn.microsoft.com/en-us/azure/communication-services/concepts/email/email-smtp-overview
