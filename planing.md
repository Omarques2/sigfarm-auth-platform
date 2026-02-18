# Sigfarm Auth Platform - Planejamento de Implementacao

Data base: 2026-02-16

## 1. Objetivo
Construir o `sigfarm-auth-platform` como plataforma central de identidade e sessao para `LandWatch` e `pbi-embed`, com login unico (SSO), suporte a Microsoft Entra + email/senha, alta qualidade de engenharia e hardening de seguranca.

Este plano assume migracao rapida (sem estrategia longa de convivio), porque os dois produtos estao em ambiente de teste.

## 2. Diagnostico consolidado dos repositorios

### 2.1 LandWatch
- Frontend Vue usa `@azure/msal-browser` em `apps/web/src/auth/auth.ts`.
- Backend Nest valida JWT Entra via `jose` e aplica `GlobalAuthGuard`.
- `UsersService` ativa usuario no primeiro login (`status: active`).
- Banco Prisma no schema `app` com `app_user(entra_sub, entra_oid, email...)`.

### 2.2 pbi-embed
- Frontend Vue tambem usa `@azure/msal-browser` em `apps/web/src/auth/auth.ts`.
- Backend Nest valida JWT Entra via `jose`, mas com guards por rota (nao global).
- Regras de acesso mais restritivas: `pending`, membership ativa, papel `platform_admin`.
- Banco Prisma com foco em RBAC/customer e `users(entra_sub, entra_oid, email citext...)`.

### 2.3 Problemas atuais (comuns)
- Implementacao de auth duplicada em frontend e backend.
- Sem fonte unica de identidade/sessao.
- Sem fluxo nativo de email/senha (cadastro, verificacao, reset).
- Divergencia de regras de lifecycle (`active` imediato vs `pending`/membership).

## 3. Diretrizes (skills de referencia)
- `writing-plans`: backlog executavel, com ordem de dependencia clara.
- `auth-implementation-patterns`: separacao AuthN/AuthZ, tokens curtos, refresh seguro, RBAC central.
- `azure-auth`: boas praticas de Entra/MSAL, tratamento de fluxo redirect e validacao robusta de issuer.
- `security-review`: hardening, auditoria, controle de segredos, eventos de seguranca e testes negativos.

## 4. Arquitetura alvo do sigfarm-auth-platform

## 4.1 Estrutura do repositorio
- `apps/auth-api` - API central de identidade (Better Auth + dominio de autorizacao).
- `packages/auth-client-vue` - SDK compartilhado para apps Vue.
- `packages/auth-guard-nest` - SDK compartilhado para APIs Nest.
- `packages/auth-contracts` - tipos/claims/erros canonicos compartilhados.
- `infra` - deploy, envs, secrets, runbooks.

## 4.2 Fluxo alvo de autenticacao
1. App (LandWatch/pbi-embed) redireciona usuario para Auth Platform.
2. Usuario autentica por Entra ou email/senha.
3. Auth Platform cria/atualiza identidade central e sessao.
4. App recebe sessao padronizada.
5. API do app valida token emitido pela Auth Platform (nao mais token Entra direto).
6. API aplica autorizacao local (membership, customer, admin) com claims padronizadas.

## 4.3 Fronteira de responsabilidade
- Auth Platform:
  - identidade primaria, credenciais, sessoes, verificacao email, reset senha;
  - emissao de tokens e claims canonicas;
  - auditoria de eventos de autenticacao.
- Apps:
  - regras de dominio (permissoes por customer/report/farm etc);
  - consumo das claims centralizadas.

## 5. Contratos canonicos (evitar retrabalho)

## 5.1 Identidade
- Chave primaria global: `identity_user.id` (UUID).
- Todo app deve mapear usuario local para `identity_user_id`.
- `email` sempre normalizado (`lowercase`, trim) e unico case-insensitive.

## 5.2 Claims minimas do access token
- `sub` = `identity_user.id`
- `sid` = sessao atual
- `amr` = metodo de auth (`entra`, `password`, etc)
- `email`, `email_verified`
- `global_status` (`active`, `pending`, `disabled`)
- `apps` (lista de apps com papeis globais, quando aplicavel)
- `ver` (versao do contrato de claims)

## 5.3 Contrato de erros de auth
- `UNAUTHORIZED`
- `FORBIDDEN`
- `EMAIL_NOT_VERIFIED`
- `ACCOUNT_DISABLED`
- `TOKEN_EXPIRED`
- `RATE_LIMIT`
- `INVALID_CREDENTIALS`

## 6. Modelo de dados central (Auth DB)

## 6.1 Tabelas obrigatorias
- `identity_user`
- `identity_provider_account` (entra, password, futuros providers)
- `identity_credential` (hash Argon2id + metadados de senha)
- `identity_session` (refresh rotation, revogacao, ip/user-agent)
- `identity_email_token` (verify/reset com hash e expiracao)
- `identity_audit_log` (eventos de seguranca)
- `identity_app_membership` (vinculo global usuario x app x status base)

## 6.2 Regras de modelagem
- Unicos: `email_normalized`, `(provider, provider_subject)`, `session_id`.
- Indices: `identity_user(status)`, `identity_session(user_id, expires_at)`, `identity_audit_log(created_at, event_type)`.
- Soft-delete apenas onde necessario; revogacao explicita para sessoes/tokens.

## 7. Sequencia de execucao unica (ordem logica obrigatoria)
Nao e migracao em fases longas. E uma trilha unica de implementacao com ordem de dependencia para nao gerar retrabalho.

### 7.1 Fundacao tecnica do repo
- Criar monorepo com `auth-api`, packages compartilhados e padrao de lint/test/build.
- Configurar CI minima (lint + unit + contract tests + build).
- Definir strategy de versionamento interno para SDKs.
Saida esperada: base pronta para desenvolver sem refatoracao estrutural futura.

### 7.2 Contratos primeiro (antes de codigo de integracao)
- Publicar `packages/auth-contracts` com tipos de claims, erros e payloads.
- Escrever contract tests para `token payload`, `/session`, `/me`, `/logout`.
- Congelar `v1` do contrato para integrar apps sem quebrar interface.
Saida esperada: times de LandWatch/pbi-embed implementam contra contrato estavel.

### 7.3 Banco de identidade + migracoes
- Modelar schema Prisma do Auth DB.
- Criar migracoes iniciais e seeds tecnicos (apps registrados, papeis base).
- Incluir validacoes de consistencia (email normalize, unicidade provider-subject).
Saida esperada: base de dados pronta para receber login Entra e email/senha.

### 7.4 Auth engine (Better Auth) + fluxo email/senha
- Integrar Better Auth no `auth-api`.
- Implementar cadastro, login, logout, verify email, forgot/reset password.
- Persistir sessoes e eventos de auditoria.
- Implementar politicas de senha (minimo, bloqueio de senha fraca, history opcional).
Saida esperada: fluxo completo de credencial local com seguranca.

### 7.5 Provider Microsoft Entra
- Configurar provider Entra no Auth Platform.
- Implementar account linking seguro (mesmo email + confirmacao de ownership).
- Garantir que usuarios Entra existentes sejam consolidados em `identity_user`.
Saida esperada: usuario pode entrar com Entra ou senha sem criar conta duplicada.

### 7.6 Emissao e validacao de tokens
- Definir access token curto + refresh token rotativo.
- Implementar revogacao de sessao por `sid` e `logout all devices`.
- Assinatura com chave assimetrica e `kid` rotacionavel.
- Expor JWKS publico para os backends consumidores.
Saida esperada: APIs Nest validam token da plataforma central com baixa acoplacao.

### 7.7 SDK Vue compartilhado (`auth-client-vue`)
- Encapsular login, callback, sessao, renovacao, logout e guards de rota.
- Encapsular resiliencia ja validada nos repos atuais (single-flight, retry controlado, recovery de background).
- Adapter para substituir `apps/web/src/auth/*` dos dois apps sem duplicacao.
Saida esperada: troca de auth no frontend com mudanca minima por app.

### 7.8 SDK Nest compartilhado (`auth-guard-nest`)
- Guard para validar JWT da Auth Platform.
- Decorators/helpers para ler claims padronizadas.
- Interceptor opcional para correlation + erro canonico de auth.
Saida esperada: APIs LandWatch/pbi-embed removem dependencia direta do Entra JWT parser.

### 7.9 Integracao direta no LandWatch
- Frontend: substituir MSAL por `auth-client-vue`.
- Backend: trocar `EntraJwtService/AuthGuard` por `auth-guard-nest`.
- DB local: adicionar `identity_user_id` em `app_user` + indice unico parcial.
- Ajustar `UsersService` para sincronizar com identidade central.
Saida esperada: LandWatch autenticando 100% pela plataforma central.

### 7.10 Integracao direta no pbi-embed
- Frontend: substituir MSAL por `auth-client-vue`.
- Backend: usar `auth-guard-nest` e manter regras de membership/customer.
- DB local: adicionar `identity_user_id` em `users` + indice unico parcial.
- Ajustar `users/me` para status efetivo usando `global_status` + regras locais.
Saida esperada: pbi-embed autenticando 100% pela plataforma central.

### 7.11 Hardening final + operacao
- Rate limit forte em login/reset/verify.
- Auditoria obrigatoria de eventos de seguranca (sucesso e falha).
- Dashboards/logs para sessao, falhas, lockout, reset.
- Runbook de incidentes: revogar chaves, revogar sessoes, recuperar servico.
Saida esperada: operacao segura e pronta para producao.

## 8. Criterios de qualidade e seguranca (nao negociaveis)
- Senha com Argon2id e parametros fortes.
- Access token curto (ex.: 10-15 min) e refresh rotativo com reuse detection.
- Chaves de assinatura com rotacao planejada e `kid`.
- Cookies somente `httpOnly + secure + sameSite` quando sessao cookie-based.
- Protecao anti brute force e anti enumeration.
- CSRF protection para endpoints state-changing baseados em cookie.
- Logs sem segredos e sem token bruto.
- Auditoria para: login, falha login, logout, reset, verify email, troca senha, link/unlink provider.

## 9. Estrategia de testes (TDD + regressao)

### 9.1 Auth API
- Unit: services de credencial, sessao, claims, linking, rate-limit policy.
- Integration: fluxo completo de register/login/verify/reset.
- Security tests: token invalido, token expirado, replay refresh, brute force.

### 9.2 SDKs
- `auth-client-vue`: testes de navegacao/guard/callback/recovery.
- `auth-guard-nest`: testes de validacao JWT, claims parsing e erros.

### 9.3 Integracao apps
- LandWatch e pbi-embed: smoke e2e de login, `/me`, rotas protegidas, logout.
- Testes de regressao para status/pending/admin/customer membership.

## 10. Plano de cutover rapido (sem migracao longa)
- Preparar staging dos 3 repositorios.
- Publicar Auth Platform + SDKs.
- Atualizar LandWatch e pbi-embed para nova auth no mesmo ciclo.
- Executar bateria de testes integrados.
- Liberar producao em janela unica com rollback simples (toggle de env para auth antiga apenas se necessario).

## 11. Riscos principais e mitigacoes
- Duplicidade de conta por email:
  - Mitigacao: normalizacao forte + linking transacional + testes de dedupe.
- Regressao em regras de `pending/active`:
  - Mitigacao: contrato de status central + testes de autorizacao por app.
- Quebra de sessao entre apps:
  - Mitigacao: testes e2e cross-app e cookie/domain strategy definida antes do go-live.
- Superficie de ataque maior na plataforma central:
  - Mitigacao: hardening de rate limit, audit logs, monitoramento e runbook.

## 12. Definition of Done (DoD)
- Auth Platform em producao com Entra + email/senha + verify + reset.
- SDK Vue e SDK Nest publicados e usados por LandWatch e pbi-embed.
- Codigo legado de auth duplicada removido dos apps.
- Testes unit/integration/e2e verdes nos 3 repos.
- Checklist de seguranca aprovado e evidenciado.

## 13. Status real de implementacao (revisado em 2026-02-18)

### 13.1 Concluido no codigo
- Auth API central com Better Auth, Entra + email/senha, verify/reset, refresh rotativo e JWKS.
- Hardening principal ativo: rate limit, auditoria de eventos e redaction de dados sensiveis em logs.
- Fluxo de self-service de conta implementado:
  - `GET /v1/auth/account`
  - `POST /v1/auth/account/profile`
  - `POST /v1/auth/account/email-change/request-code`
  - `POST /v1/auth/account/email-change/confirm-code`
- Frontend auth com telas:
  - `/login`, `/verify-email`, `/reset-password`, `/auth/callback`
  - `/my-account` (resumo) e `/my-account/edit` (edicao de dados + troca de email por codigo)
- Contratos (`packages/auth-contracts`) com testes de schema.
- Monorepo com CI (`lint`, `test`, `build`) em PR/push.

### 13.2 Parcial (evitar interpretar como pronto)
- `packages/auth-client-vue` existe, mas ainda e scaffold e nao substitui os fluxos completos dos apps consumidores.
- `packages/auth-guard-nest` existe, mas ainda e scaffold sem guard/decorators prontos para Nest em producao.

### 13.3 Nao iniciado no repo atual
- Integracao efetiva de LandWatch e pbi-embed usando SDKs finais.
- Bateria E2E cross-repo de cutover.
- Observabilidade operacional completa (dashboards/alertas Azure Monitor e runbook de incidente fechado).
