# Sigfarm Auth Platform - Status Cards (ordem logica, sem retrabalho)

Legenda:
- [ ] nao iniciado
- [~] em andamento
- [x] concluido

Prioridade:
- P0 = bloqueante de seguranca/arquitetura
- P1 = essencial para entrega
- P2 = melhoria relevante apos core pronto

## EPIC-00 - Base de engenharia e contratos (executar primeiro)

- [x] P0 Card 00.01 - Definir ADR oficial de identidade unificada
  Objetivo: registrar decisoes tecnicas obrigatorias (Better Auth, claims, sessao, ownership de dados).
  Dependencias: nenhuma.
  Criterios de aceite:
  - ADR aprovado com escopo de Auth Platform e fronteira AuthN/AuthZ.
  - Contrato de claims `v1` fechado e versionado.
  - Politica global de status (`pending`, `active`, `disabled`) definida.

- [x] P0 Card 00.02 - Estruturar monorepo do `sigfarm-auth-platform`
  Objetivo: criar base definitiva (`apps/auth-api`, `packages/auth-client-vue`, `packages/auth-guard-nest`, `packages/auth-contracts`, `infra`).
  Dependencias: Card 00.01.
  Criterios de aceite:
  - `lint`, `test`, `build` funcionando por app/package.
  - Pipeline CI inicial executando em PR.
  - Padrao de env e secrets documentado.

- [x] P0 Card 00.03 - Publicar contratos canonicos (`packages/auth-contracts`)
  Objetivo: evitar quebrar integracao por divergencia de payload/erros.
  Dependencias: Card 00.01 e 00.02.
  Criterios de aceite:
  - Tipos de claims, sessoes e erros publicados.
  - Contract tests cobrindo `/session`, `/me`, `/logout`, refresh.
  - Versao `v1` congelada antes das integracoes.

## EPIC-01 - Banco de identidade central

- [x] P0 Card 01.01 - Modelar schema Prisma do Auth DB
  Objetivo: criar entidades centrais (`identity_user`, provider, credential, session, email_token, audit_log).
  Dependencias: EPIC-00 completo.
  Criterios de aceite:
  - Migracao inicial aplicada sem erro.
  - Constraints de unicidade e indices criticos criados.
  - `email` normalizado e case-insensitive.

- [x] P0 Card 01.02 - Implementar tabela de vinculo por app (`identity_app_membership`)
  Objetivo: permitir status e papeis globais por aplicacao sem duplicar identidade.
  Dependencias: Card 01.01.
  Criterios de aceite:
  - Usuario pode ter status por app.
  - Relacao `identity_user` x app unica e consistente.
  - Queries de autorizacao com indice eficiente.

- [x] P1 Card 01.03 - Seed tecnico inicial
  Objetivo: registrar apps `LANDWATCH` e `PBI_EMBED`, papeis base e configuracoes de ambiente.
  Dependencias: Card 01.01 e 01.02.
  Criterios de aceite:
  - Seed idempotente.
  - Ambientes novos sobem com dados minimos prontos.
  - Sem segredo hardcoded.

## EPIC-02 - Core de autenticacao (Better Auth)

- [x] P0 Card 02.01 - Bootstrap Better Auth no `auth-api`
  Objetivo: subir engine central de auth com persistencia no Auth DB.
  Dependencias: EPIC-01 completo.
  Criterios de aceite:
  - Endpoint de health pronto.
  - Login e sessao basicos operando em dev.
  - Logs estruturados sem vazar segredo.

- [x] P0 Card 02.02 - Fluxo email/senha completo
  Objetivo: cadastro, login, verify email, forgot/reset password.
  Dependencias: Card 02.01.
  Criterios de aceite:
  - Cadastro cria conta com status consistente.
  - Verify email valida token com expiracao e uso unico.
  - Reset senha invalida sessoes antigas quando configurado.

- [x] P0 Card 02.03 - Integracao Microsoft Entra
  Objetivo: permitir login Entra no auth central e consolidar identidade.
  Dependencias: Card 02.01.
  Criterios de aceite:
  - Login Entra cria/atualiza `identity_provider_account`.
  - Linking evita duplicidade de conta.
  - Fluxo callback cobre erros comuns de redirect.

- [x] P0 Card 02.04 - Emissao de access/refresh token segura
  Objetivo: padrao de token para todos os apps.
  Dependencias: Card 02.02 e 02.03.
  Criterios de aceite:
  - Access token curto e refresh rotativo ativos.
  - Reuso de refresh invalida sessao (reuse detection).
  - JWKS publicado com `kid` valido.

- [x] P0 Card 02.05 - Politicas de hardening de auth
  Objetivo: proteger endpoints de autenticacao contra abuso.
  Dependencias: Card 02.02, 02.03, 02.04.
  Criterios de aceite:
  - Rate limit em login/reset/verify.
  - Anti-enumeration em erros de credencial.
  - Auditoria de eventos de seguranca persistida.

- [x] P1 Card 02.06 - Self-service de conta (`/my-account` e `/my-account/edit`)
  Objetivo: permitir visualizacao e edicao segura de dados da conta no portal central.
  Dependencias: Card 02.02 e 02.05.
  Criterios de aceite:
  - `/my-account` exibe resumo da conta e acao de editar por icone.
  - `/my-account/edit` permite editar nome.
  - Fluxo de troca de email exige codigo enviado ao novo email antes da confirmacao.
  - Reenvio de codigo respeita cooldown.
  - Frontend consome endpoints `/v1/auth/account*` sem quebrar contrato.

## EPIC-03 - SDK compartilhado para apps

- [x] P1 Card 03.01 - Criar `auth-client-vue`
  Objetivo: remover duplicacao de MSAL/auth lifecycle nos dois frontends.
  Dependencias: EPIC-02 completo.
  Status atual:
  - SDK implementado com login redirect seguro, callback/session exchange, sessao, refresh e logout.
  - Single-flight de refresh e recovery de background com retry/backoff implementados.
  - Contratos v1 validados por testes automatizados (`auth-client-vue/test`).
  Criterios de aceite:
  - SDK cobre login, callback, sessao, refresh, logout.
  - Inclui single-flight e recovery de background.
  - Exemplo de uso validado em app sandbox.

- [x] P1 Card 03.02 - Criar `auth-guard-nest`
  Objetivo: padronizar validacao de token e acesso a claims nas APIs Nest.
  Dependencias: Card 02.04.
  Status atual:
  - Guard Nest implementado com validacao JWT RS256 via JWKS remoto (jose).
  - Decorators e helpers de claims tipadas implementados (`CurrentAuthClaims`, `CurrentAuthUserId`, `CurrentAuthSessionId`).
  - Suporte a bypass por metadata (`@Public`) implementado.
  Criterios de aceite:
  - Guard valida JWT da Auth Platform via JWKS.
  - Decorators/helpers entregam claims tipadas.
  - Erros seguem contrato canonico.

- [x] P1 Card 03.03 - Testes de contrato SDK <-> Auth API
  Objetivo: impedir regressao de payload/claims durante evolucao.
  Dependencias: Card 03.01 e 03.02.
  Status atual:
  - Suite de contrato implementada para SDK Vue (`contract-sdk-api.spec.ts`) validando refresh/session/me/logout.
  - Esquema canonico de claims publicado em `@sigfarm/auth-contracts` (`AccessTokenClaimsSchema`).
  - Suite de guard valida parsing tipado e cenarios de erro.
  Criterios de aceite:
  - Suite automatica quebra se contrato mudar sem versao.
  - Cobertura de fluxo feliz e erro.
  - Pipeline CI bloqueia merge em quebra de contrato.

## EPIC-04 - Integracao LandWatch (migracao direta)

- [ ] P1 Card 04.01 - Migrar frontend LandWatch para `auth-client-vue`
  Objetivo: substituir `apps/web/src/auth/*` atual.
  Dependencias: EPIC-03 completo.
  Criterios de aceite:
  - Login/callback/logout funcionam no novo provider.
  - Guard de rota mantem comportamento esperado.
  - Nenhuma dependencia direta de MSAL no app final.

- [ ] P1 Card 04.02 - Migrar backend LandWatch para `auth-guard-nest`
  Objetivo: parar validacao direta de token Entra no app.
  Dependencias: Card 03.02.
  Criterios de aceite:
  - Rotas privadas validam token da Auth Platform.
  - `users/me` opera com `identity_user_id`.
  - Regras `disabled`/`active` preservadas.

- [ ] P1 Card 04.03 - Ajustar banco LandWatch para `identity_user_id`
  Objetivo: mapear usuario local com identidade central.
  Dependencias: Card 04.02.
  Criterios de aceite:
  - Coluna `identity_user_id` adicionada com indice unico parcial.
  - Fluxo de primeiro login nao cria duplicidade.
  - Queries de usuario mantem performance.

## EPIC-05 - Integracao pbi-embed (migracao direta)

- [ ] P1 Card 05.01 - Migrar frontend pbi-embed para `auth-client-vue`
  Objetivo: padronizar auth client com LandWatch.
  Dependencias: EPIC-03 completo.
  Criterios de aceite:
  - `/login`, `/auth/callback`, `/pending` operando com nova auth.
  - Fluxo resiliente de token mantido.
  - Nenhuma dependencia direta de MSAL no app final.

- [ ] P1 Card 05.02 - Migrar backend pbi-embed para `auth-guard-nest`
  Objetivo: manter regras de membership/admin com token central.
  Dependencias: Card 03.02.
  Criterios de aceite:
  - `AuthGuard` local passa a consumir claims centrais.
  - `ActiveUserGuard` continua exigindo membership/customer quando aplicavel.
  - Endpoint `/users/me` retorna status efetivo correto.

- [ ] P1 Card 05.03 - Ajustar banco pbi-embed para `identity_user_id`
  Objetivo: consolidar identidade sem perder RBAC local.
  Dependencias: Card 05.02.
  Criterios de aceite:
  - Coluna `identity_user_id` em `users` com indice unico parcial.
  - Relacoes RBAC continuam funcionando.
  - Sem duplicidade de usuario por email/sub.

## EPIC-06 - Seguranca, observabilidade e operacao

- [ ] P0 Card 06.01 - Implementar auditoria completa de seguranca
  Objetivo: rastrear eventos criticos de autenticacao e sessao.
  Dependencias: EPIC-02 e integracoes principais.
  Criterios de aceite:
  - Eventos: login sucesso/falha, reset, verify, revoke, logout.
  - Eventos possuem actor, timestamp, ip, user-agent, origem.
  - Consulta basica de auditoria disponivel para suporte.

- [ ] P0 Card 06.02 - Hardening de segredos e criptografia
  Objetivo: eliminar exposicao de segredo e fragilidade criptografica.
  Dependencias: Card 02.04.
  Criterios de aceite:
  - Chaves e secrets via env/secret manager.
  - Nenhum token/senha em log.
  - Rotacao de chaves documentada e testada.

- [ ] P1 Card 06.03 - Dashboards e alertas operacionais
  Objetivo: detectar falhas de auth antes de impacto amplo.
  Dependencias: Card 06.01.
  Criterios de aceite:
  - Metricas de erro de login, taxa de refresh falho e 429 disponiveis.
  - Alertas configurados para degradacao de auth.
  - Runbook de resposta a incidente pronto.

- [ ] P2 Card 06.04 - Diagnostico Azure centralizado (baixa urgencia)
  Objetivo: enviar logs de `sigfarm-comms` e `sigfarm-email` para Log Analytics com retencao padrao.
  Dependencias: Card 06.01.
  Criterios de aceite:
  - Diagnostic Settings ativos para `sigfarm-comms` e `sigfarm-email`.
  - Workspace Log Analytics definido e testado com recebimento de eventos.
  - Consulta KQL basica documentada para falhas de envio, bounce e blocked.

- [ ] P2 Card 06.05 - Alertas operacionais de autenticacao e email (baixa urgencia)
  Objetivo: acionar resposta quando houver degradacao real de auth/email.
  Dependencias: Card 06.04.
  Criterios de aceite:
  - Alertas para pico de erro de login, pico de 429, falha de envio de email, bounce/blocked.
  - Action Group configurado com canal de notificacao do time.
  - Thresholds e janela temporal documentados com racional tecnico.

- [ ] P2 Card 06.06 - Hardening de ambiente produtivo (ISO 8.31) (baixa urgencia)
  Objetivo: formalizar checklist tecnico para separacao de ambientes e seguranca de sessao.
  Dependencias: Card 02.05 e Card 06.02.
  Criterios de aceite:
  - Evidencia de HTTPS + cookie `Secure` em staging/prod anexada.
  - `trustedOrigins` revisado por ambiente (dev/staging/prod) sem wildcard indevido.
  - Checklist de deploy bloqueia promote se algum item de hardening falhar.

- [ ] P2 Card 06.07 - Governanca de dependencias de seguranca (baixa urgencia)
  Objetivo: reduzir passivo de vulnerabilidades transitivas sem quebra de runtime.
  Dependencias: Card 06.02.
  Criterios de aceite:
  - Politica de patch mensal definida (`npm audit` + update guiado).
  - Plano de upgrade Prisma/toolchain com teste de regressao.
  - Meta de zerar high/critical e reduzir moderadas documentada.

- [ ] P2 Card 06.08 - Pacote de evidencias ISO 27002 para auditoria (baixa urgencia)
  Objetivo: consolidar trilha de evidencias tecnicas por controle de autenticacao.
  Dependencias: Card 06.04, 06.05 e 06.06.
  Criterios de aceite:
  - Mapeamento controle -> evidencia -> comando/reporte reproduzivel.
  - PDF ISO OCR/searchable (ou referencia licenciada) para rastreabilidade formal.
  - Documento de conformidade versionado em `docs/security`.

## EPIC-07 - Validacao final e cutover rapido

- [ ] P0 Card 07.01 - Bateria E2E integrada dos 3 repositorios
  Objetivo: validar fluxo ponta a ponta antes de liberar.
  Dependencias: EPIC-04, EPIC-05, EPIC-06.
  Criterios de aceite:
  - Cenarios: login Entra, login senha, verify, reset, logout, rota protegida.
  - Cenarios de erro: token expirado, conta disabled, sem membership (pbi).
  - Todos os testes verdes em staging.

- [ ] P0 Card 07.02 - Cutover unico em producao com rollback simples
  Objetivo: trocar para auth central sem janela longa de coexistencia.
  Dependencias: Card 07.01.
  Criterios de aceite:
  - LandWatch e pbi-embed autenticam pela plataforma central no mesmo ciclo.
  - Plano de rollback validado (troca de env/config controlada).
  - Pos-go-live monitorado sem erro critico de autenticacao.

## Checklist final de nao retrabalho
- [ ] Contratos de claims e erros fechados antes da integracao de apps.
- [ ] SDKs prontos antes de substituir auth em LandWatch/pbi-embed.
- [ ] Colunas `identity_user_id` aplicadas antes de limpar codigo legado.
- [ ] Testes de contrato e E2E rodando antes de cutover.
- [ ] Runbook e observabilidade ativos antes de producao.
