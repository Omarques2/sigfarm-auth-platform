# ADR-0001: Identidade Unificada SSO

Data: 2026-02-16  
Status: Aprovado

## Contexto
- `LandWatch` e `pbi-embed` implementam autenticacao duplicada (MSAL no frontend + validacao JWT Entra no backend).
- Regras de status divergentes (`active` direto no LandWatch e `pending` + membership no pbi-embed).
- Nao existe plataforma central para sessao, linking de provedores e governanca de seguranca.

## Decisoes
1. O repositorio `sigfarm-auth-platform` sera a unica fonte de identidade e sessao para os produtos da Sigfarm.
2. O motor de autenticacao escolhido e Better Auth.
3. O login inicial suportado sera:
   - Microsoft Entra (OAuth/OIDC provider).
   - Email/senha local com verificacao de email e reset de senha.
4. O identificador global de usuario sera `identity_user.id` (UUID) em tokens e integracoes.
5. Os produtos manterao autorizacao de dominio local (RBAC/membership), mas consumindo claims canonicas.
6. O contrato de claims `v1` sera versionado e congelado antes da integracao dos apps.

## Contrato de claims v1 (minimo)
- `sub`: `identity_user.id` (UUID).
- `sid`: id da sessao.
- `amr`: metodo de autenticacao (`entra`, `password`).
- `email`: email normalizado quando disponivel.
- `email_verified`: boolean.
- `global_status`: `pending | active | disabled`.
- `apps`: papeis globais por aplicacao (opcional).
- `ver`: versao do contrato (`1`).

## Politica de status global
- `pending`: identidade criada sem autorizacao final.
- `active`: identidade liberada para uso.
- `disabled`: identidade bloqueada globalmente.

Observacao:
- Cada aplicacao pode aplicar regras adicionais locais (ex.: membership customer no pbi-embed), mas nunca pode elevar `disabled` para acesso.

## Sessao e tokens
- Access token de curta duracao.
- Refresh token com rotacao obrigatoria.
- Revogacao por sessao (`sid`) e opcao de invalidar todas as sessoes do usuario.
- Assinatura com chave assimetrica + JWKS publico.

## Modelo de dados central (nucleo)
- `identity_user`
- `identity_provider_account`
- `identity_credential`
- `identity_session`
- `identity_email_token`
- `identity_audit_log`
- `identity_app_membership`

## Seguranca obrigatoria
- Hash de senha com Argon2id.
- Rate limit para login/reset/verify.
- Anti-enumeration em respostas de credencial.
- Auditoria de eventos de autenticacao e sessao.
- Segredos somente via secret manager/env seguro.

## Consequencias
- Ganhos:
  - elimina duplicacao entre produtos;
  - padroniza seguranca e observabilidade;
  - reduz custo de manutencao futura.
- Custos:
  - cria dependencia operacional da plataforma central;
  - exige disciplina de versionamento de contratos.

## Fora de escopo neste ciclo
- Billing gateway e planos pagos (apenas preparacao de modelo).
- MFA obrigatorio (pode entrar em ciclo posterior).

