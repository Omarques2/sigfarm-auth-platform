# @sigfarm/auth-client-vue

SDK Vue/TypeScript para ciclo de autenticacao da Sigfarm com foco em producao.

## Recursos
- Login redirect seguro (`buildLoginUrl`) com sanitizacao de `returnTo`.
- Callback/session exchange via `POST /v1/auth/refresh`.
- Refresh com **single-flight** (evita rajada concorrente).
- Recovery de background com retry/backoff.
- `authFetch` com bearer automatico e retry unico em `401`.
- Validacao de contrato com `@sigfarm/auth-contracts`.

## Exemplo rapido
```ts
import { createAuthClient } from "@sigfarm/auth-client-vue";

const authClient = createAuthClient({
  authApiBaseUrl: "https://auth.sigfarmintelligence.com",
  authPortalBaseUrl: "https://auth.sigfarmintelligence.com",
  appBaseUrl: window.location.origin,
  allowedReturnOrigins: [
    "https://bi.sigfarmintelligence.com",
    "https://landwatch.sigfarmintelligence.com",
  ],
  defaultReturnTo: `${window.location.origin}/home`,
});

// 1) login
const loginUrl = authClient.buildLoginUrl({ returnTo: window.location.href });
window.location.assign(loginUrl);

// 2) callback
await authClient.exchangeSession();

// 3) chamada protegida
const response = await authClient.authFetch("https://api.sigfarmintelligence.com/v1/reports");
```

## Validacao em sandbox
- Fluxo validado por testes em:
  - `packages/auth-client-vue/test/auth-client.spec.ts`
  - `packages/auth-client-vue/test/contract-sdk-api.spec.ts`