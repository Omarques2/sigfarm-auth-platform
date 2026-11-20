/**
 * Página para onde o Better Auth redireciona erros que ele não consegue
 * devolver ao callback do app (ex.: `state_mismatch` quando o cookie `state`
 * expirou ou outro login começou em paralelo).
 *
 * Sem isso, em produção o Better Auth redireciona para a raiz do api-auth
 * (`/?error=...`), que responde 404.
 *
 * Aponta para `/auth/callback` do portal, que já trata `?error=`: mostra
 * "Não foi possível concluir o login social. Tente novamente." e volta para /login.
 *
 * A URL não pode ter query string: o Better Auth 1.4 (oauth2/state) concatena
 * `?error=<codigo>` sem checar se já existe `?`.
 */
export function buildAuthErrorUrl(authWebBaseUrl: string | undefined): string | undefined {
  if (!authWebBaseUrl) return undefined;
  return new URL("/auth/callback", authWebBaseUrl).toString();
}
