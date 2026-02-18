# @sigfarm/auth-guard-nest

Guard NestJS para validar JWT da Auth Platform via JWKS, com claims tipadas.

## Recursos
- Validacao de JWT `RS256` por JWKS remoto (`jose`).
- Enforce opcional de conta ativa (`requireActiveStatus`).
- Decorators para consumo de claims no controller.
- Compatibilidade com metadata `@Public()` para bypass seletivo.

## Exemplo rapido
```ts
import {
  SigfarmAuthGuard,
  createMetadataPublicResolver,
  CurrentAuthClaims,
  Public,
} from "@sigfarm/auth-guard-nest";
import { Controller, Get, UseGuards } from "@nestjs/common";
import { Reflector } from "@nestjs/core";

@Controller("v1")
@UseGuards(
  new SigfarmAuthGuard(
    {
      issuer: "https://auth.sigfarmintelligence.com",
      audience: "sigfarm-apps",
      jwksUrl: "https://auth.sigfarmintelligence.com/.well-known/jwks.json",
      requireActiveStatus: true,
    },
    createMetadataPublicResolver(new Reflector()),
  ),
)
export class ExampleController {
  @Get("public")
  @Public()
  ping() {
    return { ok: true };
  }

  @Get("me")
  me(@CurrentAuthClaims() claims: unknown) {
    return { claims };
  }
}
```

## Validacao
- Fluxo de guard validado em `packages/auth-guard-nest/test/guard.spec.ts`.