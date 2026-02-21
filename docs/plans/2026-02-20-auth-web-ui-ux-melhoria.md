# Auth Web UI UX Improvement Plan

Goal: elevar a experiencia de login/cadastro/reset para um padrao SaaS premium, sem quebrar fluxos de seguranca ja implementados no auth-platform.

Contexto atual (resumo):
- Fluxo em 2 etapas ja existe (`email -> senha`), com descoberta de conta.
- OTP de 6 digitos ja existe com auto-focus, backspace e paste.
- Senha forte ja existe com checklist visual (12+, maiuscula, minuscula, numero, especial).
- Estados de loading/erro/sucesso ja existem.
- Login social Microsoft e Google ja estao ativos.

Principios para esta fase:
- Manter seguranca atual (nao reduzir politica de senha para 8 caracteres).
- Melhorar clareza e microcopy sem aumentar friccao.
- Evitar retrabalho visual pesado antes de fechar EPIC-04/05.
- Acessibilidade AA e estabilidade de layout como requisitos obrigatorios.
- Anti-enumeration habilitado: mensagens genericas em reset/login.
- Ordem social definida: Microsoft primeiro, Google depois.
- Nivel visual definido: redesign mais agressivo.
- Indicador de etapa no reset definido para implementacao imediata.

---

## Escopo recomendado por prioridade

### P0 - Alto impacto, baixo risco (implementar primeiro)

1. Clareza do metodo de autenticacao no passo de email
- Ajustar titulo/subtitulo para deixar explicito: "Digite seu email para continuar com senha ou login social".
- Critico para reduzir duvida cognitiva no primeiro passo.

2. Hierarquia social mais clara
- Inserir divisor "ou continue com".
- Manter botoes sociais visiveis, mas com peso visual secundario ao CTA principal.

3. Mensageria e microcopy de recuperacao
- Padronizar texto de reenviar para: "Reenviar codigo (53s)" e depois "Reenviar codigo".
- Adicionar dica: "Nao recebeu? Verifique spam/lixeira."
- Aplicar mensagens genericas de erro/sucesso em cenarios sensiveis (sem confirmar existencia de conta).

4. Estabilidade de layout (anti jump)
- Reservar altura minima fixa para areas de feedback e helper text em todos os steps.
- Garantir que CTA nao mude de posicao quando mensagens aparecem.

5. Indicador de progresso no reset (agora em P0)
- Exibir "Etapa 1 de 2" no passo de codigo OTP.
- Exibir "Etapa 2 de 2" no passo de nova senha.

6. Acessibilidade baseline
- Revisar focus visible em inputs/botoes.
- Garantir labels reais + `aria-describedby` para mensagens de erro.
- Garantir alvos de toque >= 44px em mobile.

Arquivos principais:
- `apps/auth-web/src/views/LoginView.vue`
- `apps/auth-web/src/views/login.css` (ou bloco style atual)
- `apps/auth-web/src/test/auth-api.spec.ts` (ajustes quando necessario)

Aceite P0:
- Fluxo completo login/cadastro/reset sem regressao funcional.
- Sem jump visual perceptivel nos CTAs.
- Navegacao por teclado funcional em todos os steps.

---

### P1 - Refinamento visual premium (depois do P0)

1. Card e superficie
- Redesign agressivo do card (superficie mais sofisticada, borda/iluminacao e profundidade modernas).
- Validar performance e contraste AA no novo estilo (desktop e mobile).

2. Botao e motion system
- Hover/active padronizados (`translateY`, `scale(0.98)` no active).
- Spinner ja existe; ajustar timing/easing para nao parecer travado.

3. Tipografia e ritmo
- Ajustar peso de headings e tracking.
- Ajustar densidade vertical para melhor leitura em desktop e mobile.

Aceite P1:
- UI mais moderna sem perda de contraste AA.
- Performance e fluidez mantidas em dispositivos medianos.

---

### P2 - Experimentacao de produto (somente apos P0/P1 estabilizados)

1. Bloco lateral ilustrado (layout split)
- Avaliar somente em desktop largo.
- Mobile continua layout single-column.

2. Mensagens de confianca/conversao
- Exibir apenas se houver copy real validada com negocio/juridico.
- Nao usar "prova social" inventada.

Aceite P2:
- Sem aumento de abandono em mobile.
- Copy aprovada por negocio.

---

## Itens da sua lista que NAO recomendo agora

1. Reduzir regra de senha para 8+
- Nao recomendado: politica atual de 12+ e melhor para seguranca.

2. Fluxo ambiguidade por "link magico"
- Nao adicionar referencia a magic link se o backend nao oferece esse modo.

3. Mensagem explicita de existencia de conta em todos os cenarios
- Pode aumentar enumeracao de contas.
- Melhor decidir politica unica de privacidade para mensagens de auth.

---

## Plano de implementacao (sequencia)

Fase 1 (P0):
1. Ajustar microcopy e hierarquia do passo inicial.
2. Aplicar politica de anti-enumeration com mensagens genericas em reset/login.
3. Padronizar copy de reset + contador + dica de spam/lixeira.
4. Implementar indicador "Etapa 1 de 2 / Etapa 2 de 2" no reset.
5. Implementar slots de feedback com altura reservada em todos os steps.
6. Revisar focus/aria/tamanho de alvo.
7. Rodar testes web (`lint`, `test`, `typecheck`) e smoke manual.

Fase 2 (P1):
1. Aplicar redesign visual agressivo do card e superficie.
2. Ajustar motion e transicoes (incluindo botoes e trocas de step).
3. Refinar hierarquia social mantendo Microsoft primeiro.
4. Validar contraste e regressao em mobile.

Fase 3 (P2):
1. Avaliar split layout desktop com feature flag visual.
2. Medir impacto e decidir manter/remover.

---

## Testes recomendados

Automatizados:
- `npm run lint --workspace @sigfarm/auth-web`
- `npm run test --workspace @sigfarm/auth-web`
- `npm run typecheck --workspace @sigfarm/auth-web`

Manuais (staging):
- Login email/senha (conta ativa).
- Conta pendente de verificacao.
- Signup com senha fraca/forte.
- Recuperacao senha (codigo invalido/expirado/valido).
- Login Microsoft e Google.
- Navegacao 100% por teclado.

---

## Decisoes fechadas

Decisoes fechadas:
- Anti-enumeration: Opcao A (mensagens genericas em reset/login).
- Ordem social: Opcao A (Microsoft primeiro).
- Estilo visual: Opcao B (redesign mais agressivo).
- Indicador no reset: Opcao A (implementar agora).
